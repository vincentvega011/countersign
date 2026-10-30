"""The checkout operations: create, get, update, complete (stubbed), cancel.

Every operation runs in one database transaction that holds the checkout row lock, changes state,
and appends the decision to the hash-chained log before the transaction commits (INV-12). If the
log append fails the state change rolls back and the caller gets an error, never a success without
a record. Any unexpected exception propagates to the router, which answers 500 (INV-10).

Security reasoning.

- Prices and titles come only from the catalog (`catalog.item(id).to_item()`); the request supplies
  an item id and a quantity and nothing else that reaches a response. The built checkout is the
  canonical model, so it is internally consistent by construction.
- A checkout is priced once per write and stored; reads never re-price, so a catalog change cannot
  alter terms that were already shown.
- Status changes only through `checkout_state.transition`. A request that is not allowed in the
  current status changes nothing and gets a typed error message.
- `complete` never succeeds in this stage: with no mandate verification yet, the only safe answer
  is `mandate_required` (INV-3, INV-10), whatever the request carries.
- Expiry is applied when a checkout is next touched: a non-final checkout past `expires_at`
  becomes `canceled` and the change is logged.
"""

from __future__ import annotations

import re
import secrets
import time
from collections.abc import Callable
from dataclasses import dataclass, field, replace
from functools import wraps
from typing import Any, Literal, Protocol

from sqlalchemy import Connection, Engine

from countersign.canonical.models import Checkout
from countersign.catalog.catalog import Catalog
from countersign.checkout import store
from countersign.checkout.state import (
    FINAL,
    Status,
    cancelable,
    transition,
    updatable,
)
from countersign.ledger import store as ledger
from countersign.lock import LockPort, LockRequest, Principal
from countersign.protocols.ucp import messages as m
from countersign.protocols.ucp.profile import AP2_CAPABILITY
from countersign.protocols.ucp.requests import CheckoutRequest, CompleteRequest, LineRequest
from countersign.protocols.ucp.responses import checkout_response

TTL_US = 6 * 3600 * 1_000_000  # the spec's default session lifetime, 6 hours
MAX_LINES = 20
MAX_QUANTITY = 99
ID_PATTERN = re.compile(r"chk_[A-Za-z0-9_-]{22}")

Message = dict[str, Any]


@dataclass(frozen=True)
class CompletionOutcome:
    """What the completion port reports; the service turns it into status, messages and a link.

    `kind` is `rejected`, `approval_required`, `pending`, `authorized`, `in_progress`, `captured`
    or `unresolved`. `messages` are the UCP error messages of a rejection or of an unresolved
    payment. `consumed` says whether the checkout's single-use keys were reserved before the
    rejection (then the checkout is spent and canceled). `receipts` holds the signed receipts of
    a `captured` outcome. An `unresolved` payment leaves the checkout `complete_in_progress`:
    money may be held, so the checkout is neither completed nor canceled.
    """

    kind: str
    messages: tuple[Message, ...] = ()
    continue_url: str | None = None
    consumed: bool = False
    receipts: dict[str, str] = field(default_factory=dict)


class CompletionPort(Protocol):
    """Merchant verification, the lock, then the Credential Provider (`countersign.completion`)."""

    def complete(
        self,
        *,
        checkout: Checkout,
        mandate: str | None,
        payment_token: str | None,
        resume: bool,
        principal: Principal | None = None,
        negotiated: bool = False,
    ) -> CompletionOutcome: ...


@dataclass(frozen=True)
class RequestContext:
    """What the HTTP layer read besides the body.

    `delegation` is an open mandate that names the principal (identity). `capabilities` are the
    capabilities the agent says it negotiated; Countersign does not fetch the platform profile (L11),
    so this header stands in for profile based negotiation (docs/PROTOCOL.md Decision 49).
    """

    delegation: str | None = None
    capabilities: tuple[str, ...] = ()

    @property
    def negotiated_ap2(self) -> bool:
        return AP2_CAPABILITY in self.capabilities


_LOCK_DENIED = m.error_message(
    m.MANDATE_REQUIRED,
    "This agent must use AP2: negotiate the AP2 mandates capability and present a mandate.",
    "recoverable",
    "$.ap2",
)


def now_us() -> int:
    return time.time_ns() // 1000


def new_checkout_id() -> str:
    """`chk_` plus 22 characters of 128 random bits: unguessable and unique per session."""
    return "chk_" + secrets.token_urlsafe(16)


@dataclass(frozen=True)
class Result:
    """What an operation returns: a checkout (or none) and the messages to attach."""

    http_status: int
    record: store.CheckoutRecord | None
    messages: tuple[Message, ...] = ()
    continue_url: str | None = None
    order: dict[str, str] | None = None
    receipts: dict[str, str] = field(default_factory=dict)

    def body(self) -> dict[str, Any]:
        if self.record is None:
            return m.error_response(list(self.messages))
        body = checkout_response(
            self.record.checkout,
            self.record.status,
            self.record.expires_us,
            list(self.messages),
            self.continue_url,
            self.order,
        )
        if self.receipts:
            # Outside the merchant_authorization signature (which excludes `ap2`); each receipt is
            # a signed JWS of its own (docs/PROTOCOL.md Decision 45).
            body["ap2"] = dict(self.receipts)
        return body


def _with_order(method: Callable[..., Result]) -> Callable[..., Result]:
    """A completed checkout always carries its order confirmation (UCP `order`)."""

    @wraps(method)
    def wrapper(self: UcpService, *args: Any, **kwargs: Any) -> Result:
        result = method(self, *args, **kwargs)
        record = result.record
        if record is not None and record.status is Status.COMPLETED and result.order is None:
            return replace(result, order=self._order_confirmation(record.checkout.id))
        return result

    return wrapper


class UcpService:
    def __init__(
        self,
        engine: Engine,
        catalog: Catalog,
        *,
        policy_hash: bytes,
        clock_us: Callable[[], int] = now_us,
        new_id: Callable[[], str] = new_checkout_id,
        completion: CompletionPort | None = None,
        lock: LockPort | None = None,
        ttl_us: int = TTL_US,
        order_base_url: str = "http://localhost:8000/ucp/v1/checkout-sessions",
    ) -> None:
        self._order_base_url = order_base_url.rstrip("/")
        self._engine = engine
        self._completion = completion
        self._lock = lock
        self._catalog = catalog
        self._policy_hash = policy_hash
        self._clock = clock_us
        self._new_id = new_id
        self._ttl_us = ttl_us

    # ---- helpers ----

    def _principal(self, ctx: RequestContext | None) -> Principal | None:
        if self._lock is None or ctx is None:
            return None
        return self._lock.principal_from_delegation(ctx.delegation)

    def _lock_denial(
        self, op: Literal["create", "update"], checkout: Checkout, ctx: RequestContext | None
    ) -> Message | None:
        """Ask the shared lock about a create or update. The adapter makes no decision of its own."""
        if self._lock is None:
            return None
        principal = self._principal(ctx)
        total = next(t.amount for t in checkout.totals if t.type == "total")
        verdict = self._lock.decide(
            LockRequest(
                op, checkout.id, principal, ctx is not None and ctx.negotiated_ap2, False, total
            )
        )
        return None if verdict.allowed else _LOCK_DENIED

    def _order_confirmation(self, checkout_id: str) -> dict[str, str]:
        """The order of a completed checkout. Its id is the checkout id (docs/PROTOCOL.md Decision 45)."""
        return {"id": checkout_id, "permalink_url": f"{self._order_base_url}/{checkout_id}"}

    def _log(self, conn: Connection, kind: str, record: store.CheckoutRecord, **extra: Any) -> None:
        payload: dict[str, Any] = {
            "status": record.status.value,
            "version": record.version,
            "terms_hash": record.checkout.terms_hash().hex(),
            **extra,
        }
        ledger.append(
            conn,
            kind=kind,
            payload=payload,
            policy_hash=self._policy_hash,
            checkout_id=record.id,
            ts_us=self._clock(),
        )

    def _open(
        self, conn: Connection, checkout_id: str, *, lock: bool
    ) -> store.CheckoutRecord | None:
        """Load a checkout, expiring it first if its time has passed. None if there is none."""
        if not ID_PATTERN.fullmatch(checkout_id):
            return None
        record = store.load(conn, checkout_id, lock=lock)
        if record is None:
            return None
        now = self._clock()
        if not _expired(record, now):
            return record
        if not lock:
            # Re-read under the row lock so two readers cannot both expire the checkout.
            record = store.load(conn, checkout_id, lock=True)
            if record is None or not _expired(record, now):
                return record
        expired = record.advanced(status=transition(record.status, Status.CANCELED), now_us=now)
        store.save(conn, expired)
        self._log(conn, "checkout.expired", expired, previous=record.status.value)
        return expired

    @staticmethod
    def _not_found() -> Result:
        msg = m.error_message(m.NOT_FOUND, "No such checkout.", "unrecoverable")
        return Result(200, None, (msg,))

    def _resolve(
        self,
        req: CheckoutRequest,
        existing_ids: set[str],
        next_seq: int,
        *,
        update: bool,
    ) -> tuple[list[tuple[str, Any, int]], int, list[Message]]:
        """Turn the request lines into priced lines, or collect the business errors."""
        errors: list[Message] = []
        lines: list[tuple[str, Any, int]] = []
        if len(req.lines) > MAX_LINES:
            msg = m.error_message(
                m.LINE_LIMIT,
                f"At most {MAX_LINES} line items are allowed.",
                "recoverable",
                "$.line_items",
            )
            return [], next_seq, [msg]
        used: set[str] = set()
        seq = next_seq
        for i, line in enumerate(req.lines):
            path = f"$.line_items[{i}]"
            errors += self._check_line(line, path)
            line_id: str | None = None
            if update and line.line_id is not None:
                if line.line_id not in existing_ids or line.line_id in used:
                    errors.append(
                        m.error_message(
                            m.LINE_ITEM_NOT_FOUND,
                            "The line item id is not part of this checkout or is repeated.",
                            "recoverable",
                            f"{path}.id",
                        )
                    )
                else:
                    line_id = line.line_id
                    used.add(line_id)
            if line_id is None:
                line_id = f"li_{seq}"
                seq += 1
            if not errors:
                lines.append((line_id, self._catalog.item(line.item_id).to_item(), line.quantity))
        return lines, seq, errors

    def _check_line(self, line: LineRequest, path: str) -> list[Message]:
        found = [c for c in self._catalog.items if c.id == line.item_id]
        if not found:
            return [
                m.error_message(
                    m.ITEM_UNAVAILABLE,
                    "The item is not available for purchase.",
                    "recoverable",
                    f"{path}.item.id",
                )
            ]
        out: list[Message] = []
        if line.quantity > MAX_QUANTITY:
            out.append(
                m.error_message(
                    m.QUANTITY_LIMIT,
                    f"At most {MAX_QUANTITY} of one item can be bought in one checkout.",
                    "recoverable",
                    f"{path}.quantity",
                )
            )
        if line.unit is not None and line.unit != ("C62", 0):
            out.append(
                m.error_message(
                    m.QUANTITY_UNIT_MISMATCH,
                    "Items are sold per whole item (unit C62, scale 0).",
                    "recoverable",
                    f"{path}.item.quantity_unit",
                )
            )
        return out

    def _build(self, checkout_id: str, lines: list[tuple[str, Any, int]]) -> Checkout:
        return Checkout.from_lines(checkout_id, self._catalog.currency, lines)

    # ---- operations ----

    @_with_order
    def create(self, req: CheckoutRequest, ctx: RequestContext | None = None) -> Result:
        lines, next_seq, errors = self._resolve(req, set(), 1, update=False)
        if errors:
            # No resource is created: an error response, unrecoverable for this request.
            return Result(200, None, tuple({**e, "severity": "unrecoverable"} for e in errors))
        built = self._build(self._new_id(), lines)
        denial = self._lock_denial("create", built, ctx)
        if denial is not None:
            return Result(200, None, ({**denial, "severity": "unrecoverable"},))
        now = self._clock()
        record = store.CheckoutRecord(
            checkout=built,
            status=Status.READY_FOR_COMPLETE,
            version=1,
            next_line_seq=next_seq,
            catalog_hash=self._catalog.catalog_hash(),
            created_us=now,
            updated_us=now,
            expires_us=now + self._ttl_us,
        )
        with self._engine.begin() as conn:
            store.insert_record(conn, record)
            self._log(conn, "checkout.created", record, lines=_lines_of(record))
        return Result(201, record)

    @_with_order
    def get(self, checkout_id: str) -> Result:
        with self._engine.begin() as conn:
            record = self._open(conn, checkout_id, lock=False)
        return self._not_found() if record is None else Result(200, record)

    @_with_order
    def update(
        self, checkout_id: str, req: CheckoutRequest, ctx: RequestContext | None = None
    ) -> Result:
        with self._engine.begin() as conn:
            record = self._open(conn, checkout_id, lock=True)
            if record is None:
                return self._not_found()
            if not updatable(record.status):
                return self._refuse(conn, "update", record, *_not_updatable(record.status))
            existing = {li.id for li in record.checkout.line_items}
            lines, next_seq, errors = self._resolve(
                req, existing, record.next_line_seq, update=True
            )
            if errors:
                return self._reject(conn, "update", record, errors)
            built = self._build(record.id, lines)
            denial = self._lock_denial("update", built, ctx)
            if denial is not None:
                return self._reject(conn, "update", record, [denial])
            new = record.advanced(
                checkout=built,
                next_line_seq=next_seq,
                catalog_hash=self._catalog.catalog_hash(),
                now_us=self._clock(),
            )
            store.save(conn, new)
            self._log(
                conn,
                "checkout.updated",
                new,
                lines=_lines_of(new),
                previous_terms_hash=record.checkout.terms_hash().hex(),
            )
            return Result(200, new)

    @_with_order
    def complete(
        self,
        checkout_id: str,
        request: CompleteRequest | None = None,
        ctx: RequestContext | None = None,
    ) -> Result:
        """Complete a checkout: Merchant verification, then the Credential Provider.

        Three steps so that no database lock is held while PayPal is called: (1) under the row
        lock, move `ready_for_complete` to `complete_in_progress` and log it; (2) run the completion
        port with no transaction open; (3) under the row lock again, record the outcome. Without a
        completion port configured, nothing is verified and the only answer is `mandate_required`
        (INV-3, INV-10).
        """
        if self._completion is None:
            return self._complete_stub(checkout_id)
        request = request or CompleteRequest(None, None)
        with self._engine.begin() as conn:
            record = self._open(conn, checkout_id, lock=True)
            if record is None:
                return self._not_found()
            resume = record.status is Status.COMPLETE_IN_PROGRESS
            if not resume and record.status is not Status.READY_FOR_COMPLETE:
                return self._refuse(conn, "complete", record, *_not_ready(record.status))
            if not resume:
                started = record.advanced(
                    status=transition(record.status, Status.COMPLETE_IN_PROGRESS),
                    now_us=self._clock(),
                )
                store.save(conn, started)
                self._log(conn, "checkout.complete_started", started)
                record = started
        principal = self._principal(ctx)
        outcome = self._completion.complete(
            checkout=record.checkout,
            mandate=request.checkout_mandate,
            payment_token=request.payment_token,
            resume=resume,
            principal=principal,
            negotiated=ctx is not None and ctx.negotiated_ap2,
        )
        return self._finish_complete(checkout_id, outcome)

    def _finish_complete(self, checkout_id: str, outcome: CompletionOutcome) -> Result:
        with self._engine.begin() as conn:
            record = self._open(conn, checkout_id, lock=True)
            if record is None:
                return self._not_found()
            if outcome.kind == "in_progress":
                # Another request is completing this checkout (or already did). Logged before the
                # answer (INV-12); nothing else changes.
                text = "The checkout is being completed."
                msg = m.error_message(m.UPDATE_DURING_COMPLETION, text, "recoverable")
                self._log(conn, "checkout.complete_in_progress", record)
                return Result(200, record, (msg,))
            if record.status in FINAL:
                # A concurrent request already ended this checkout; this one reports it and does not
                # try a transition the lifecycle has no edge for.
                self._log(conn, "checkout.complete_after_end", record, outcome=outcome.kind)
                if record.status is Status.COMPLETED and outcome.kind == "captured":
                    return Result(200, record, receipts=dict(outcome.receipts))
                text = "The checkout is being completed."
                msg = m.error_message(m.UPDATE_DURING_COMPLETION, text, "recoverable")
                return Result(200, record, (msg,))
            if outcome.kind == "rejected":
                messages = list(outcome.messages)
                if outcome.consumed:
                    # The single-use keys of this checkout are spent; it cannot be completed again.
                    new = record.advanced(
                        status=transition(record.status, Status.CANCELED), now_us=self._clock()
                    )
                    text = "The payment was rejected; create a new checkout to try again."
                    messages.append(
                        m.error_message(m.CHECKOUT_CANCELED_AFTER_REJECTION, text, "unrecoverable")
                    )
                else:
                    new = record.advanced(
                        status=transition(record.status, Status.READY_FOR_COMPLETE),
                        now_us=self._clock(),
                    )
                if new.status is not record.status:
                    store.save(conn, new)
                self._log(
                    conn, "checkout.complete_rejected", new,
                    codes=[x["code"] for x in outcome.messages], consumed=outcome.consumed,
                )  # fmt: skip
                return Result(200, new, tuple(messages))
            if outcome.kind == "approval_required":
                text = "The payer must approve the payment on PayPal, then complete again."
                info = m.info_message(m.PAYER_APPROVAL_REQUIRED, text)
                self._log(conn, "checkout.payer_approval_required", record)
                return Result(200, record, (info,), outcome.continue_url)
            if outcome.kind == "pending":
                text = "The payer has not approved the payment on PayPal yet."
                info = m.info_message(m.PAYER_APPROVAL_REQUIRED, text)
                return Result(200, record, (info,), outcome.continue_url)
            if outcome.kind == "unresolved":
                # Money may be held: neither completed nor canceled, and told so.
                self._log(conn, "checkout.payment_unresolved", record)
                return Result(200, record, tuple(outcome.messages))
            if outcome.kind == "captured":
                done = record.advanced(
                    status=transition(record.status, Status.COMPLETED), now_us=self._clock()
                )
                store.save(conn, done)
                self._log(conn, "checkout.completed", done)
                return Result(200, done, receipts=dict(outcome.receipts))
            text = "The payment is authorized and waits for the capture gate."
            info = m.info_message(m.PAYMENT_AUTHORIZED, text)
            self._log(conn, "checkout.payment_authorized", record)
            return Result(200, record, (info,))

    def _complete_stub(self, checkout_id: str) -> Result:
        """No completion configured: never completes."""
        with self._engine.begin() as conn:
            record = self._open(conn, checkout_id, lock=True)
            if record is None:
                return self._not_found()
            if record.status is not Status.READY_FOR_COMPLETE:
                return self._refuse(conn, "complete", record, *_not_ready(record.status))
            msg = m.error_message(
                m.MANDATE_REQUIRED,
                "This checkout requires an AP2 checkout mandate to complete.",
                "recoverable",
                "$.ap2.checkout_mandate",
            )
            return self._reject(conn, "complete", record, [msg])

    @_with_order
    def cancel(self, checkout_id: str) -> Result:
        with self._engine.begin() as conn:
            record = self._open(conn, checkout_id, lock=True)
            if record is None:
                return self._not_found()
            if not cancelable(record.status):
                code = m.CHECKOUT_NOT_CANCELABLE
                text = f"A {record.status.value} checkout cannot be canceled."
                return self._refuse(conn, "cancel", record, code, text, "unrecoverable")
            new = record.advanced(
                status=transition(record.status, Status.CANCELED), now_us=self._clock()
            )
            store.save(conn, new)
            self._log(conn, "checkout.canceled", new, previous=record.status.value)
            return Result(200, new)

    # ---- refusals ----

    def _refuse(
        self,
        conn: Connection,
        op: str,
        record: store.CheckoutRecord,
        code: str,
        text: str,
        severity: m.Severity,
    ) -> Result:
        """The operation is not allowed in this status: unchanged checkout, typed error."""
        return self._reject(conn, op, record, [m.error_message(code, text, severity)])

    def _reject(
        self, conn: Connection, op: str, record: store.CheckoutRecord, errors: list[Message]
    ) -> Result:
        self._log(conn, f"checkout.{op}_rejected", record, codes=[e["code"] for e in errors])
        return Result(200, record, tuple(errors))


def _expired(record: store.CheckoutRecord, now_us: int) -> bool:
    return record.status not in FINAL and now_us >= record.expires_us


def _lines_of(record: store.CheckoutRecord) -> list[list[Any]]:
    return [[li.id, li.item.id, li.quantity] for li in record.checkout.line_items]


def _not_updatable(status: Status) -> tuple[str, str, m.Severity]:
    if status is Status.COMPLETE_IN_PROGRESS:
        return (
            m.UPDATE_DURING_COMPLETION,
            "The checkout is being completed and cannot be updated now.",
            "recoverable",
        )
    return (
        m.CHECKOUT_NOT_MODIFIABLE,
        f"A {status.value} checkout cannot be updated.",
        "unrecoverable",
    )


def _not_ready(status: Status) -> tuple[str, str, m.Severity]:
    severity: m.Severity = "unrecoverable" if status in FINAL else "recoverable"
    return (
        m.CHECKOUT_NOT_READY,
        f"A {status.value} checkout cannot be completed.",
        severity,
    )
