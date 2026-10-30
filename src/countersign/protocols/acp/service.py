"""The ACP checkout operations: create, get, update, complete, cancel (thin adapter).

Security reasoning.

- **Same canonical model.** A cart is built with `Checkout.from_lines` from catalog prices, with the
  same line ids (`li_1`, `li_2`, ...) as the UCP adapter, and stored in the same table. Prices and
  names never come from the request. An equivalent ACP and UCP cart therefore has identical
  canonical bytes (tests/integration/test_acp_canonical.py).
- **No lock logic here (INV-5).** The adapter turns the two Countersign request headers into a
  `Principal` and a `LockRequest` and calls the shared `PrincipalLock.decide`, then reads
  `verdict.allowed`. It never looks inside the policy or the store. Lock denials answer 403 `Error`
  with the stable code `mandate_required`.
- **Complete never pays in this adapter.** ACP has no slot for an AP2 mandate, so an ACP complete is
  an unmandated request. For a locked principal, or under a policy that requires AP2, it is denied
  `mandate_required`. Otherwise it is handed to the `UnmandatedCompletion` seam, whose default
  denies (`unmandated_checkout_not_allowed`): the Credential Provider and the capture gate require
  mandates, and the unmandated cap is not built. Nothing is reserved, authorized or captured here.
- **Fail closed and log before respond (INV-10, INV-12).** Any exception becomes a 500 `Error` with no
  detail. Every operation appends its decision to the hash-chained log in the transaction that changes
  state, or, for a denial, in a transaction of its own before the answer; a failed append fails the
  request.
"""

from __future__ import annotations

import secrets
import time
from collections.abc import Callable
from dataclasses import dataclass
from typing import Any, Protocol

from sqlalchemy import Connection, Engine

from countersign.canonical.models import Checkout
from countersign.catalog.catalog import Catalog
from countersign.checkout import store
from countersign.checkout.state import FINAL, Status, cancelable, transition, updatable
from countersign.ledger import store as ledger
from countersign.lock import AP2_CAPABILITY, LockPort, LockRequest, Principal
from countersign.protocols.acp import errors as e
from countersign.protocols.acp.requests import CartLine, CreateRequest, UpdateRequest
from countersign.protocols.acp.responses import session_response

TTL_US = 6 * 3600 * 1_000_000


def now_us() -> int:
    return time.time_ns() // 1000


def new_session_id() -> str:
    return "chk_" + secrets.token_urlsafe(16)


@dataclass(frozen=True)
class AcpContext:
    """What the HTTP layer read besides the body (the same two headers as the UCP adapter)."""

    delegation: str | None = None
    capabilities: tuple[str, ...] = ()

    @property
    def negotiated_ap2(self) -> bool:
        return AP2_CAPABILITY in self.capabilities


@dataclass(frozen=True)
class Session:
    record: store.CheckoutRecord
    http_status: int
    order_url: str | None = None
    continue_url: str | None = None

    def body(self) -> dict[str, Any]:
        r = self.record
        return session_response(
            r.checkout, r.status, created_us=r.created_us, updated_us=r.updated_us,
            expires_us=r.expires_us, order_url=self.order_url,
            continue_url=self.continue_url,
        )  # fmt: skip


@dataclass(frozen=True)
class UnmandatedDenied:
    code: str
    message: str


@dataclass(frozen=True)
class UnmandatedApproval:
    """The payer must approve at `url` first; nothing is authorized or captured yet."""

    url: str


@dataclass(frozen=True)
class UnmandatedPaid:
    """The seam authorized and captured the payment. Only the baseline mode returns this."""

    order_id: str
    capture_id: str


UnmandatedOutcome = UnmandatedDenied | UnmandatedApproval | UnmandatedPaid


class UnmandatedCompletion(Protocol):
    """The seam for completing a checkout with no mandate, for a principal no lock applies to.

    The default (`DenyUnmandated`) denies. The permissive naive path of the baseline mode (accept the
    complete, authorize and capture at once, `countersign.degraded.unmandated`) is a different
    implementation of this Protocol, chosen at the composition root. Anything this returns other
    than the three outcomes is refused as an internal error (fail closed). `resumable` says whether
    a checkout already `complete_in_progress` may come back to the seam (the baseline after the
    payer approved); the default is False, so in `full` that status is still a 409.
    """

    resumable: bool

    def complete(self, checkout: Checkout, principal: Principal | None) -> UnmandatedOutcome: ...


class DenyUnmandated:
    resumable = False

    def complete(self, checkout: Checkout, principal: Principal | None) -> UnmandatedOutcome:
        return UnmandatedDenied(
            e.UNMANDATED_NOT_ALLOWED,
            "This merchant completes no checkout without an AP2 mandate.",
        )


class AcpService:
    def __init__(
        self,
        engine: Engine,
        catalog: Catalog,
        *,
        policy_hash: bytes,
        lock: LockPort,
        unmandated: UnmandatedCompletion | None = None,
        clock_us: Callable[[], int] = now_us,
        new_id: Callable[[], str] = new_session_id,
        ttl_us: int = TTL_US,
        order_base_url: str = "http://localhost:8000/checkout_sessions",
    ) -> None:
        self._engine = engine
        self._catalog = catalog
        self._policy_hash = policy_hash
        self._lock = lock
        self._unmandated: UnmandatedCompletion = unmandated or DenyUnmandated()
        self._clock = clock_us
        self._new_id = new_id
        self._ttl_us = ttl_us
        self._order_base_url = order_base_url.rstrip("/")

    # ---------------------------------------------------------------- helpers

    def _log(
        self, conn: Connection | None, kind: str, checkout_id: str | None, **payload: Any
    ) -> None:
        def append(c: Connection) -> None:
            ledger.append(
                c, kind=kind, payload=payload, policy_hash=self._policy_hash,
                checkout_id=checkout_id, ts_us=self._clock(),
            )  # fmt: skip

        if conn is not None:
            append(conn)
            return
        with self._engine.begin() as own:
            append(own)

    def _order_url(self, record: store.CheckoutRecord) -> str | None:
        if record.status is not Status.COMPLETED:
            return None
        return f"{self._order_base_url}/{record.id}"

    def _session(self, record: store.CheckoutRecord, http_status: int = 200) -> Session:
        return Session(record, http_status, self._order_url(record))

    def _principal(self, ctx: AcpContext) -> Principal | None:
        return self._lock.principal_from_delegation(ctx.delegation)

    def _lock_request(
        self, op: str, checkout: Checkout, ctx: AcpContext, principal: Principal | None
    ) -> LockRequest:
        total = next(t.amount for t in checkout.totals if t.type == "total")
        return LockRequest(op, checkout.id, principal, ctx.negotiated_ap2, False, total)  # type: ignore[arg-type]

    def _deny_unless_allowed(self, op: str, checkout: Checkout, ctx: AcpContext) -> None:
        verdict = self._lock.decide(self._lock_request(op, checkout, ctx, self._principal(ctx)))
        if not verdict.allowed:
            self._log(None, f"acp.{op}_denied", checkout.id, reason=verdict.reason)
            raise e.denied(
                e.MANDATE_REQUIRED,
                "This agent must use AP2: negotiate the AP2 mandates capability and present a mandate.",
                "$.ap2",
            )

    def _build(self, checkout_id: str, lines: list[tuple[str, CartLine]]) -> Checkout:
        priced = []
        for index, (line_id, line) in enumerate(lines):
            found = next((c for c in self._catalog.items if c.id == line.item_id), None)
            if found is None:
                raise e.AcpError(
                    400, "item_not_found", "The item is not available for purchase.",
                    param=f"$.line_items[{index}].id",
                )  # fmt: skip
            item = found.to_item()
            if line.unit_amount is not None and line.unit_amount != item.price.minor:
                raise e.AcpError(
                    400, "price_mismatch", "The unit amount differs from the merchant price.",
                    param=f"$.line_items[{index}].unit_amount",
                )  # fmt: skip
            priced.append((line_id, item, line.quantity))
        return Checkout.from_lines(checkout_id, self._catalog.currency, priced)

    def _open(
        self, conn: Connection, session_id: str, *, lock: bool
    ) -> store.CheckoutRecord | None:
        record = store.load(conn, session_id, lock=lock)
        if record is None:
            return None
        if record.status not in FINAL and self._clock() >= record.expires_us:
            expired = record.advanced(
                status=transition(record.status, Status.CANCELED), now_us=self._clock()
            )
            store.save(conn, expired)
            self._log(conn, "acp.session_expired", record.id, previous=record.status.value)
            return expired
        return record

    @staticmethod
    def _not_found() -> e.AcpError:
        return e.AcpError(404, "not_found", "No such checkout session.")

    # ---------------------------------------------------------------- operations

    def create(self, req: CreateRequest, ctx: AcpContext) -> Session:
        if req.currency != self._catalog.currency:
            raise e.AcpError(
                400, "invalid_field", "The currency is not supported.", param="$.currency"
            )
        lines = [(f"li_{n}", line) for n, line in enumerate(req.lines, start=1)]
        checkout = self._build(self._new_id(), lines)
        self._deny_unless_allowed("create", checkout, ctx)
        now = self._clock()
        record = store.CheckoutRecord(
            checkout=checkout, status=Status.READY_FOR_COMPLETE, version=1,
            next_line_seq=len(lines) + 1, catalog_hash=self._catalog.catalog_hash(),
            created_us=now, updated_us=now, expires_us=now + self._ttl_us,
        )  # fmt: skip
        with self._engine.begin() as conn:
            store.insert_record(conn, record)
            self._log(conn, "acp.session_created", record.id,
                      lines=[[ln.id, ln.item.id, ln.quantity] for ln in checkout.line_items])  # fmt: skip
        return self._session(record, 201)

    def get(self, session_id: str) -> Session:
        with self._engine.begin() as conn:
            record = self._open(conn, session_id, lock=False)
        if record is None:
            raise self._not_found()
        return self._session(record)

    def update(self, session_id: str, req: UpdateRequest, ctx: AcpContext) -> Session:
        with self._engine.begin() as conn:
            record = self._open(conn, session_id, lock=True)
            if record is None:
                raise self._not_found()
            if not updatable(record.status):
                raise e.AcpError(
                    409, "not_modifiable", "This checkout session cannot be changed now."
                )
            checkout = record.checkout
            seq = record.next_line_seq
            if req.lines is not None:
                lines = [(f"li_{seq + n}", line) for n, line in enumerate(req.lines)]
                checkout = self._build(record.id, lines)
                seq += len(lines)
            self._deny_unless_allowed("update", checkout, ctx)
            new = record.advanced(
                checkout=checkout, next_line_seq=seq, catalog_hash=self._catalog.catalog_hash(),
                now_us=self._clock(),
            )  # fmt: skip
            store.save(conn, new)
            self._log(conn, "acp.session_updated", new.id,
                      previous_terms_hash=record.checkout.terms_hash().hex())  # fmt: skip
        return self._session(new)

    def complete(self, session_id: str, ctx: AcpContext) -> Session:
        """Always an error in this adapter: see the module docstring. Nothing is reserved or paid."""
        with self._engine.begin() as conn:
            record = self._open(conn, session_id, lock=False)
        if record is None:
            raise self._not_found()
        if record.status is Status.COMPLETED:
            return self._session(record)
        resumed = record.status is Status.COMPLETE_IN_PROGRESS and self._unmandated.resumable
        if record.status is not Status.READY_FOR_COMPLETE and not resumed:
            raise e.AcpError(409, "not_ready", "This checkout session is not ready for payment.")
        principal = self._principal(ctx)
        verdict = self._lock.decide(self._lock_request("complete", record.checkout, ctx, principal))
        if not verdict.allowed:
            self._log(
                None, "acp.complete_denied", record.id, reason=verdict.reason, locked=verdict.locked
            )
            raise e.denied(
                e.MANDATE_REQUIRED,
                "This agent must use AP2: negotiate the AP2 mandates capability and present a mandate.",
            )
        outcome = self._unmandated.complete(record.checkout, principal)
        if isinstance(outcome, UnmandatedPaid):
            return self._finish_unmandated(record, outcome)
        if isinstance(outcome, UnmandatedApproval):
            return self._await_approval(record, outcome)
        if not isinstance(outcome, UnmandatedDenied):
            raise TypeError("the unmandated seam returned something that is not an outcome")
        self._log(None, "acp.complete_denied", record.id, reason=outcome.code, locked=False)
        raise e.denied(outcome.code, outcome.message)

    def _await_approval(self, record: store.CheckoutRecord, outcome: UnmandatedApproval) -> Session:
        """Baseline only: the session waits for the payer, and the answer carries the approval link."""
        with self._engine.begin() as conn:
            current = self._open(conn, record.id, lock=True)
            if current is None:
                raise self._not_found()
            if current.status is Status.READY_FOR_COMPLETE:
                current = current.advanced(
                    status=transition(current.status, Status.COMPLETE_IN_PROGRESS),
                    now_us=self._clock(),
                )
                store.save(conn, current)
            self._log(conn, "acp.complete_approval_required", record.id, mandate=False)
        return Session(current, 200, continue_url=outcome.url)

    def _finish_unmandated(self, record: store.CheckoutRecord, outcome: UnmandatedPaid) -> Session:
        """Baseline only: the seam captured the payment; the session becomes `completed`."""
        with self._engine.begin() as conn:
            current = self._open(conn, record.id, lock=True)
            if current is None:
                raise self._not_found()
            for target in (Status.COMPLETE_IN_PROGRESS, Status.COMPLETED):
                if current.status is not target and current.status is not Status.COMPLETED:
                    current = current.advanced(
                        status=transition(current.status, target), now_us=self._clock()
                    )
                    store.save(conn, current)
            self._log(conn, "acp.completed_unmandated", record.id,
                      order_id=outcome.order_id, capture_id=outcome.capture_id)  # fmt: skip
        return self._session(current)

    def reject_delegated_payment(self, ctx: AcpContext) -> e.AcpError:
        """ACP delegated payment is not implemented. A locked principal gets `mandate_required`."""
        principal = self._principal(ctx)
        verdict = self._lock.decide(
            LockRequest(
                "complete", "chk_delegated_payment", principal, ctx.negotiated_ap2, False, None
            )
        )
        reason = "locked_or_required" if not verdict.allowed else "unsupported"
        self._log(None, "acp.delegated_payment_rejected", None, reason=reason)
        if not verdict.allowed:
            return e.denied(
                e.MANDATE_REQUIRED,
                "This agent must use AP2: negotiate the AP2 mandates capability and present a mandate.",
                "$",
            )
        return e.denied(e.DELEGATED_PAYMENT_UNSUPPORTED, "Delegated payment is not supported.", "$")

    def cancel(self, session_id: str) -> Session:
        with self._engine.begin() as conn:
            record = self._open(conn, session_id, lock=True)
            if record is None:
                raise self._not_found()
            if not cancelable(record.status):
                raise e.AcpError(405, "not_cancelable", "This checkout session cannot be canceled.")
            new = record.advanced(
                status=transition(record.status, Status.CANCELED), now_us=self._clock()
            )
            store.save(conn, new)
            self._log(conn, "acp.session_canceled", new.id, previous=record.status.value)
        return self._session(new)
