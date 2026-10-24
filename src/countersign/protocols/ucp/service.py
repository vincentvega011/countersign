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
from dataclasses import dataclass
from typing import Any

from sqlalchemy import Connection, Engine

from countersign.canonical.models import Checkout
from countersign.catalog.catalog import Catalog
from countersign.ledger import store as ledger
from countersign.protocols.ucp import messages as m
from countersign.protocols.ucp import store
from countersign.protocols.ucp.checkout_state import (
    FINAL,
    Status,
    cancelable,
    transition,
    updatable,
)
from countersign.protocols.ucp.requests import CheckoutRequest, LineRequest
from countersign.protocols.ucp.responses import checkout_response

TTL_US = 6 * 3600 * 1_000_000  # the spec's default session lifetime, 6 hours
MAX_LINES = 20
MAX_QUANTITY = 99
ID_PATTERN = re.compile(r"chk_[A-Za-z0-9_-]{22}")

Message = dict[str, Any]


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

    def body(self) -> dict[str, Any]:
        if self.record is None:
            return m.error_response(list(self.messages))
        return checkout_response(
            self.record.checkout, self.record.status, self.record.expires_us, list(self.messages)
        )


class UcpService:
    def __init__(
        self,
        engine: Engine,
        catalog: Catalog,
        *,
        policy_hash: bytes,
        clock_us: Callable[[], int] = now_us,
        new_id: Callable[[], str] = new_checkout_id,
        ttl_us: int = TTL_US,
    ) -> None:
        self._engine = engine
        self._catalog = catalog
        self._policy_hash = policy_hash
        self._clock = clock_us
        self._new_id = new_id
        self._ttl_us = ttl_us

    # ---- helpers ----

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

    def create(self, req: CheckoutRequest) -> Result:
        lines, next_seq, errors = self._resolve(req, set(), 1, update=False)
        if errors:
            # No resource is created: an error response, unrecoverable for this request.
            return Result(200, None, tuple({**e, "severity": "unrecoverable"} for e in errors))
        now = self._clock()
        record = store.CheckoutRecord(
            checkout=self._build(self._new_id(), lines),
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

    def get(self, checkout_id: str) -> Result:
        with self._engine.begin() as conn:
            record = self._open(conn, checkout_id, lock=False)
        return self._not_found() if record is None else Result(200, record)

    def update(self, checkout_id: str, req: CheckoutRequest) -> Result:
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
            new = record.advanced(
                checkout=self._build(record.id, lines),
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

    def complete(self, checkout_id: str) -> Result:
        """Stub: never completes. See the module docstring."""
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
