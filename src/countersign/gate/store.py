"""Database access of the capture gate (tables from migrations 0003 and 0004).

Claiming. `claim` is one conditional UPDATE: `payment_attempts` moves from the state the caller
saw to `gating` only if it is still in that state (and, for a takeover of a stale claim, still has
the `updated_us` the caller saw). Postgres takes the row lock for that statement, so of two gates
racing on one checkout exactly one sees `rowcount == 1` and runs; the other gets `GatePending` and
makes no PayPal call at all. The PayPal Request-Ids are deterministic as well (INV-11), so even a
gate that took over after a crash cannot create a second capture.

Finalizing. `finish_captured` and `finish_released` each run in one transaction: the spend entry,
both reservations (Merchant and Credential Provider), the attempt row and the log entry change
together or not at all. A captured spend entry stays in the view (a refund never restores
headroom, Decision 33); a released one frees the open mandate for a new checkout, while the
checkout id, hash and nonce stay consumed (Decisions 1 and 2).
"""

from __future__ import annotations

from collections.abc import Callable, Sequence
from dataclasses import dataclass
from typing import Any

from sqlalchemy import Connection, Engine, select, update

from countersign.checkout.state import Status
from countersign.checkout.store import checkout_sessions
from countersign.cp.ledger import SpendLedger
from countersign.merchant.pg_reservations import PostgresReservationStore
from countersign.merchant.reservations import Reservation
from countersign.openmandates import lock_row, revoked_in
from countersign.tables import (
    attempt_mandates,
    payment_attempts,
    reservations,
    spend_entries,
)

CLAIMABLE = ("authorized",)
IN_PROGRESS = ("gating", "capturing")


@dataclass(frozen=True)
class ReservationRow:
    role: str
    handle: str
    state: str
    nonce_value: str | None


class GateStore:
    def __init__(
        self,
        engine: Engine,
        clock_us: Callable[[], int],
        *,
        ledger: SpendLedger | None = None,
        session_scoped: bool = False,
    ) -> None:
        self.engine = engine
        self._clock = clock_us
        self.ledger = ledger or SpendLedger(clock_us)
        self._stores = {
            "merchant": PostgresReservationStore(
                engine, "merchant", clock_us, session_scoped=session_scoped
            ),
            "cp": PostgresReservationStore(engine, "cp", clock_us, session_scoped=session_scoped),
        }

    # ------------------------------------------------------------------ reads

    def row(self, checkout_id: str) -> Any:
        with self.engine.connect() as conn:
            return conn.execute(
                select(payment_attempts).where(payment_attempts.c.checkout_id == checkout_id)
            ).first()

    def row_where(self, column: str, value: str) -> Any:
        """The attempt whose `authorization_id`, `capture_id` or `order_id` is `value`, if any."""
        if column not in ("authorization_id", "capture_id", "order_id"):
            raise ValueError("unknown attempt column")
        with self.engine.connect() as conn:
            return conn.execute(
                select(payment_attempts).where(payment_attempts.c[column] == value)
            ).first()

    def tokens(self, checkout_id: str) -> tuple[str, str] | None:
        with self.engine.connect() as conn:
            found = conn.execute(
                select(attempt_mandates.c.payment_token, attempt_mandates.c.checkout_mandate).where(
                    attempt_mandates.c.checkout_id == checkout_id
                )
            ).first()
        return None if found is None else (str(found[0]), str(found[1]))

    def revoked(self, identities: Sequence[str]) -> bool:
        with self.engine.connect() as conn:
            return revoked_in(conn, identities)

    def reservation_rows(self, checkout_id: str) -> dict[str, ReservationRow]:
        with self.engine.connect() as conn:
            rows = conn.execute(
                select(reservations).where(
                    reservations.c.checkout_id == checkout_id, reservations.c.state != "aborted"
                )
            ).all()
        return {r.role: ReservationRow(r.role, r.handle, r.state, r.nonce_value) for r in rows}

    def spend(self, spend_id: str) -> tuple[int, str]:
        with self.engine.connect() as conn:
            found = conn.execute(
                select(spend_entries.c.amount_minor, spend_entries.c.currency).where(
                    spend_entries.c.id == spend_id
                )
            ).one()
        return int(found[0]), str(found[1])

    # ------------------------------------------------------------------ transitions

    def claim(
        self,
        checkout_id: str,
        *,
        expect: tuple[str, ...],
        seen_updated_us: int | None = None,
        require_gate_code: bool = False,
    ) -> bool:
        """Move the attempt to `gating` if it is still in a state of `expect`. True if we won."""
        stmt = update(payment_attempts).where(
            payment_attempts.c.checkout_id == checkout_id, payment_attempts.c.state.in_(expect)
        )
        if seen_updated_us is not None:
            stmt = stmt.where(payment_attempts.c.updated_us == seen_updated_us)
        if require_gate_code:
            stmt = stmt.where(payment_attempts.c.gate_code.is_not(None))
        with self.engine.begin() as conn:
            result = conn.execute(stmt.values(state="gating", updated_us=self._clock()))
        return bool(result.rowcount == 1)

    def set_state(
        self, checkout_id: str, state: str, *, expect: tuple[str, ...], **values: Any
    ) -> bool:
        with self.engine.begin() as conn:
            result = conn.execute(
                update(payment_attempts)
                .where(
                    payment_attempts.c.checkout_id == checkout_id,
                    payment_attempts.c.state.in_(expect),
                )
                .values(state=state, updated_us=self._clock(), **values)
            )
        return bool(result.rowcount == 1)

    def begin_capture(self, checkout_id: str) -> str | None:
        """G-CHECKOUT and the move to `capturing`, in ONE transaction. None if this call may capture.

        Under a shared row lock on the checkout, require that it is still `complete_in_progress`
        and not past `expires_at`; then, in the same transaction, move the attempt from `gating`
        to `capturing`. `cancel` takes the exclusive lock on the same row and refuses once an
        attempt is live (`checkout.cancel`), so a cancel that commits first is seen here (the gate
        fails and voids) and a cancel that comes later waits for this transaction and is refused.
        There is no window between the check and the transition.

        Returns `mandate_revoked` when a revocation of the open mandate exists (checked under the
        open mandate's row lock, Decision 88). Returns a fixed reason when the checkout does not own the attempt (`checkout_missing`,
        `checkout_<status>`, `checkout_expired`) and `lost_claim` when the attempt was no longer
        `gating`. Reads the table directly (never a cache) and fails closed on a missing row.
        """
        with self.engine.begin() as conn:
            found = conn.execute(
                select(checkout_sessions.c.status, checkout_sessions.c.expires_us)
                .where(checkout_sessions.c.id == checkout_id)
                .with_for_update(read=True)
            ).first()
            if found is None:
                return "checkout_missing"
            if found.status != Status.COMPLETE_IN_PROGRESS.value:
                return f"checkout_{found.status}"[:80]
            if self._clock() >= found.expires_us:
                return "checkout_expired"
            attempt = conn.execute(
                select(payment_attempts.c.mandate_digest, payment_attempts.c.state).where(
                    payment_attempts.c.checkout_id == checkout_id
                )
            ).first()
            if attempt is None or attempt.state != "gating":
                return "lost_claim"
            # Revocation (Decision 88): hold the open mandate's row FOR SHARE, which a revoke
            # (FOR UPDATE) waits behind, then read the revocations. A revocation that committed
            # first is seen here; one that arrives later waits for this transaction, sees
            # `capturing` and is refused as `in_flight`.
            currency = str(attempt_currency(conn, checkout_id))
            lock_row(conn, str(attempt.mandate_digest), currency, share=True)
            if revoked_in(conn, [str(attempt.mandate_digest)]):
                return "mandate_revoked"
            result = conn.execute(
                update(payment_attempts)
                .where(
                    payment_attempts.c.checkout_id == checkout_id,
                    payment_attempts.c.state == "gating",
                )
                .values(state="capturing", updated_us=self._clock())
            )
            return None if result.rowcount == 1 else "lost_claim"

    def _handles(self, conn: Connection, checkout_id: str) -> list[tuple[str, Reservation]]:
        found: list[tuple[str, Reservation]] = []
        for role, store in self._stores.items():
            handle = conn.execute(
                select(reservations.c.handle).where(
                    reservations.c.role == role,
                    reservations.c.checkout_id == checkout_id,
                    reservations.c.state == "reserved",
                )
            ).scalar()
            if handle is not None:
                loaded = store.load(conn, str(handle))
                if loaded is not None:
                    found.append((role, loaded))
        return found

    def finish_captured(
        self,
        checkout_id: str,
        *,
        spend_id: str,
        capture_id: str,
        receipt: str,
        log: Callable[[Connection], None],
    ) -> None:
        """Spend captured, both reservations consumed, attempt `captured`, log entry: one transaction."""
        with self.engine.begin() as conn:
            self.ledger.capture(conn, spend_id)
            for role, reservation in self._handles(conn, checkout_id):
                self._stores[role].consume_in(conn, reservation)
            result = conn.execute(
                update(payment_attempts)
                .where(
                    payment_attempts.c.checkout_id == checkout_id,
                    payment_attempts.c.state.in_(("gating", "capturing", "unresolved")),
                )
                .values(
                    state="captured", capture_id=capture_id, receipt=receipt,
                    updated_us=self._clock(),
                )
            )  # fmt: skip
            if result.rowcount != 1:
                raise RuntimeError("the attempt is not in a state that can be captured")
            log(conn)

    def finish_released(
        self,
        checkout_id: str,
        *,
        spend_id: str,
        code: str,
        reason: str,
        receipt: str | None,
        log: Callable[[Connection], None],
    ) -> None:
        """Spend voided, both reservations released, attempt `voided`, log entry: one transaction."""
        with self.engine.begin() as conn:
            self.release_in(
                conn, checkout_id, spend_id=spend_id, code=code, reason=reason, receipt=receipt,
                log=log,
            )  # fmt: skip

    def release_in(
        self,
        conn: Connection,
        checkout_id: str,
        *,
        spend_id: str,
        code: str,
        reason: str,
        receipt: str | None,
        log: Callable[[Connection], None],
    ) -> None:
        """`finish_released` inside the caller's transaction (the webhook handler's)."""
        self.ledger.void(conn, spend_id)
        for role, reservation in self._handles(conn, checkout_id):
            self._stores[role].release_in(conn, reservation)
        result = conn.execute(
            update(payment_attempts)
            .where(
                payment_attempts.c.checkout_id == checkout_id,
                payment_attempts.c.state.in_(
                    ("gating", "capturing", "unresolved", "authorized")
                ),
            )
            .values(
                state="voided", gate_code=code, gate_reason=reason[:80], receipt=receipt,
                updated_us=self._clock(),
            )
        )  # fmt: skip
        if result.rowcount != 1:
            raise RuntimeError("the attempt is not in a state that can be released")
        log(conn)

    def stale_attempts(self, states: tuple[str, ...], cutoff_us: int) -> list[tuple[str, str]]:
        with self.engine.connect() as conn:
            rows = conn.execute(
                select(payment_attempts.c.checkout_id, payment_attempts.c.state).where(
                    payment_attempts.c.state.in_(states),
                    payment_attempts.c.updated_us < cutoff_us,
                )
            ).all()
        return [(str(a), str(b)) for a, b in rows]


def attempt_currency(conn: Connection, checkout_id: str) -> str:
    """The currency of the attempt's spend entry (the open mandate's row is created with it)."""
    found = conn.execute(
        select(spend_entries.c.currency)
        .select_from(
            spend_entries.join(payment_attempts, payment_attempts.c.spend_id == spend_entries.c.id)
        )
        .where(payment_attempts.c.checkout_id == checkout_id)
    ).scalar()
    return str(found) if found is not None else "USD"
