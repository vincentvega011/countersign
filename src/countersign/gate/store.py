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

from countersign.cp.ledger import SpendLedger
from countersign.merchant.pg_reservations import PostgresReservationStore
from countersign.merchant.reservations import Reservation
from countersign.tables import (
    attempt_mandates,
    mandate_revocations,
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
    def __init__(self, engine: Engine, clock_us: Callable[[], int]) -> None:
        self.engine = engine
        self._clock = clock_us
        self.ledger = SpendLedger(clock_us)
        self._stores = {
            "merchant": PostgresReservationStore(engine, "merchant", clock_us),
            "cp": PostgresReservationStore(engine, "cp", clock_us),
        }

    # ------------------------------------------------------------------ reads

    def row(self, checkout_id: str) -> Any:
        with self.engine.connect() as conn:
            return conn.execute(
                select(payment_attempts).where(payment_attempts.c.checkout_id == checkout_id)
            ).first()

    def tokens(self, checkout_id: str) -> tuple[str, str] | None:
        with self.engine.connect() as conn:
            found = conn.execute(
                select(attempt_mandates.c.payment_token, attempt_mandates.c.checkout_mandate).where(
                    attempt_mandates.c.checkout_id == checkout_id
                )
            ).first()
        return None if found is None else (str(found[0]), str(found[1]))

    def revoked(self, digests: Sequence[str]) -> bool:
        with self.engine.connect() as conn:
            found = conn.execute(
                select(mandate_revocations.c.mandate_digest)
                .where(mandate_revocations.c.mandate_digest.in_(list(digests)))
                .limit(1)
            ).first()
        return found is not None

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
        receipt: str,
        log: Callable[[Connection], None],
    ) -> None:
        """Spend voided, both reservations released, attempt `voided`, log entry: one transaction."""
        with self.engine.begin() as conn:
            self.ledger.void(conn, spend_id)
            for role, reservation in self._handles(conn, checkout_id):
                self._stores[role].release_in(conn, reservation)
            result = conn.execute(
                update(payment_attempts)
                .where(
                    payment_attempts.c.checkout_id == checkout_id,
                    payment_attempts.c.state.in_(("gating", "capturing", "unresolved", "authorized")),
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


def revoke_mandate(engine: Engine, digest: str, clock_us: Callable[[], int]) -> None:
    """Record the revocation of an open mandate (insert only; the Trusted Surface calls this in P3)."""
    from sqlalchemy.dialects.postgresql import insert as pg_insert

    with engine.begin() as conn:
        conn.execute(
            pg_insert(mandate_revocations)
            .values(mandate_digest=digest, revoked_us=clock_us())
            .on_conflict_do_nothing(index_elements=["mandate_digest"])
        )
