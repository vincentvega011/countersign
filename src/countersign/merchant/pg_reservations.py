"""Postgres single-use reservations (docs/PROTOCOL.md Decisions 1, 28; INV-6).

Same contract as `InMemoryReservationStore`, enforced by the database. The keys are partial unique
indexes on the `reservations` table (migration 0003), so two processes or two threads cannot both
reserve a key: the second insert waits for the first transaction and then fails. `reserve_in`
takes a connection so the Credential Provider can reserve in the same transaction in which it
evaluated the constraints; `reserve` is the standalone form the `ReservationStore` interface needs.

The table is scoped by `role` (`merchant` or `cp`): the Merchant's reservation of a checkout
mandate and the Credential Provider's reservation of a payment are separate acts with separate
keys. `abort` marks the row `aborted` (its keys become free again), `release` marks it `released`
(only the mandate is freed), `consume` marks it `consumed`. Rows are never deleted: the application
role has no DELETE.
"""

from __future__ import annotations

import secrets
import time
from collections.abc import Callable

from sqlalchemy import ColumnElement, Connection, Engine, and_, select, update
from sqlalchemy.exc import IntegrityError

from countersign.merchant.reservations import (
    REASON_CHECKOUT_REUSED,
    REASON_MANDATE_IN_USE,
    REASON_NONCE_REPLAYED,
    AlreadyReservedError,
    Reservation,
    ReservationError,
    ReservationRequest,
)
from countersign.tables import reservations

ROLES = ("merchant", "cp")


def now_us() -> int:
    return time.time_ns() // 1000


class PostgresReservationStore:
    def __init__(self, engine: Engine, role: str, clock_us: Callable[[], int] = now_us) -> None:
        if role not in ROLES:
            raise ValueError("role must be 'merchant' or 'cp'")
        self._engine = engine
        self._role = role
        self._clock = clock_us

    # ---- the ReservationStore interface (own transaction) ----

    def reserve(self, request: ReservationRequest) -> Reservation:
        with self._engine.begin() as conn:
            return self.reserve_in(conn, request)

    def abort(self, reservation: Reservation) -> None:
        with self._engine.begin() as conn:
            self.abort_in(conn, reservation)

    def release(self, reservation: Reservation) -> None:
        with self._engine.begin() as conn:
            self.release_in(conn, reservation)

    def consume(self, reservation: Reservation) -> None:
        with self._engine.begin() as conn:
            self.consume_in(conn, reservation)

    # ---- inside a caller's transaction ----

    def reserve_in(self, conn: Connection, request: ReservationRequest) -> Reservation:
        handle = secrets.token_urlsafe(16)
        thumbprint, audience, nonce = request.nonce_scope or (None, None, None)
        now = self._clock()
        try:
            with conn.begin_nested():  # a savepoint: a refused insert must not poison the caller
                conn.execute(
                    reservations.insert().values(
                        handle=handle,
                        role=self._role,
                        checkout_id=request.checkout_id,
                        checkout_hash=request.checkout_hash,
                        mandate_digest=request.mandate_digest,
                        nonce_thumbprint=thumbprint,
                        nonce_audience=audience,
                        nonce_value=nonce,
                        state="reserved",
                        created_us=now,
                        updated_us=now,
                    )
                )
        except IntegrityError:
            raise AlreadyReservedError(self._conflict(conn, request)) from None
        return Reservation(handle, request)

    def _conflict(self, conn: Connection, request: ReservationRequest) -> str:
        """Which key was taken, in the order of the in-memory store (hash and id, nonce, mandate)."""
        table = reservations
        base = and_(table.c.role == self._role, table.c.state != "aborted")

        def exists(condition: ColumnElement[bool]) -> bool:
            return (
                conn.execute(select(table.c.handle).where(base, condition).limit(1)).first()
                is not None
            )

        if exists(
            (table.c.checkout_hash == request.checkout_hash)
            | (table.c.checkout_id == request.checkout_id)
        ):
            return REASON_CHECKOUT_REUSED
        if request.nonce_scope is not None:
            thumbprint, audience, nonce = request.nonce_scope
            if exists(
                and_(
                    table.c.nonce_thumbprint == thumbprint,
                    table.c.nonce_audience == audience,
                    table.c.nonce_value == nonce,
                )
            ):
                return REASON_NONCE_REPLAYED
        if conn.execute(
            select(table.c.handle)
            .where(
                table.c.role == self._role,
                table.c.mandate_digest == request.mandate_digest,
                table.c.state.in_(("reserved", "consumed")),
            )
            .limit(1)
        ).first():
            return REASON_MANDATE_IN_USE
        return REASON_CHECKOUT_REUSED  # a key was taken and released meanwhile: fail closed

    def _end(self, conn: Connection, reservation: Reservation, state: str) -> None:
        result = conn.execute(
            update(reservations)
            .where(reservations.c.handle == reservation.handle, reservations.c.state == "reserved")
            .values(state=state, updated_us=self._clock())
        )
        if result.rowcount != 1:
            raise ReservationError("the reservation is not in flight")

    def abort_in(self, conn: Connection, reservation: Reservation) -> None:
        self._end(conn, reservation, "aborted")

    def release_in(self, conn: Connection, reservation: Reservation) -> None:
        self._end(conn, reservation, "released")

    def consume_in(self, conn: Connection, reservation: Reservation) -> None:
        self._end(conn, reservation, "consumed")

    def release_checkout(self, checkout_id: str) -> bool:
        """Release the in-flight reservation of a checkout, if one exists (a later stage failed)."""
        with self._engine.begin() as conn:
            result = conn.execute(
                update(reservations)
                .where(
                    reservations.c.role == self._role,
                    reservations.c.checkout_id == checkout_id,
                    reservations.c.state == "reserved",
                )
                .values(state="released", updated_us=self._clock())
            )
        return bool(result.rowcount == 1)

    def load(self, conn: Connection, handle: str) -> Reservation | None:
        row = conn.execute(
            select(reservations).where(
                reservations.c.handle == handle, reservations.c.role == self._role
            )
        ).first()
        if row is None:
            return None
        scope = None
        if row.nonce_value is not None:
            scope = (row.nonce_thumbprint, row.nonce_audience, row.nonce_value)
        return Reservation(
            handle,
            ReservationRequest(row.checkout_id, row.checkout_hash, row.mandate_digest, scope),
        )
