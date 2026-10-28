"""The Postgres spend ledger for `payment.budget` (docs/PROTOCOL.md Decisions 2 and 33, INV-7).

Same rules as `constraints.BudgetAccount`, enforced by the database (migration 0003 triggers):
`reserve` adds an in-flight entry, `capture` and `void` end an in-flight entry once, a refund adds
to `refunded_minor` and never changes the view. Every operation takes the caller's connection so
the constraint check and the reservation are one transaction.

Race safety. `lock` takes `SELECT ... FOR UPDATE` on the open mandate's row (creating it first). A
second transaction for the same open mandate waits there until the first commits or rolls back, so
it reads a spend view that includes the first one's in-flight entry. Two presentations therefore
cannot both pass a budget check against the same headroom. `view` is only meaningful after `lock`
in the same transaction and, because the presentation being evaluated has no entry yet, it
excludes that presentation (Decision 33).
"""

from __future__ import annotations

import time
from collections.abc import Callable

from sqlalchemy import Connection, func, select, update
from sqlalchemy.dialects.postgresql import insert as pg_insert
from sqlalchemy.exc import IntegrityError

from countersign.constraints import BudgetError, SpendView
from countersign.tables import open_payment_mandates, spend_entries


def now_us() -> int:
    return time.time_ns() // 1000


class SpendLedger:
    def __init__(self, clock_us: Callable[[], int] = now_us) -> None:
        self._clock = clock_us

    def lock(self, conn: Connection, digest: str, currency: str) -> None:
        """Create the open mandate's row if needed and hold its row lock until the transaction ends."""
        conn.execute(
            pg_insert(open_payment_mandates)
            .values(digest=digest, currency=currency, created_us=self._clock())
            .on_conflict_do_nothing(index_elements=["digest"])
        )
        row = conn.execute(
            select(open_payment_mandates.c.currency)
            .where(open_payment_mandates.c.digest == digest)
            .with_for_update()
        ).one()
        if row.currency != currency:
            raise BudgetError("the open mandate was first seen in another currency")

    def view(self, conn: Connection, digest: str, currency: str) -> SpendView:
        rows = conn.execute(
            select(spend_entries.c.state, func.coalesce(func.sum(spend_entries.c.amount_minor), 0))
            .where(spend_entries.c.mandate_digest == digest, spend_entries.c.state != "voided")
            .group_by(spend_entries.c.state)
        ).all()
        totals = {state: int(total) for state, total in rows}
        return SpendView(currency, totals.get("captured", 0), totals.get("in_flight", 0))

    def reserve(
        self,
        conn: Connection,
        *,
        spend_id: str,
        digest: str,
        checkout_id: str,
        amount_minor: int,
        currency: str,
    ) -> None:
        if not isinstance(amount_minor, int) or isinstance(amount_minor, bool) or amount_minor <= 0:
            raise BudgetError("a reservation is a positive integer of minor units")
        now = self._clock()
        try:
            with conn.begin_nested():
                conn.execute(
                    spend_entries.insert().values(
                        id=spend_id,
                        mandate_digest=digest,
                        checkout_id=checkout_id,
                        amount_minor=amount_minor,
                        currency=currency,
                        state="in_flight",
                        refunded_minor=0,
                        created_us=now,
                        updated_us=now,
                    )
                )
        except IntegrityError:
            raise BudgetError("the spend entry or the checkout already has a reservation") from None

    def _end(self, conn: Connection, spend_id: str, state: str) -> None:
        result = conn.execute(
            update(spend_entries)
            .where(spend_entries.c.id == spend_id, spend_entries.c.state == "in_flight")
            .values(state=state, updated_us=self._clock())
        )
        if result.rowcount != 1:
            raise BudgetError(f"only an in-flight reservation can be {state}")

    def capture(self, conn: Connection, spend_id: str) -> None:
        self._end(conn, spend_id, "captured")

    def void(self, conn: Connection, spend_id: str) -> None:
        self._end(conn, spend_id, "voided")

    def refund(self, conn: Connection, spend_id: str, amount_minor: int) -> None:
        """Record a refund of captured money. It never changes `view`."""
        if not isinstance(amount_minor, int) or isinstance(amount_minor, bool) or amount_minor <= 0:
            raise BudgetError("a refund is a positive integer of minor units")
        result = conn.execute(
            update(spend_entries)
            .where(
                spend_entries.c.id == spend_id,
                spend_entries.c.state == "captured",
                spend_entries.c.refunded_minor + amount_minor <= spend_entries.c.amount_minor,
            )
            .values(
                refunded_minor=spend_entries.c.refunded_minor + amount_minor,
                updated_us=self._clock(),
            )
        )
        if result.rowcount != 1:
            raise BudgetError("only captured money can be refunded, and not more than captured")
