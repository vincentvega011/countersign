"""Add-only spend accounting for `payment.budget` (docs/PROTOCOL.md Decision 2, INV-7).

The spend view of one open Payment Mandate is two integers in minor units of one currency:
`captured_minor` (money that was captured) and `in_flight_minor` (amounts reserved while a
presentation or a PayPal authorization is open). The evaluator receives this view as an argument;
it never reads an amount claimed by the agent. The view is built from PayPal capture and void
outcomes and verified webhooks by the caller; `BudgetAccount` is the rule set those events must
follow, in memory, so the property tests and the Postgres implementation (P2.4) share one
definition:

- `reserve` adds to in-flight; it is how concurrent presentations block each other.
- `capture` moves a reservation from in-flight to captured. Captured only ever grows.
- `void` releases a reservation that was never captured. It is the only event that lowers the
  used amount, because nothing was approved.
- `refund` of captured money changes nothing in the view. The spec says the amount "MUST be added
  to the accumulated total" after approval; a refund does not subtract it, so headroom is never
  restored by a refund. The refunded amount is kept for information only.

Security reasoning: if a refund restored headroom, an agent (or a merchant-side bug) could spend the
same budget repeatedly by refunding and buying again. If a void could target captured money, the
same would follow. Every transition that is not allowed raises `BudgetError`; nothing is ignored.

Not thread safe: callers serialize access (a row lock in Postgres).
"""

from __future__ import annotations

from dataclasses import dataclass

from countersign.constraints.model import is_int


class BudgetError(ValueError):
    """An event that the add-only rules do not allow."""


@dataclass(frozen=True)
class SpendView:
    """Spend under one open Payment Mandate, excluding the presentation being evaluated."""

    currency: str
    captured_minor: int
    in_flight_minor: int

    def __post_init__(self) -> None:
        if not is_int(self.captured_minor) or not is_int(self.in_flight_minor):
            raise BudgetError("a spend view holds integer minor units")
        if self.captured_minor < 0 or self.in_flight_minor < 0:
            raise BudgetError("a spend view cannot be negative")
        if not isinstance(self.currency, str) or not self.currency:
            raise BudgetError("a spend view needs a currency")

    @property
    def used_minor(self) -> int:
        return self.captured_minor + self.in_flight_minor

    def headroom(self, maximum_minor: int) -> int:
        return maximum_minor - self.used_minor


class BudgetAccount:
    def __init__(self, currency: str) -> None:
        self._currency = currency
        self._in_flight: dict[str, int] = {}
        self._captured: dict[str, int] = {}
        self._refunded: dict[str, int] = {}

    def view(self) -> SpendView:
        return SpendView(
            self._currency, sum(self._captured.values()), sum(self._in_flight.values())
        )

    @property
    def refunded_minor(self) -> int:
        return sum(self._refunded.values())

    def view_excluding(self, reservation_id: str) -> SpendView:
        """The view without one in-flight reservation (what the gate re-evaluates against)."""
        if reservation_id not in self._in_flight:
            raise BudgetError("unknown or settled reservation")
        return SpendView(
            self._currency,
            sum(self._captured.values()),
            sum(v for k, v in self._in_flight.items() if k != reservation_id),
        )

    def reserve(self, reservation_id: str, amount_minor: int) -> None:
        if not is_int(amount_minor) or amount_minor <= 0:
            raise BudgetError("a reservation is a positive integer of minor units")
        if reservation_id in self._in_flight or reservation_id in self._captured:
            raise BudgetError("the reservation id is already used")
        self._in_flight[reservation_id] = amount_minor

    def capture(self, reservation_id: str) -> None:
        if reservation_id not in self._in_flight:
            raise BudgetError("only an in-flight reservation can be captured")
        self._captured[reservation_id] = self._in_flight.pop(reservation_id)

    def void(self, reservation_id: str) -> None:
        if reservation_id not in self._in_flight:
            raise BudgetError("only an uncaptured reservation can be voided")
        del self._in_flight[reservation_id]

    def refund(self, reservation_id: str, amount_minor: int) -> None:
        """Record a refund. It never changes the spend view."""
        if reservation_id not in self._captured:
            raise BudgetError("only captured money can be refunded")
        if not is_int(amount_minor) or amount_minor <= 0:
            raise BudgetError("a refund is a positive integer of minor units")
        already = self._refunded.get(reservation_id, 0)
        if already + amount_minor > self._captured[reservation_id]:
            raise BudgetError("cannot refund more than was captured")
        self._refunded[reservation_id] = already + amount_minor
