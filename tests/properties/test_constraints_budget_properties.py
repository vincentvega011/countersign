"""Add-only accounting under any sequence of reserve, capture, void and refund events.

Invariants, checked after every event (500 sequences in CI):

1. `captured` never decreases.
2. `used = captured + in_flight` and both are non-negative integers.
3. Headroom (max - used) increases ONLY on a void of an uncaptured reservation, and then by exactly
   that reservation's amount. A reserve lowers it by the amount, capture and refund leave it
   unchanged.
4. A refused event changes nothing.
5. When reservations are admitted only if the budget constraint passes, `used <= max` always.
"""

from __future__ import annotations

from typing import Any

from hypothesis import given
from hypothesis import strategies as st

from countersign.constraints import BudgetAccount, BudgetError, SpendView
from countersign.constraints import payment as payment_constraints
from countersign.constraints.payment import PaymentFacts

MAX = 5_000

events = st.lists(
    st.tuples(
        st.sampled_from(["reserve", "capture", "void", "refund"]),
        st.integers(min_value=0, max_value=5),
        st.integers(min_value=-10, max_value=3_000),
    ),
    max_size=40,
)


def admitted(view: SpendView, amount: int) -> bool:
    facts = PaymentFacts({}, amount, "USD", None, None, None, view, frozenset())  # type: ignore[arg-type]
    constraint = {"type": "payment.budget", "max": MAX, "currency": "USD"}
    return payment_constraints.budget(constraint, facts).satisfied


@given(sequence=events, gate=st.booleans())
def test_the_budget_view_is_add_only(sequence: list[tuple[str, int, int]], gate: bool) -> None:
    account = BudgetAccount("USD")
    amounts: dict[str, int] = {}
    for kind, number, amount in sequence:
        rid = f"r{number}"
        before = account.view()
        headroom_before = before.headroom(MAX)
        try:
            if kind == "reserve":
                if gate and (amount <= 0 or not admitted(before, amount)):
                    continue
                account.reserve(rid, amount)
                amounts[rid] = amount
            elif kind == "capture":
                account.capture(rid)
            elif kind == "void":
                account.void(rid)
            else:
                account.refund(rid, max(amount, 1))
        except BudgetError:
            assert account.view() == before  # 4
            continue
        after = account.view()
        assert after.captured_minor >= before.captured_minor  # 1
        assert after.used_minor == after.captured_minor + after.in_flight_minor >= 0  # 2
        delta = after.headroom(MAX) - headroom_before
        if kind == "reserve":
            assert delta == -amount  # 3
        elif kind == "void":
            assert delta == amounts[rid]  # the only increase, by exactly the reservation
        else:
            assert delta == 0
        if gate:
            assert after.used_minor <= MAX  # 5


@given(sequence=events)
def test_headroom_never_rises_except_by_a_void(sequence: list[tuple[str, int, int]]) -> None:
    account = BudgetAccount("USD")
    for kind, number, amount in sequence:
        before = account.view().headroom(MAX)
        try:
            getattr(account, kind)(
                *([f"r{number}", amount] if kind in ("reserve", "refund") else [f"r{number}"])
            )
        except BudgetError:
            continue
        rose = account.view().headroom(MAX) > before
        assert rose == (kind == "void")


def test_the_helper_agrees_with_the_evaluator_boundary() -> None:
    assert admitted(SpendView("USD", 0, 0), MAX)
    assert not admitted(SpendView("USD", 0, 0), MAX + 1)
    assert admitted(SpendView("USD", 2_500, 2_499), 1) and not admitted(
        SpendView("USD", 2_500, 2_500), 1
    )


def _unused(x: Any) -> None:  # keeps the Any import honest for type checkers
    del x
