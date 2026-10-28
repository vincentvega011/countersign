"""Budget never exceeded under any interleaving of reserve, authorize and void (real Postgres).

Each example gets its own open mandate. Events are applied through the same check-and-reserve
transaction the Credential Provider uses (lock, spend view, `payment.budget`, reserve). `authorize`
is the PayPal authorization: it leaves the reservation in flight and must change nothing in the view.
`void` releases an uncaptured reservation. After every event: used <= max, and headroom rises only
on a void.
"""

from __future__ import annotations

import itertools

from hypothesis import given, settings
from hypothesis import strategies as st
from sqlalchemy import Engine

from countersign.constraints import BudgetError
from countersign.constraints import payment as payment_constraints
from countersign.constraints.payment import PaymentFacts
from countersign.cp.ledger import SpendLedger

MAX = 5_000
COUNTER = itertools.count()
events = st.lists(
    st.tuples(
        st.sampled_from(["reserve", "authorize", "void"]),
        st.integers(min_value=0, max_value=4),
        st.integers(min_value=100, max_value=3_000),
    ),
    max_size=10,
)


def test_budget_is_never_exceeded(app_engine: Engine, clean_payments: None) -> None:
    ledger = SpendLedger()
    constraint = {"type": "payment.budget", "max": MAX, "currency": "USD"}

    @settings(deadline=None)
    @given(sequence=events)
    def check(sequence: list[tuple[str, int, int]]) -> None:
        digest = f"open-{next(COUNTER)}"
        live: dict[int, str] = {}
        with app_engine.begin() as conn:
            ledger.lock(conn, digest, "USD")
        for kind, slot, amount in sequence:
            with app_engine.begin() as conn:
                ledger.lock(conn, digest, "USD")
                before = ledger.view(conn, digest, "USD")
                if kind == "reserve" and slot not in live:
                    facts = PaymentFacts({}, amount, "USD", None, None, None, before, frozenset())  # type: ignore[arg-type]
                    if payment_constraints.budget(constraint, facts).satisfied:
                        serial = next(COUNTER)
                        spend_id = f"sp_{serial}"
                        ledger.reserve(conn, spend_id=spend_id, digest=digest,
                                       checkout_id=f"chk_{serial}", amount_minor=amount,
                                       currency="USD")  # fmt: skip
                        live[slot] = spend_id
                elif kind == "void" and slot in live:
                    ledger.void(conn, live.pop(slot))
                elif kind == "void":
                    try:
                        ledger.void(conn, f"sp_missing_{slot}")
                    except BudgetError:
                        pass
                after = ledger.view(conn, digest, "USD")
                assert after.used_minor <= MAX
                rose = after.headroom(MAX) > before.headroom(MAX)
                assert rose == (kind == "void" and before.used_minor > after.used_minor)
                if kind == "authorize":
                    assert after == before

    check()
