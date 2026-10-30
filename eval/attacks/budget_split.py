"""budget_split: two purchases that each fit the budget alone but not together, in two sessions."""

from eval.core import BLOCKED, Actor, AttackCase, Ctx, Expect
from tests.mode_support import total_of


def run(ctx: Ctx) -> None:
    first = ctx.checkout()
    budget = total_of(first) * 3 // 2  # each purchase fits alone; two do not
    pair = ctx.mandates(first, budget=budget)
    ctx.buy(first, pair, budget=budget)
    second = ctx.checkout()
    again = ctx.mandates(
        second, budget=budget, reuse=pair, nonce_checkout="nc-2", nonce_payment="np-2"
    )
    ctx.buy(second, again, budget=budget)


CASE = AttackCase(
    id="budget_split",
    category="budget_split",
    description="A budget of 1.5 purchases is spent twice, one purchase per session.",
    actor=Actor.MALICIOUS_AGENT,
    steps=(
        "sign an open mandate with a budget of 1.5 x the checkout total",
        "buy once, then open a second checkout under the same open mandate",
        "complete the second checkout",
    ),
    success_condition="captures under one open mandate above its signed budget",
    expected={
        "full": Expect(
            BLOCKED,
            "mandate_scope_mismatch",
            "denied by the single-use rule (merchant open_mandate_in_use) before the budget is read",
        ),
        "baseline": Expect(
            BLOCKED,
            None,
            "denied by the persistent local budget counter (Decision 63), not by single use",
        ),
    },
    run=run,
)
