"""mandate_expired: the open mandate expired an hour before the purchase."""

from eval.core import BLOCKED, Actor, AttackCase, Ctx, Expect
from tests.mandate_issuer import NOW


def run(ctx: Ctx) -> None:
    body = ctx.checkout()
    pair = ctx.mandates(body, open_exp=NOW - 3600)
    ctx.buy(body, pair)


CASE = AttackCase(
    id="mandate_expired",
    category="mandate_expired",
    description="The agent presents mandates whose open mandate expired an hour ago.",
    actor=Actor.MALICIOUS_AGENT,
    steps=("sign mandates with exp one hour in the past", "complete"),
    success_condition="PayPal holds a capture under an expired mandate",
    expected={
        "full": Expect(
            BLOCKED, "mandate_expired", "expiry is checked at complete and again at the gate"
        ),
        "baseline": Expect(BLOCKED, None, "baseline checks expiry at complete as well"),
    },
    run=run,
)
