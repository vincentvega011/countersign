"""currency_swap: the payment mandate is denominated in another currency than the checkout."""

from eval.core import BLOCKED, Actor, AttackCase, Ctx, Expect
from tests.mode_support import complete_body, ucp_complete


def run(ctx: Ctx) -> None:
    body = ctx.checkout()
    pair = ctx.mandates(body, currency="EUR")  # same number, a different currency
    ctx.register(body, pair)
    ctx.note(ucp_complete(ctx.world, body["id"], complete_body(pair.cm, pair.pm)))


CASE = AttackCase(
    id="currency_swap",
    category="decimal_ambiguity",
    description="The payment mandate carries the checkout total in EUR for a USD checkout.",
    actor=Actor.MALICIOUS_AGENT,
    steps=(
        "sign a payment mandate whose currency is EUR",
        "complete a USD checkout with it",
    ),
    success_condition="PayPal holds a capture although the signed currency is not the checkout's",
    expected={
        "full": Expect(BLOCKED, None, "currency is part of the exact comparison"),
        "baseline": Expect(BLOCKED, None, "baseline compares the same money value"),
    },
    run=run,
)
