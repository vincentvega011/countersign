"""amount_off_by_one_minor_unit: the payment mandate authorizes one minor unit more or less."""

from eval.core import BLOCKED, Actor, AttackCase, Ctx, Expect
from tests.mode_support import complete_body, total_of, ucp_complete


def run(ctx: Ctx) -> None:
    for delta, nonce in ((1, "1"), (-1, "2")):
        body = ctx.checkout()
        pair = ctx.mandates(
            body, amount=total_of(body) + delta, nonce_checkout="nc-" + nonce,
            nonce_payment="np-" + nonce,
        )  # fmt: skip
        ctx.register(body, pair)
        ctx.note(ucp_complete(ctx.world, body["id"], complete_body(pair.cm, pair.pm)))


CASE = AttackCase(
    id="amount_off_by_one_minor_unit",
    category="price_change_before_complete",
    description="The payment mandate amount differs from the checkout total by one cent either way.",
    actor=Actor.MALICIOUS_AGENT,
    steps=(
        "sign a payment mandate for the total plus one minor unit, then for the total minus one",
        "complete each checkout with its mandates",
    ),
    success_condition="PayPal holds a capture whose amount is not exactly what the mandate allowed",
    expected={
        "full": Expect(BLOCKED, None, "amounts are integer minor units and compared exactly"),
        "baseline": Expect(BLOCKED, None, "baseline compares the same integers at complete"),
    },
    run=run,
)
