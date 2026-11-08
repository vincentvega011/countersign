"""payment_mandate_missing: a genuine checkout mandate and no payment mandate at all."""

from eval.core import BLOCKED, Actor, AttackCase, Ctx, Expect
from tests.mode_support import complete_body, ucp_complete


def run(ctx: Ctx) -> None:
    body = ctx.checkout()
    pair = ctx.mandates(body)
    ctx.register(body, pair)
    ctx.note(ucp_complete(ctx.world, body["id"], complete_body(pair.cm, None)))


CASE = AttackCase(
    id="payment_mandate_missing",
    category="consent_missing",
    description="The agent completes with the checkout mandate and no payment mandate.",
    actor=Actor.MALICIOUS_AGENT,
    steps=(
        "sign genuine closed mandates for one checkout",
        "complete with the checkout mandate only",
    ),
    success_condition="PayPal holds a capture although the customer's payment authority was absent",
    expected={
        "full": Expect(BLOCKED, None, "no authorization without a valid Payment Mandate (INV-3)"),
        "baseline": Expect(BLOCKED, None, "baseline requires a payment mandate at complete too"),
    },
    run=run,
)
