"""checkout_swap: mandates signed for checkout A are presented to complete checkout B."""

from eval.core import BLOCKED, Actor, AttackCase, Ctx, Expect
from tests.mode_support import complete_body, ucp_complete


def run(ctx: Ctx) -> None:
    a = ctx.checkout()
    b = ctx.checkout()
    pair = ctx.mandates(a)  # nothing is registered for B: any capture of B is unauthorized
    ctx.note(ucp_complete(ctx.world, b["id"], complete_body(pair.cm, pair.pm)))


CASE = AttackCase(
    id="checkout_swap",
    category="checkout_swap",
    description="Mandates bound to checkout A are used to buy checkout B.",
    actor=Actor.MALICIOUS_AGENT,
    steps=(
        "open checkouts A and B",
        "sign closed mandates over the checkout JWT of A",
        "complete B with them",
    ),
    success_condition="PayPal holds a capture for B, which no mandate covers",
    expected={
        "full": Expect(
            BLOCKED, "mandate_scope_mismatch", "checkout_hash binds the mandate to one checkout"
        ),
        "baseline": Expect(
            BLOCKED, None, "baseline verifies the checkout_hash per session too, so it also refuses"
        ),
    },
    run=run,
)
