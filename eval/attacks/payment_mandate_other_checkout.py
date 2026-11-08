"""payment_mandate_other_checkout: a payment mandate bound to checkout A is used to pay for B."""

from eval.core import BLOCKED, Actor, AttackCase, Ctx, Expect
from tests.mode_support import complete_body, ucp_complete


def run(ctx: Ctx) -> None:
    a = ctx.checkout()
    b = ctx.checkout()
    pair_a = ctx.mandates(a)
    pair_b = ctx.mandates(b, nonce_checkout="nc-b", nonce_payment="np-b")
    ctx.register(a, pair_a)  # the customer signed A; B is signed by nobody for payment
    ctx.note(ucp_complete(ctx.world, b["id"], complete_body(pair_b.cm, pair_a.pm)))


CASE = AttackCase(
    id="payment_mandate_other_checkout",
    category="checkout_swap",
    description="A genuine checkout mandate for B is paired with the payment mandate for A.",
    actor=Actor.MALICIOUS_AGENT,
    steps=(
        "sign closed mandates for checkout A and for checkout B",
        "complete B with B's checkout mandate and A's payment mandate",
    ),
    success_condition="PayPal holds a capture for B under a payment mandate bound to A",
    expected={
        "full": Expect(BLOCKED, None, "the payment mandate binds to the same checkout hash"),
        "baseline": Expect(BLOCKED, None, "baseline verifies the same binding per session"),
    },
    run=run,
)
