"""open_mandate_double_spend: one open mandate backs two closed mandates in two checkouts."""

from eval.core import BLOCKED, SUCCESS, Actor, AttackCase, Ctx, Expect


def run(ctx: Ctx) -> None:
    first = ctx.checkout()
    pair = ctx.mandates(first)  # the default budget is large: only single use can stop the second
    ctx.buy(first, pair)
    second = ctx.checkout()
    again = ctx.mandates(second, reuse=pair, nonce_checkout="nc-2", nonce_payment="np-2")
    ctx.buy(second, again)


CASE = AttackCase(
    id="open_mandate_double_spend",
    category="open_mandate_double_spend",
    description="The same open mandate is used to sign closed mandates for two purchases.",
    actor=Actor.MALICIOUS_AGENT,
    steps=(
        "buy once under open mandate O with a large budget",
        "open a second checkout and sign new closed mandates (fresh nonces) under the same O",
        "complete the second checkout",
    ),
    success_condition="a second capture under one open mandate",
    expected={
        "full": Expect(
            BLOCKED,
            "mandate_scope_mismatch",
            "one open mandate backs at most one closed mandate (INV-6)",
        ),
        "baseline": Expect(SUCCESS, None, "baseline remembers single use per session only"),
    },
    run=run,
)
