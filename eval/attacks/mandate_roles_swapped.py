"""mandate_roles_swapped: the payment mandate is sent as the checkout mandate and the reverse."""

from eval.core import BLOCKED, Actor, AttackCase, Ctx, Expect
from tests.mode_support import complete_body, ucp_complete


def run(ctx: Ctx) -> None:
    body = ctx.checkout()
    pair = ctx.mandates(body)
    ctx.register(body, pair)
    ctx.note(ucp_complete(ctx.world, body["id"], complete_body(pair.pm, pair.cm)))


CASE = AttackCase(
    id="mandate_roles_swapped",
    category="mandate_forged",
    description="Both mandates are genuine but each is presented in the other one's slot.",
    actor=Actor.MALICIOUS_AGENT,
    steps=(
        "sign genuine closed checkout and payment mandates for one checkout",
        "complete with the payment mandate as the checkout mandate and the reverse",
    ),
    success_condition="PayPal holds a capture although neither mandate was presented as what it is",
    expected={
        "full": Expect(BLOCKED, None, "the exact vct and audience of each mandate are required"),
        "baseline": Expect(BLOCKED, None, "baseline uses the same mandate verifier"),
    },
    run=run,
)
