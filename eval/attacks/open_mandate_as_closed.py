"""open_mandate_as_closed: the open mandates are presented as if they were the closed ones."""

from eval.core import BLOCKED, Actor, AttackCase, Ctx, Expect
from tests.mode_support import complete_body, ucp_complete


def run(ctx: Ctx) -> None:
    body = ctx.checkout()
    pair = ctx.mandates(body)
    ctx.register(body, pair)
    ctx.note(
        ucp_complete(ctx.world, body["id"], complete_body(pair.open_checkout, pair.open_payment))
    )


CASE = AttackCase(
    id="open_mandate_as_closed",
    category="mandate_forged",
    description="The customer-signed open mandates are sent without the agent's key binding.",
    actor=Actor.MALICIOUS_AGENT,
    steps=(
        "obtain the open mandates the customer signed for the agent",
        "complete with the open mandates themselves, with no agent-signed closed link",
    ),
    success_condition="PayPal holds a capture backed only by an open mandate",
    expected={
        "full": Expect(BLOCKED, None, "a closed link signed by the bound agent key is required"),
        "baseline": Expect(BLOCKED, None, "baseline uses the same mandate verifier"),
    },
    run=run,
)
