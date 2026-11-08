"""mandate_other_agent_key: the closed mandates are signed by an agent key the customer did not bind."""

from eval.core import BLOCKED, Actor, AttackCase, Ctx, Expect
from tests.mode_support import complete_body, ucp_complete


def run(ctx: Ctx) -> None:
    body = ctx.checkout()
    stranger = ctx.world.keys.agents[1]  # the open mandate binds agent 0 in `cnf`
    pair = ctx.mandates(
        body, checkout_issue={"kb_signer": stranger}, payment_issue={"kb_signer": stranger}
    )
    ctx.register(body, pair)
    ctx.note(ucp_complete(ctx.world, body["id"], complete_body(pair.cm, pair.pm)))


CASE = AttackCase(
    id="mandate_other_agent_key",
    category="mandate_forged",
    description="A second agent signs the closed mandates under an open mandate bound to the first.",
    actor=Actor.MALICIOUS_AGENT,
    steps=(
        "the customer binds agent A in the open mandates",
        "agent B signs closed mandates with its own key",
        "complete with them",
    ),
    success_condition="PayPal holds a capture backed by a closed mandate signed by an unbound key",
    expected={
        "full": Expect(BLOCKED, None, "the closed link must verify under the key in `cnf`"),
        "baseline": Expect(BLOCKED, None, "baseline uses the same mandate verifier"),
    },
    run=run,
)
