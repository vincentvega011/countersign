"""complete_after_cancel: a canceled checkout is completed with mandates the customer did sign."""

from eval.core import BLOCKED, Actor, AttackCase, Ctx, Expect
from tests.mode_support import UCP_AGENT, UCP_ROOT, complete_body, ucp_complete


def run(ctx: Ctx) -> None:
    body = ctx.checkout()
    pair = ctx.mandates(body)
    ctx.register(body, pair)
    ctx.invalid[body["id"]] = "checkout_canceled"
    ctx.world.client.post(f"{UCP_ROOT}/{body['id']}/cancel", json={}, headers=UCP_AGENT)
    ctx.note(ucp_complete(ctx.world, body["id"], complete_body(pair.cm, pair.pm)))


CASE = AttackCase(
    id="complete_after_cancel",
    category="mandate_revoked",
    description="A stale canceled checkout is resubmitted with its still-valid mandates.",
    actor=Actor.MALICIOUS_AGENT,
    steps=(
        "sign closed mandates and cancel the checkout",
        "complete the canceled checkout with the mandates",
    ),
    success_condition="PayPal holds a capture for a checkout that was canceled before it completed",
    expected={
        "full": Expect(BLOCKED, None, "a canceled checkout is terminal"),
        "baseline": Expect(BLOCKED, None, "checkout state is shared by both modes"),
    },
    run=run,
)
