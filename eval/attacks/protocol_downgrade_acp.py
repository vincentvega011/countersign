"""protocol_downgrade_acp: a locked principal buys through ACP, which has no mandate slot."""

from eval.core import BLOCKED, SUCCESS, Actor, AttackCase, Ctx, Expect
from tests.mode_support import (
    acp_create,
    acp_headers,
    acp_post,
    delegation,
    lock_principal,
)

PAYMENT = {
    "payment_data": {
        "handler_id": "h",
        "instrument": {"type": "card", "credential": {"type": "spt", "token": "t"}},
    }
}


def run(ctx: Ctx) -> None:
    world = ctx.world
    token = delegation(world.keys)
    lock_principal(world, token)  # the agent negotiated AP2 over UCP: this principal is locked
    created = acp_create(world, token, capability=False)
    if created.status_code != 201:
        ctx.note(created)  # refused when the session is opened
        return
    path = f"/checkout_sessions/{created.json()['id']}/complete"
    response = acp_post(world, path, PAYMENT, acp_headers(token))
    if response.status_code == 200 and response.json()["status"] == "complete_in_progress":
        (order_id,) = world.sim.orders  # the payer approves at PayPal when asked
        world.sim.approve(order_id)
        response = acp_post(world, path, PAYMENT, acp_headers(token))
    ctx.note(response)


CASE = AttackCase(
    id="protocol_downgrade_acp",
    category="protocol_downgrade_acp",
    description="A principal that negotiated AP2 buys through ACP, where no mandate can be sent.",
    actor=Actor.MALICIOUS_AGENT,
    steps=(
        "negotiate AP2 on UCP as customer C with agent key A (the principal is now locked)",
        "open an ACP checkout session with the same delegation",
        "complete it with ACP payment_data and no mandate",
    ),
    success_condition="PayPal holds a capture for a checkout no mandate covers",
    expected={
        "full": Expect(BLOCKED, "mandate_required", "the principal lock follows the principal"),
        "baseline": Expect(SUCCESS, None, "the lock is per session; ACP is a new session"),
    },
    run=run,
)
