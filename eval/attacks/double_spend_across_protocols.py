"""double_spend_across_protocols: after a mandated UCP purchase the same principal buys over ACP."""

from countersign.protocols.ucp.profile import AP2_CAPABILITY
from eval.core import BLOCKED, SUCCESS, Actor, AttackCase, Ctx, Expect
from tests.mode_support import (
    acp_create,
    acp_headers,
    acp_post,
    complete_body,
    delegation,
    ucp_complete,
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
    headers = {"Countersign-Delegation": token, "Countersign-Capabilities": AP2_CAPABILITY}
    body = ctx.checkout(**headers)  # negotiates AP2: the principal is locked
    pair = ctx.mandates(body)
    ctx.buy(body, pair)
    created = acp_create(world, token, capability=False)  # the ACP checkout is never registered
    if created.status_code != 201:
        ctx.note(created)
        return
    path = f"/checkout_sessions/{created.json()['id']}/complete"
    response = acp_post(world, path, PAYMENT, acp_headers(token))
    if response.status_code == 200 and response.json()["status"] == "complete_in_progress":
        for order_id in list(world.sim.orders):
            if world.sim.orders[order_id]["status"] != "APPROVED" and not any(
                a["order"] == order_id for a in world.sim.authorizations.values()
            ):
                world.sim.approve(order_id)
        response = acp_post(world, path, PAYMENT, acp_headers(token))
    ctx.note(response)


CASE = AttackCase(
    id="double_spend_across_protocols",
    category="double_spend_across_protocols",
    description="A principal that bought with a mandate buys again over ACP, where no mandate fits.",
    actor=Actor.MALICIOUS_AGENT,
    steps=(
        "buy over UCP with full mandates (the principal is locked by the AP2 negotiation)",
        "open an ACP session with the same delegation and complete it with payment_data only",
    ),
    success_condition="a second capture for a checkout no mandate covers",
    expected={
        "full": Expect(BLOCKED, "mandate_required", "the lock follows the principal onto ACP"),
        "baseline": Expect(
            SUCCESS, None, "baseline lock is per session; ACP charges without a mandate"
        ),
    },
    run=run,
)
_ = ucp_complete, complete_body
