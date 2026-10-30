"""unmandated_acp_unlocked: an agent that never negotiated AP2 completes an ACP checkout with no mandate."""

from eval.core import BLOCKED, SUCCESS, Actor, AttackCase, Ctx, Expect
from tests.mode_support import acp_create, acp_headers, acp_post, delegation

PAYMENT = {
    "payment_data": {
        "handler_id": "h",
        "instrument": {"type": "card", "credential": {"type": "spt", "token": "t"}},
    }
}


def run(ctx: Ctx) -> None:
    world = ctx.world
    token = delegation(world.keys)  # never negotiated AP2: no lock exists for this principal
    created = acp_create(world, token, capability=False)
    if created.status_code != 201:
        ctx.note(created)
        return
    path = f"/checkout_sessions/{created.json()['id']}/complete"
    response = acp_post(world, path, PAYMENT, acp_headers(token))
    if response.status_code == 200 and response.json()["status"] == "complete_in_progress":
        (order_id,) = world.sim.orders
        world.sim.approve(order_id)
        response = acp_post(world, path, PAYMENT, acp_headers(token))
    ctx.note(response)


CASE = AttackCase(
    id="unmandated_acp_unlocked",
    category="unmandated_acp_unlocked",
    description="An unlocked agent buys over ACP with no mandate at all.",
    actor=Actor.MALICIOUS_AGENT,
    steps=(
        "open an ACP session with a delegation that never negotiated AP2",
        "complete it with payment_data only",
    ),
    success_condition="PayPal holds a capture for a checkout no mandate covers",
    expected={
        "full": Expect(
            BLOCKED,
            "unmandated_checkout_not_allowed",
            "merchant policy allows no unmandated checkout (Decision 53)",
        ),
        "baseline": Expect(SUCCESS, None, "baseline charges any ACP checkout without a mandate"),
    },
    run=run,
)
