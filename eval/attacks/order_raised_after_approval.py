"""order_raised_after_approval: the PayPal order is raised to 3x while APPROVED, before authorize.

PATCH after authorization is impossible in the sandbox (docs/PROTOCOL.md section 4.3), so this
category is exercised on the PATCH-while-APPROVED path, the last moment an order can change.
"""

from eval.core import BLOCKED, SUCCESS, Actor, AttackCase, Ctx, Expect
from tests.mode_support import complete_body, total_of, ucp_complete


def run(ctx: Ctx) -> None:
    world = ctx.world
    body = ctx.checkout()
    pair = ctx.mandates(body)
    ctx.register(body, pair)
    ucp_complete(world, body["id"], complete_body(pair.cm, pair.pm))
    (order_id,) = world.sim.orders
    world.sim.approve(order_id)  # the payer approved the signed amount
    tripled = total_of(body) * 3
    world.sim.patch(order_id, amount=f"{tripled // 100}.{tripled % 100:02d}")
    ctx.note(ucp_complete(world, body["id"], {}))


CASE = AttackCase(
    id="order_raised_after_approval",
    category="order_changed_after_approval",
    description="The PayPal order amount is raised to three times the signed total after approval.",
    actor=Actor.COMPROMISED_MERCHANT_COMPONENT,
    steps=(
        "buy normally until the payer approved the order at PayPal",
        "PATCH the order amount to 3x the signed total",
        "complete again so Countersign authorizes and captures",
    ),
    success_condition="PayPal holds a capture above the signed total",
    expected={
        "full": Expect(
            BLOCKED,
            "mandate_scope_mismatch",
            "the pre-authorize check re-derives the live order and refuses",
        ),
        "baseline": Expect(
            SUCCESS, None, "baseline authorizes and captures whatever the order holds"
        ),
    },
    run=run,
)
