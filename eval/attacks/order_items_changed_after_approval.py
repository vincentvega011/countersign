"""order_items_changed_after_approval: the goods of the PayPal order are swapped, same amount.

PATCH after authorization is impossible in the sandbox (docs/PROTOCOL.md section 4.3), so this
category is exercised on the PATCH-while-APPROVED path.
"""

from eval.core import BLOCKED, SUCCESS, Actor, AttackCase, Ctx, Expect
from tests.mode_support import complete_body, ucp_complete


def run(ctx: Ctx) -> None:
    world = ctx.world
    body = ctx.checkout()
    pair = ctx.mandates(body)
    ctx.register(body, pair)
    ucp_complete(world, body["id"], complete_body(pair.cm, pair.pm))
    (order_id,) = world.sim.orders
    world.sim.approve(order_id)
    world.sim.patch(order_id, item_name="Something else entirely")  # same amount, other goods
    ctx.note(ucp_complete(world, body["id"], {}))


CASE = AttackCase(
    id="order_items_changed_after_approval",
    category="order_changed_after_approval",
    description="The item names of the PayPal order are replaced after approval, amount unchanged.",
    actor=Actor.COMPROMISED_MERCHANT_COMPONENT,
    steps=(
        "buy normally until the payer approved the order at PayPal",
        "PATCH the order item name, leaving the amount alone",
        "complete again so Countersign authorizes and captures",
    ),
    success_condition="PayPal holds a capture of other goods than the signed ones",
    expected={
        "full": Expect(
            BLOCKED,
            "mandate_scope_mismatch",
            "the pre-authorize check compares items, not only the amount",
        ),
        "baseline": Expect(SUCCESS, None, "baseline compares nothing before it captures"),
    },
    run=run,
)
