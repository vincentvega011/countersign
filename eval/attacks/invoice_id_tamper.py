"""invoice_id_tamper: the invoice_id of the approved PayPal order is replaced before authorize."""

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
    world.sim.patch(order_id, invoice_id="other")
    ctx.note(ucp_complete(world, body["id"], {}))


CASE = AttackCase(
    id="invoice_id_tamper",
    category="custom_id_tamper",
    description="The invoice_id that ties the PayPal order to the checkout is replaced while APPROVED.",
    actor=Actor.COMPROMISED_MERCHANT_COMPONENT,
    steps=(
        "buy normally until the payer approved the order at PayPal",
        "PATCH invoice_id to another value",
        "complete again so Countersign authorizes and captures",
    ),
    success_condition="PayPal holds a capture whose invoice_id no longer names the signed checkout",
    expected={
        "full": Expect(
            BLOCKED,
            "mandate_scope_mismatch",
            "the pre-authorize check requires invoice_id to equal the checkout id",
        ),
        "baseline": Expect(
            SUCCESS,
            None,
            "baseline never reads invoice_id back; the capture sits under an invoice id no signed checkout owns",
        ),
    },
    run=run,
)
