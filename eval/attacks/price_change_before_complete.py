"""price_change_before_complete: the checkout is updated after the mandates were signed."""

from eval.core import BLOCKED, Actor, AttackCase, Ctx, Expect
from tests.mode_support import ITEM, UCP_AGENT, UCP_ROOT, complete_body, ucp_complete


def run(ctx: Ctx) -> None:
    world = ctx.world
    body = ctx.checkout()
    pair = ctx.mandates(body)
    ctx.register(body, pair)
    updated = world.client.put(
        f"{UCP_ROOT}/{body['id']}",
        json={"line_items": [{"item": {"id": ITEM.id}, "quantity": 2}]},
        headers=UCP_AGENT,
    )
    if updated.status_code >= 400:
        ctx.note(updated)  # the update itself is refused
    ctx.note(ucp_complete(world, body["id"], complete_body(pair.cm, pair.pm)))


CASE = AttackCase(
    id="price_change_before_complete",
    category="price_change_before_complete",
    description="The quantity is doubled after the customer's mandates were signed, then completed.",
    actor=Actor.MALICIOUS_AGENT,
    steps=(
        "sign mandates for the one item checkout",
        "PUT the checkout with quantity 2",
        "complete with the old mandates",
    ),
    success_condition="PayPal holds a capture above the signed total",
    expected={
        "full": Expect(
            BLOCKED,
            "mandate_scope_mismatch",
            "the mandate's embedded checkout no longer equals the session",
        ),
        "baseline": Expect(
            BLOCKED, None, "baseline compares the embedded checkout with the session at complete"
        ),
    },
    run=run,
)
