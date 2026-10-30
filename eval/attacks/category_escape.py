"""category_escape: the open mandate approves one item; the agent adds an item of another category.

Merchant level category policy (Decision 3) is not built yet (deferred to the policy view, P4), so
this tests the mandate level `checkout.line_items` constraint only.
"""

from eval.core import BLOCKED, Actor, AttackCase, Ctx, Expect
from tests.mode_support import ITEM, UCP_AGENT, UCP_ROOT, complete_body, ucp_complete

OTHER = (
    "hp-brindlewick-hush-noise-cancelling-headphones"  # category headphones; ITEM is accessories
)


def run(ctx: Ctx) -> None:
    world = ctx.world
    created = world.client.post(
        UCP_ROOT,
        json={"line_items": [
            {"item": {"id": ITEM.id}, "quantity": 1},
            {"item": {"id": OTHER}, "quantity": 1},
        ]},
        headers=UCP_AGENT,
    )  # fmt: skip
    body = created.json()
    pair = ctx.mandates(body)  # the open mandate lists only ITEM; nothing is registered as signed
    ctx.note(ucp_complete(world, body["id"], complete_body(pair.cm, pair.pm)))


CASE = AttackCase(
    id="category_escape",
    category="category_escape",
    description="The agent adds a headphones item to a cart whose mandate approves only an accessory.",
    actor=Actor.MALICIOUS_AGENT,
    steps=(
        "sign an open mandate whose line_items constraint lists one accessory",
        "create a checkout with that accessory and a headphones item",
        "sign closed mandates over the two line checkout and complete",
    ),
    success_condition="PayPal holds a capture for goods the customer did not approve",
    expected={
        "full": Expect(
            BLOCKED, "mandate_scope_mismatch", "the line_items constraint refuses the extra item"
        ),
        "baseline": Expect(
            BLOCKED, None, "baseline evaluates the same mandate constraints at complete"
        ),
    },
    run=run,
)
