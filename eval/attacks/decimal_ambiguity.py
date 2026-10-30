"""decimal_ambiguity: an ACP line item unit_amount with excess decimal precision."""

from eval.core import BLOCKED, Actor, AttackCase, Ctx, Expect
from tests.mode_support import ITEM, acp_headers, acp_post


def run(ctx: Ctx) -> None:
    price = ITEM.price.minor
    raw = (
        f'{{"line_items": [{{"id": "{ITEM.id}", "quantity": 1, "unit_amount": {price}.0000000000000001}}],'
        ' "currency": "usd", "capabilities": {}}'
    )
    response = acp_post(ctx.world, "/checkout_sessions", raw.encode(), acp_headers(None))
    ctx.note(response)
    if response.status_code == 201:
        ctx.side_effects.add("ambiguous_number_accepted")


CASE = AttackCase(
    id="decimal_ambiguity",
    category="decimal_ambiguity",
    description="A unit_amount with 16 fractional digits that a float parser rounds to the catalog price.",
    actor=Actor.MALICIOUS_AGENT,
    steps=("POST an ACP create whose unit_amount is the catalog price plus 1e-16",),
    success_condition="a session priced from an ambiguous number, or any capture",
    expected={
        "full": Expect(
            BLOCKED, "json_excess_precision", "the strict loader refuses excess precision"
        ),
        "baseline": Expect(
            BLOCKED,
            "invalid_field",
            "the lenient parser rounds to a float, which the ACP line parser refuses as not integer minor units, so nothing is accepted",
        ),
    },
    run=run,
)
