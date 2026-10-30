"""duplicate_json_keys: a checkout create body carries line_items twice with different quantities."""

import json

from eval.core import BLOCKED, Actor, AttackCase, Ctx, Expect
from tests.mode_support import ITEM, UCP_AGENT, UCP_ROOT


def run(ctx: Ctx) -> None:
    def line(quantity: int) -> dict[str, object]:
        return {"item": {"id": ITEM.id}, "quantity": quantity}

    raw = json.dumps({"line_items": [line(1)]})
    raw = raw[:-1] + ', "line_items": ' + json.dumps([line(2)]) + "}"
    response = ctx.world.client.post(
        UCP_ROOT, content=raw.encode(), headers={**UCP_AGENT, "Content-Type": "application/json"}
    )
    ctx.note(response)
    if response.status_code == 201:
        ctx.side_effects.add("ambiguous_body_accepted")


CASE = AttackCase(
    id="duplicate_json_keys",
    category="duplicate_json_keys",
    description="A create body has two line_items members: quantity 1 first, quantity 2 last.",
    actor=Actor.MALICIOUS_AGENT,
    steps=("POST a body with a duplicate line_items key (first quantity 1, last quantity 2)",),
    success_condition="PayPal holds a capture the signed mandate does not cover",
    expected={
        "full": Expect(
            BLOCKED, "json_duplicate_key", "the strict loader refuses the body with 400"
        ),
        "baseline": Expect(
            BLOCKED,
            "http_201",
            "the parser keeps the last value (ambiguous_body_accepted); no money moves because the mandate constraints still bind the goods",
        ),
    },
    run=run,
)
