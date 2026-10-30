"""new_session_escape: a locked principal opens a new UCP session without the AP2 capability."""

from eval.core import BLOCKED, Actor, AttackCase, Ctx, Expect
from tests.mode_support import (
    ITEM,
    UCP_AGENT,
    UCP_ROOT,
    delegation,
    lock_principal,
    ucp_complete,
)


def run(ctx: Ctx) -> None:
    world = ctx.world
    token = delegation(world.keys)
    lock_principal(world, token)  # AP2 negotiated once: this principal is locked
    created = world.client.post(  # a new session: delegation only, no capability header
        UCP_ROOT,
        json={"line_items": [{"item": {"id": ITEM.id}, "quantity": 1}]},
        headers={**UCP_AGENT, "Countersign-Delegation": token},
    )
    if created.status_code != 201:
        ctx.note(created)  # refused when the session is opened
        return
    ctx.note(ucp_complete(world, created.json()["id"], {}))  # no mandate


CASE = AttackCase(
    id="new_session_escape",
    category="new_session_escape",
    description="A locked principal starts a fresh UCP session without AP2 and sends no mandate.",
    actor=Actor.MALICIOUS_AGENT,
    steps=(
        "negotiate AP2 on UCP as customer C with agent key A (the principal is now locked)",
        "open a NEW UCP checkout with the same delegation and no AP2 capability header",
        "complete it with no mandate",
    ),
    success_condition="PayPal holds a capture for a checkout no mandate covers",
    expected={
        "full": Expect(
            BLOCKED, "mandate_required", "the lock keys on the principal, not the session"
        ),
        "baseline": Expect(
            BLOCKED,
            None,
            "UCP has no payment path without a mandate, so the lock is not needed here",
        ),
    },
    run=run,
)
