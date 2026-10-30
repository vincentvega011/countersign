"""double_complete_retry: the final complete is replayed many times after the payer approved.

Sequential replays only, so the report is deterministic. The concurrent burst has a known race that
can void the winner's own authorization (never a duplicate object, never a second capture); it is
covered by tests/integration/test_complete_race.py and docs/LIMITATIONS.md L28, not by this case.
"""

from eval.core import BLOCKED, Actor, AttackCase, Ctx, Expect
from tests.mode_support import complete_body, ucp_complete


def run(ctx: Ctx) -> None:
    world = ctx.world
    body = ctx.checkout()
    pair = ctx.mandates(body)
    ctx.register(body, pair)
    ucp_complete(world, body["id"], complete_body(pair.cm, pair.pm))
    (order_id,) = world.sim.orders
    world.sim.approve(order_id)
    results = [ucp_complete(world, body["id"], {}) for _ in range(13)]
    ctx.note(results[-1])


CASE = AttackCase(
    id="double_complete_retry",
    category="double_complete_retry",
    description="The last complete is replayed 13 times in a row after the payer approved.",
    actor=Actor.MALICIOUS_AGENT,
    steps=(
        "buy until the payer approved the order",
        "send the final complete 13 times in sequence",
    ),
    success_condition="a second PayPal order, authorization or capture for the checkout",
    expected={
        "full": Expect(
            BLOCKED,
            "checkout_not_ready",
            "the first complete captures; replays are answered from the stored outcome",
        ),
        "baseline": Expect(
            BLOCKED,
            "checkout_not_ready",
            "baseline also claims the attempt, so it yields exactly one capture",
        ),
    },
    run=run,
)
