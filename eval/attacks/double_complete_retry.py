"""double_complete_retry: the final complete is sent 10 times at once, then 3 more times in a row.

The burst is real and concurrent. Which racer wins is not recorded: the report holds only what is
stable (what PayPal ended up holding and the reason of a later replay). Before the ownership fix a
losing racer could void the winner's authorization (docs/PROTOCOL.md Decision 66, 67).
"""

from concurrent.futures import ThreadPoolExecutor

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
    with ThreadPoolExecutor(max_workers=10) as pool:
        burst = list(pool.map(lambda _: ucp_complete(world, body["id"], {}), range(10)))
    if any(r.status_code != 200 for r in burst):
        ctx.side_effects.add("a_racer_was_not_answered_with_200")
    if len(world.sim.captures) != 1:
        ctx.side_effects.add("purchase_not_completed")  # a liveness failure, not a money one
    results = [ucp_complete(world, body["id"], {}) for _ in range(3)]
    ctx.note(results[-1])


CASE = AttackCase(
    id="double_complete_retry",
    category="double_complete_retry",
    description="The last complete is sent 10 times at once, then 3 times in a row.",
    actor=Actor.MALICIOUS_AGENT,
    steps=(
        "buy until the payer approved the order",
        "send the final complete 10 times concurrently",
        "send it 3 more times in sequence",
    ),
    success_condition="a second PayPal order, authorization or capture for the checkout",
    expected={
        "full": Expect(
            BLOCKED,
            "checkout_not_ready",
            "one racer owns the attempt and captures; the others are told it is in progress",
        ),
        "baseline": Expect(
            BLOCKED,
            "checkout_not_ready",
            "baseline also claims the attempt, so it yields exactly one capture",
        ),
    },
    run=run,
)
