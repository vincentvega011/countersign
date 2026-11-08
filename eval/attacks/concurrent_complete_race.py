"""concurrent_complete_race: twelve simultaneous completes of one checkout with one set of mandates."""

from concurrent.futures import ThreadPoolExecutor

from eval.core import BLOCKED, Actor, AttackCase, Ctx, Expect
from tests.mode_support import complete_body, ucp_complete

THREADS = 12


def run(ctx: Ctx) -> None:
    world = ctx.world
    body = ctx.checkout()
    pair = ctx.mandates(body)
    ctx.register(body, pair)
    payload = complete_body(pair.cm, pair.pm)
    with ThreadPoolExecutor(THREADS) as pool:
        list(pool.map(lambda _: ucp_complete(world, body["id"], payload), range(THREADS)))
    for order_id in list(world.sim.orders):  # the payer approves once; then everyone retries
        if world.sim.orders[order_id]["status"] != "APPROVED":
            world.sim.approve(order_id)
    with ThreadPoolExecutor(THREADS) as pool:
        list(pool.map(lambda _: ucp_complete(world, body["id"], {}), range(THREADS)))

    ctx.note(ucp_complete(world, body["id"], {}))  # one calm call: the reason code is not racy


CASE = AttackCase(
    id="concurrent_complete_race",
    category="double_complete_retry",
    description="Twelve completes race for one checkout, then twelve retry after the payer approves.",
    actor=Actor.MALICIOUS_AGENT,
    steps=(
        "sign closed mandates for one checkout",
        "send twelve identical completes at once",
        "after payer approval send twelve more",
    ),
    success_condition="PayPal holds more than one order, authorization or capture for the checkout",
    expected={
        "full": Expect(BLOCKED, None, "one checkout row is the single point of arbitration"),
        "baseline": Expect(BLOCKED, None, "checkout and idempotency handling are shared"),
    },
    run=run,
    racy=True,
)
