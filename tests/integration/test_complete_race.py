"""Ten concurrent completes after payer approval: safe, but not always live (docs/LIMITATIONS.md L28).

The safety half is asserted: never a second PayPal object, never a second capture, and an authorization
that ends without a capture is voided. The liveness half is a known defect found by the attack suite:
now and then a losing racer voids the winner's authorization, so the legitimate purchase is not
completed. It is reported, not asserted away.
"""

from __future__ import annotations

from concurrent.futures import ThreadPoolExecutor

import pytest
from sqlalchemy import Engine

from tests.mode_support import (
    complete_body,
    make_world,
    mandate_pair,
    new_checkout,
    reset,
    settings_for,
    ucp_complete,
)


@pytest.mark.parametrize("config", ["full", "baseline"])
def test_concurrent_completes_never_duplicate_or_capture_twice(
    app_engine: Engine, admin_engine: Engine, config: str
) -> None:
    for _ in range(8):
        run_burst(app_engine, admin_engine, config)


def run_burst(app_engine: Engine, admin_engine: Engine, config: str) -> None:
    reset(admin_engine)
    world = make_world(app_engine, settings_for(config))
    with world.client:
        body = new_checkout(world)
        pair = mandate_pair(world, body)
        ucp_complete(world, body["id"], complete_body(pair.cm, pair.pm))
        (order_id,) = world.sim.orders
        world.sim.approve(order_id)
        with ThreadPoolExecutor(max_workers=10) as pool:
            list(pool.map(lambda _: ucp_complete(world, body["id"], {}), range(10)))
    sim = world.sim
    assert len(sim.orders) == 1 and len(sim.authorizations) == 1 and len(sim.captures) <= 1
    (auth,) = sim.authorizations.values()
    assert auth["status"] == ("CAPTURED" if sim.captures else "VOIDED")
