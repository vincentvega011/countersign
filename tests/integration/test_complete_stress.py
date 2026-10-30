"""Concurrent completes after payer approval, over HTTP, on the real Postgres.

Every iteration builds a fresh checkout and fires 10 or 20 completes at once. Whoever owns the attempt
finishes the purchase; the rest are answered with the typed `complete_in_progress` (or the completed
checkout, if they arrive late). Never a 500, never a second PayPal object, never a void of the winner.
"""

from __future__ import annotations

import json
import threading
from collections import Counter
from concurrent.futures import ThreadPoolExecutor
from functools import partial
from typing import Any

import pytest
from sqlalchemy import Engine

from tests.mode_support import (
    UCP_AGENT,
    UCP_ROOT,
    World,
    acp_create,
    acp_headers,
    acp_post,
    codes,
    complete_body,
    make_world,
    mandate_pair,
    new_checkout,
    reset,
    settings_for,
    ucp_complete,
)

ITERATIONS = 200
PAYMENT = {
    "payment_data": {
        "handler_id": "h",
        "instrument": {"type": "card", "credential": {"type": "spt", "token": "t"}},
    }
}


def burst(count: int, call: Any) -> list[Any]:
    barrier = threading.Barrier(count)

    def go(_: int) -> Any:
        barrier.wait()
        return call()

    with ThreadPoolExecutor(max_workers=count) as pool:
        return list(pool.map(go, range(count)))


def ucp_replay(world: World, checkout_id: str) -> Any:
    return ucp_complete(world, checkout_id, {})


def acp_replay(world: World, path: str) -> Any:
    return acp_post(world, path, PAYMENT, acp_headers(None))


def check_one_purchase(world: World) -> None:
    sim = world.sim
    assert len(sim.orders) == 1, "a second PayPal order"
    assert len(sim.authorizations) == 1, "a second PayPal authorization"
    assert len(sim.captures) == 1, "no capture, or a second one"
    (auth,) = sim.authorizations.values()
    assert auth["status"] == "CAPTURED"
    assert sim.count("/void") == 0, "an authorization was voided"


@pytest.mark.parametrize("config", ["full", "baseline"])
def test_ucp_bursts_make_exactly_one_purchase_and_never_a_500(
    app_engine: Engine, admin_engine: Engine, config: str
) -> None:
    classes: Counter[str] = Counter()
    for i in range(ITERATIONS):
        reset(admin_engine)
        world = make_world(app_engine, settings_for(config))
        with world.client:
            body = new_checkout(world)
            pair = mandate_pair(world, body)
            ucp_complete(world, body["id"], complete_body(pair.cm, pair.pm))
            (order_id,) = world.sim.orders
            world.sim.approve(order_id)
            responses = burst(10 + 10 * (i % 2), partial(ucp_replay, world, body["id"]))
            final = world.client.get(f"{UCP_ROOT}/{body['id']}", headers=UCP_AGENT).json()
        assert [r.status_code for r in responses if r.status_code != 200] == []
        for r in responses:
            kind = r.json()["status"]
            assert kind in ("completed", "complete_in_progress"), kind
            if kind == "complete_in_progress":
                assert codes(r) == ["complete_in_progress"], codes(r)
            classes[kind] += 1
        assert final["status"] == "completed"
        check_one_purchase(world)
    assert sum(classes.values()) == ITERATIONS * 15
    print("stress", config, dict(classes))


def test_baseline_acp_bursts_make_exactly_one_purchase_and_never_an_error(
    app_engine: Engine, admin_engine: Engine
) -> None:
    classes: Counter[str] = Counter()
    for i in range(ITERATIONS):
        reset(admin_engine)
        world = make_world(app_engine, settings_for("baseline"))
        with world.client:
            session = acp_create(world, None, capability=False).json()
            path = f"/checkout_sessions/{session['id']}/complete"
            first = acp_post(world, path, PAYMENT, acp_headers(None))
            assert first.status_code == 200 and first.json()["status"] == "complete_in_progress"
            (order_id,) = world.sim.orders
            world.sim.approve(order_id)
            responses = burst(10 + 10 * (i % 2), partial(acp_replay, world, path))
        assert [r.status_code for r in responses if r.status_code != 200] == []
        for r in responses:
            assert r.json()["status"] in ("completed", "complete_in_progress")
            classes[r.json()["status"]] += 1
        assert any(r.json()["status"] == "completed" for r in responses)
        check_one_purchase(world)
    print("stress acp-baseline", dict(classes))


_ = json
