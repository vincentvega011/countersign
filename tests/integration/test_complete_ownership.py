"""Who owns a payment attempt: deterministic interleavings of concurrent completes (Decision 67).

Each reproduction forces one exact interleaving with a rendezvous at a PayPal call, not with luck.
On the code before the ownership fix, the first one ends with the winner's authorization VOIDED by a
request that did not own the attempt, the second cancels a checkout that is still being created, and the
third answers 500 for a purchase that succeeded. The property test explores interleavings drawn by
Hypothesis with a token scheduler.
"""

from __future__ import annotations

import threading
import time
from collections.abc import Callable
from typing import Any

import pytest
from hypothesis import HealthCheck, given, settings
from hypothesis import strategies as st
from sqlalchemy import Engine, select

from countersign.ledger.store import entries_for_checkout
from countersign.protocols.ucp.requests import CompleteRequest
from countersign.tables import reservations
from tests.interleave import PausingTransport, Rendezvous, TokenScheduler
from tests.mode_support import (
    World,
    make_world,
    mandate_pair,
    new_checkout,
    reset,
    settings_for,
    total_of,
)
from tests.paypal_sim import server_error

EMPTY = CompleteRequest(None, None)


class Hook:
    """A swappable callback for the transport, so a world can be built before the test arms it."""

    def __init__(self) -> None:
        self.before: Callable[[str], None] = lambda op: None

    def __call__(self, op: str) -> None:
        self.before(op)


def build(app: Engine, admin: Engine, config: str = "full") -> tuple[World, Hook]:
    reset(admin)
    hook = Hook()
    world = make_world(
        app, settings_for(config), wrap_transport=lambda t: PausingTransport(t, hook)
    )
    return world, hook


def service(world: World) -> Any:
    return world.client.app.state.ucp  # type: ignore[attr-defined]


def approved_checkout(world: World) -> dict[str, Any]:
    """The first complete (order created, payer approval pending), then the payer approves."""
    body = new_checkout(world)
    pair = mandate_pair(world, body)
    service(world).complete(body["id"], CompleteRequest(pair.cm, pair.pm), None)
    (order_id,) = world.sim.orders
    world.sim.approve(order_id)
    return body


def in_thread(fn: Callable[[], Any], name: str, out: dict[str, Any]) -> threading.Thread:
    def run() -> None:
        try:
            out[name] = fn()
        except BaseException as exc:  # noqa: BLE001
            out[name] = exc

    thread = threading.Thread(target=run, name=name)
    thread.start()
    return thread


def wait_for(condition: Callable[[], bool], seconds: float = 10.0) -> None:
    deadline = time.monotonic() + seconds
    while not condition():
        if time.monotonic() > deadline:
            raise TimeoutError("the interleaving did not reach its rendezvous")
        time.sleep(0.005)


@pytest.mark.parametrize("config", ["full", "baseline"])
def test_a_request_that_read_before_the_claim_cannot_void_the_winners_authorization(
    app_engine: Engine, admin_engine: Engine, config: str
) -> None:
    """One request reads the order and stops; another authorizes and stops before its capture; the
    first resumes. Whoever owns the attempt finishes; nobody else may touch the authorization."""
    world, hook = build(app_engine, admin_engine, config)
    with world.client:
        body = approved_checkout(world)
        first_read, before_capture = Rendezvous(), Rendezvous()
        state: dict[str, Any] = {}
        lock = threading.Lock()

        def before(op: str) -> None:
            me = threading.get_ident()
            if op == "get_order":
                with lock:
                    mine = "first" not in state
                    if mine:
                        state["first"] = me
                if mine:
                    first_read.hold()
            elif op == "capture":
                with lock:
                    other = state.get("first") not in (None, me) and "cap" not in state
                    if other:
                        state["cap"] = me
                if other:
                    before_capture.hold()

        hook.before = before
        out: dict[str, Any] = {}
        call = lambda: service(world).complete(body["id"], EMPTY, None)
        t1 = in_thread(call, "t1", out)
        assert first_read.arrived.wait(10)
        t2 = in_thread(call, "t2", out)
        wait_for(lambda: before_capture.arrived.is_set() or not t2.is_alive())
        first_read.released.set()
        t1.join(20)
        before_capture.released.set()
        t2.join(20)

    assert not any(isinstance(v, BaseException) for v in out.values()), out
    sim = world.sim
    assert sim.count("/void") == 0, "a request voided an authorization it did not own"
    assert len(sim.orders) == 1 and len(sim.authorizations) == 1 and len(sim.captures) == 1
    (auth,) = sim.authorizations.values()
    assert auth["status"] == "CAPTURED"


def test_a_request_that_finds_the_attempt_being_created_neither_cancels_nor_releases_it(
    app_engine: Engine, admin_engine: Engine
) -> None:
    world, hook = build(app_engine, admin_engine)
    with world.client:
        body = new_checkout(world)
        pair = mandate_pair(world, body)
        creating = Rendezvous()

        def before(op: str) -> None:
            if op == "create" and not creating.arrived.is_set():
                creating.hold()

        hook.before = before
        out: dict[str, Any] = {}
        a = in_thread(
            lambda: service(world).complete(body["id"], CompleteRequest(pair.cm, pair.pm), None),
            "a",
            out,
        )
        assert creating.arrived.wait(10)
        other = service(world).complete(body["id"], EMPTY, None)  # sees the attempt `reserved`
        assert other.record is not None and other.record.status.value == "complete_in_progress"
        assert [m["code"] for m in other.messages] == ["complete_in_progress"]  # the typed answer
        with app_engine.connect() as conn:  # logged before it was returned (INV-12)
            logged = [e.kind for e in entries_for_checkout(conn, body["id"])]
        assert "checkout.complete_in_progress" in logged
        with app_engine.connect() as conn:
            held = {r.role: r.state for r in conn.execute(select(reservations)).all()}
        assert held == {"merchant": "reserved", "cp": "reserved"}  # nothing was released
        creating.released.set()
        a.join(20)

    assert not isinstance(out["a"], BaseException), out
    assert out["a"].continue_url is not None  # the owner's flow is unchanged: payer approval next
    assert len(world.sim.orders) == 1


def test_a_request_that_loses_to_a_finished_purchase_reports_it_instead_of_failing(
    app_engine: Engine, admin_engine: Engine
) -> None:
    """The slow request passed the status check while the checkout was still completing; by the time
    it reaches the gate the winner has captured. It must report the completed checkout, not raise."""
    world, _ = build(app_engine, admin_engine)
    with world.client:
        body = approved_checkout(world)
        coordinator = service(world)._completion
        entered, go = threading.Event(), threading.Event()
        original = coordinator.complete

        def slow(**kwargs: Any) -> Any:
            if threading.current_thread().name == "slow":
                entered.set()
                go.wait(20)
            return original(**kwargs)

        coordinator.complete = slow
        out: dict[str, Any] = {}
        t = in_thread(lambda: service(world).complete(body["id"], EMPTY, None), "slow", out)
        assert entered.wait(10)
        winner = service(world).complete(body["id"], EMPTY, None)
        assert winner.record is not None and winner.record.status.value == "completed"
        go.set()
        t.join(20)

    late = out["slow"]
    assert not isinstance(late, BaseException), late
    assert late.record.status.value == "completed" and late.receipts
    assert len(world.sim.captures) == 1


# ------------------------------------------------------------------ the property


@settings(
    max_examples=500,
    deadline=None,
    suppress_health_check=[HealthCheck.function_scoped_fixture, HealthCheck.too_slow],
)
@given(
    requests=st.integers(min_value=2, max_value=4),
    picks=st.lists(st.integers(min_value=0, max_value=7), min_size=1, max_size=60),
    approve=st.booleans(),
    owner_fails=st.booleans(),
    config=st.sampled_from(["full", "baseline"]),
    start_phase=st.booleans(),
)
def test_over_any_interleaving_a_non_owner_never_voids_and_money_stays_within_the_signed_total(
    app_engine: Engine,
    admin_engine: Engine,
    requests: int,
    picks: list[int],
    approve: bool,
    owner_fails: bool,
    config: str,
    start_phase: bool,
) -> None:
    world, hook = build(app_engine, admin_engine, config)
    scheduler = TokenScheduler(requests, picks)
    hook.before = scheduler.before_paypal
    with world.client:
        body = new_checkout(world)
        pair = mandate_pair(world, body)
        signed = total_of(body)
        svc = service(world)
        present = CompleteRequest(pair.cm, pair.pm)
        if start_phase:  # several requests present the mandates at once (the start races)
            scheduler.run([lambda: svc.complete(body["id"], present, None)] * requests)
        else:
            svc.complete(body["id"], present, None)
        if not world.sim.orders:
            return  # every start was refused before PayPal (cannot happen, kept honest)
        (order_id,) = world.sim.orders
        if approve:
            world.sim.approve(order_id)
        if owner_fails:
            world.sim.fail_when["authorize"] = lambda sim: True
        scheduler = TokenScheduler(requests, list(reversed(picks)))
        hook.before = scheduler.before_paypal
        scheduler.run([lambda: svc.complete(body["id"], EMPTY, None)] * requests)
        hook.before = lambda op: None
        world.sim.fail_when.clear()
        final = svc.complete(body["id"], EMPTY, None)  # a sequential retry

    sim = world.sim
    assert len(sim.orders) == 1 and len(sim.authorizations) <= 1 and len(sim.captures) <= 1
    held = [
        _minor(a["amount"]["value"]) for a in sim.authorizations.values() if a["status"] != "VOIDED"
    ]
    moved = [_minor(c["amount"]["value"]) for c in sim.captures.values()]
    assert sum(moved) <= signed and sum(held) <= signed
    if not owner_fails:
        assert sim.count("/void") == 0, "a void happened although the owner never failed"
    if owner_fails or not approve:
        assert not sim.captures
    else:
        assert len(sim.captures) == 1 and final.record is not None
        assert final.record.status.value == "completed"


def _minor(value: str) -> int:
    from decimal import Decimal

    return int(Decimal(value) * 100)


_ = server_error
