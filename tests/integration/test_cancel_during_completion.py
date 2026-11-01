"""Cancel while a checkout is completing (Decisions 70 and 71): the entry guard and the gate re-check.

Everything on the money path is real (Merchant, Credential Provider, gate, lock, Postgres, the
hash-chained log); only PayPal is the simulator. The interleavings are forced at exact PayPal calls
with a rendezvous, not left to luck. The outcome rule for every test: a checkout ends either
`canceled` with nothing authorized and nothing captured, or `completed` and captured with its
receipts. Never canceled with a capture, never a capture without receipts.
"""

from __future__ import annotations

import threading
import time
from collections.abc import Callable
from typing import Any

import pytest
from hypothesis import HealthCheck, given, settings
from hypothesis import strategies as st
from sqlalchemy import Engine, select, text

from countersign.gate import CaptureGate, GatePassed, GateRejected
from countersign.gate.store import GateStore
from countersign.ledger.store import entries_for_checkout
from countersign.protocols.ucp.requests import CompleteRequest
from countersign.tables import payment_attempts, reservations, spend_entries
from tests.checkout_seed import seed_checkout, set_status
from tests.gate_support import GateWorld, make_gate_world
from tests.integration.test_complete_ownership import (
    Hook,
    approved_checkout,
    build,
    in_thread,
    service,
    wait_for,
)
from tests.interleave import PausingTransport, Rendezvous, TokenScheduler
from tests.mode_support import (
    UCP_AGENT,
    UCP_ROOT,
    World,
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

EMPTY = CompleteRequest(None, None)
ACP_PAYMENT = {
    "payment_data": {
        "handler_id": "h",
        "instrument": {"type": "card", "credential": {"type": "spt", "token": "t"}},
    }
}
CONFIGS = ["full", "baseline"]


# ------------------------------------------------------------------ helpers


def ucp_cancel(world: World, checkout_id: str) -> Any:
    return world.client.post(f"{UCP_ROOT}/{checkout_id}/cancel", json={}, headers=UCP_AGENT)


def acp_cancel(world: World, checkout_id: str) -> Any:
    return acp_post(world, f"/checkout_sessions/{checkout_id}/cancel", {}, acp_headers(None))


def status_of(world: World, checkout_id: str) -> str:
    return str(world.client.get(f"{UCP_ROOT}/{checkout_id}", headers=UCP_AGENT).json()["status"])


def attempt(admin: Engine, checkout_id: str) -> Any:
    with admin.connect() as conn:
        return conn.execute(
            select(payment_attempts).where(payment_attempts.c.checkout_id == checkout_id)
        ).first()


def books(admin: Engine) -> dict[str, list[Any]]:
    """Everything a refused cancel must leave untouched."""
    with admin.connect() as conn:
        return {
            "attempts": [
                (r.checkout_id, r.state, r.updated_us)
                for r in conn.execute(select(payment_attempts)).all()
            ],
            "reservations": sorted(
                (r.role, r.checkout_id, r.state) for r in conn.execute(select(reservations)).all()
            ),
            "spend": sorted((r.id, r.state) for r in conn.execute(select(spend_entries)).all()),
        }


def force_attempt_state(admin: Engine, checkout_id: str, state: str) -> None:
    with admin.begin() as conn:
        conn.execute(
            text("UPDATE payment_attempts SET state = :s WHERE checkout_id = :c"),
            {"s": state, "c": checkout_id},
        )


def force_status(admin: Engine, checkout_id: str, status: str) -> None:
    with admin.begin() as conn:
        conn.execute(
            text("UPDATE checkout_sessions SET status = :s, version = version + 1 WHERE id = :i"),
            {"s": status, "i": checkout_id},
        )


def logged(admin: Engine, checkout_id: str) -> list[str]:
    with admin.connect() as conn:
        return [e.kind for e in entries_for_checkout(conn, checkout_id)]


def assert_consistent(world: World, admin: Engine, checkout_id: str) -> str:
    """The one-outcome rule. Returns the final status."""
    sim, status = world.sim, status_of(world, checkout_id)
    row = attempt(admin, checkout_id)
    if status == "canceled":
        assert not sim.captures, "canceled with a capture"
    if sim.captures:
        assert status == "completed", f"captured but the checkout reads {status}"
        assert row is not None and row.state == "captured"
        assert row.receipt and row.capture_id, "a capture without its receipt"
        assert "gate.captured" in logged(admin, checkout_id)
    if status == "completed":
        assert len(sim.captures) == 1 and row is not None and row.receipt
    held = [a for a in sim.authorizations.values() if a["status"] not in ("VOIDED", "CAPTURED")]
    if status == "canceled":
        assert not held, "canceled with an authorization still held"
    return status


def first_complete(world: World, body: dict[str, Any]) -> dict[str, Any]:
    pair = mandate_pair(world, body)
    service(world).complete(body["id"], CompleteRequest(pair.cm, pair.pm), None)
    return body


# ------------------------------------------------------------------ the entry guard


@pytest.mark.parametrize("config", CONFIGS)
@pytest.mark.parametrize("protocol", ["ucp", "acp"])
@pytest.mark.parametrize("status_says", ["complete_in_progress", "ready_for_complete"])
@pytest.mark.parametrize(
    "state",
    ["order_created", "authorizing", "authorized", "gating", "capturing", "unresolved"],
)
def test_cancel_is_refused_in_every_non_final_attempt_state(
    app_engine: Engine,
    admin_engine: Engine,
    config: str,
    protocol: str,
    state: str,
    status_says: str,
) -> None:
    """The attempt state alone refuses the cancel, whatever status the checkout row shows."""
    world, _ = build(app_engine, admin_engine, config)
    with world.client:
        body = first_complete(world, new_checkout(world))
        cid = body["id"]
        force_attempt_state(admin_engine, cid, state)
        force_status(admin_engine, cid, status_says)
        before = books(admin_engine)
        if protocol == "ucp":
            r = ucp_cancel(world, cid)
            assert r.status_code == 200 and r.json()["status"] == status_says
            assert codes(r) == ["complete_in_progress"]
            assert r.json()["messages"][0]["severity"] == "recoverable"
            kinds = logged(admin_engine, cid)
            assert "checkout.cancel_rejected" in kinds and "checkout.canceled" not in kinds
        else:
            r = acp_cancel(world, cid)
            assert r.status_code == 405 and r.json()["code"] == "complete_in_progress"
            kinds = logged(admin_engine, cid)
            assert "acp.cancel_rejected" in kinds and "acp.session_canceled" not in kinds
        assert books(admin_engine) == before, "a refused cancel changed the payment books"
        assert status_of(world, cid) == status_says
        assert not world.sim.captures and not any(
            a["status"] == "VOIDED" for a in world.sim.authorizations.values()
        )


@pytest.mark.parametrize("config", CONFIGS)
@pytest.mark.parametrize("protocol", ["ucp", "acp"])
def test_cancel_is_refused_while_the_checkout_is_completing_even_with_no_attempt_yet(
    app_engine: Engine, admin_engine: Engine, config: str, protocol: str
) -> None:
    """The Merchant is still verifying: the status alone refuses the cancel."""
    world, _ = build(app_engine, admin_engine, config)
    with world.client:
        cid = new_checkout(world)["id"]
        force_status(admin_engine, cid, "complete_in_progress")
        r = ucp_cancel(world, cid) if protocol == "ucp" else acp_cancel(world, cid)
        assert (r.status_code, codes(r) if protocol == "ucp" else [r.json()["code"]]) == (
            (200 if protocol == "ucp" else 405),
            ["complete_in_progress"],
        )
        assert status_of(world, cid) == "complete_in_progress"


@pytest.mark.parametrize("config", CONFIGS)
def test_a_live_attempt_refuses_a_cancel_whatever_the_status_says(
    app_engine: Engine, admin_engine: Engine, config: str
) -> None:
    """Defense in depth: an attempt that outlives its checkout's status is still money held."""
    world, _ = build(app_engine, admin_engine, config)
    with world.client:
        cid = first_complete(world, new_checkout(world))["id"]
        force_status(admin_engine, cid, "ready_for_complete")
        r = ucp_cancel(world, cid)
        assert codes(r) == ["complete_in_progress"] and r.json()["status"] == "ready_for_complete"


@pytest.mark.parametrize("config", CONFIGS)
@pytest.mark.parametrize("protocol", ["ucp", "acp"])
def test_cancel_before_any_attempt_still_works(
    app_engine: Engine, admin_engine: Engine, config: str, protocol: str
) -> None:
    world, _ = build(app_engine, admin_engine, config)
    with world.client:
        cid = new_checkout(world)["id"]
        r = ucp_cancel(world, cid) if protocol == "ucp" else acp_cancel(world, cid)
        assert r.status_code == 200 and r.json()["status"] == "canceled"
        assert not world.sim.orders
        # and a complete on it is refused as not ready, nothing is created
        pair = mandate_pair(world, new_checkout(world))
        gone = ucp_complete(world, cid, complete_body(pair.cm, pair.pm))
        assert codes(gone) == ["checkout_not_ready"] and not world.sim.orders


@pytest.mark.parametrize("config", CONFIGS)
def test_cancel_after_completion_reports_the_completed_checkout(
    app_engine: Engine, admin_engine: Engine, config: str
) -> None:
    world, _ = build(app_engine, admin_engine, config)
    with world.client:
        body = approved_checkout(world)
        done = ucp_complete(world, body["id"], {})
        assert done.json()["status"] == "completed"
        before = books(admin_engine)
        r = ucp_cancel(world, body["id"])
        assert r.json()["status"] == "completed" and codes(r) == ["checkout_not_cancelable"]
        a = acp_cancel(world, body["id"])
        assert a.status_code == 405 and a.json()["code"] == "not_cancelable"
        assert books(admin_engine) == before
        assert assert_consistent(world, admin_engine, body["id"]) == "completed"


def test_cancel_after_a_void_reports_the_ended_checkout(
    app_engine: Engine, admin_engine: Engine
) -> None:
    """The order was raised after approval: the gate (or the pre-authorize check) ended it."""
    world, _ = build(app_engine, admin_engine, "full")
    with world.client:
        body = approved_checkout(world)
        (order_id,) = world.sim.orders
        world.sim.fail_when["authorize"] = lambda sim: True  # the owner fails: void and release
        ended = ucp_complete(world, body["id"], {})
        assert ended.json()["status"] == "canceled"
        before = books(admin_engine)
        r = ucp_cancel(world, body["id"])
        assert r.json()["status"] == "canceled" and codes(r) == ["checkout_not_cancelable"]
        assert books(admin_engine) == before and order_id in world.sim.orders
        assert_consistent(world, admin_engine, body["id"])


# ------------------------------------------------------------------ the gate re-check


class NoRecheckStore(GateStore):
    """The gate store as it was before G-CHECKOUT: the move to `capturing` without the checkout."""

    def begin_capture(self, checkout_id: str) -> str | None:
        won = self.set_state(checkout_id, "capturing", expect=("gating",))
        return None if won else "lost_claim"


def gate_with(world: GateWorld, store: GateStore | None = None) -> CaptureGate:
    gate = world.new_gate()
    if store is not None:
        gate = CaptureGate(
            world.base.config, world.engine, world.base.client, gate._lock,
            clock=world.tick, paypal_now=gate._paypal_now, store=store,
        )  # fmt: skip
    return gate


@pytest.fixture
def gworld(app_engine: Engine, admin_engine: Engine) -> GateWorld:
    reset(admin_engine)
    return make_gate_world(app_engine)


@pytest.mark.parametrize("name", ["canceled", "ready_for_complete", "incomplete"])
def test_the_gate_voids_and_rejects_a_checkout_that_no_longer_owns_the_attempt(
    gworld: GateWorld, name: str
) -> None:
    gworld.authorize()
    set_status(gworld.engine, gworld.checkout.id, _status(name))
    outcome = gworld.gate.run(checkout_id=gworld.checkout.id, current=gworld.checkout)
    assert isinstance(outcome, GateRejected), outcome
    assert outcome.code == "G-CHECKOUT" and outcome.reason == f"checkout_{name}"
    assert gworld.sim.count("/capture") == 0 and gworld.sim.count("/void") == 1
    (auth,) = gworld.sim.authorizations.values()
    assert auth["status"] == "VOIDED", "the void was not confirmed by PayPal"
    row = gworld.row()
    assert row.state == "voided" and row.gate_code == "G-CHECKOUT" and row.receipt
    with gworld.engine.connect() as conn:
        held = {r.state for r in conn.execute(select(reservations)).all()}
    assert held <= {"released", "aborted"}, held
    assert [e.state for e in gworld.spend()] == ["voided"]


def test_the_gate_rejects_an_expired_checkout(gworld: GateWorld) -> None:
    seed_checkout(gworld.engine, gworld.checkout, expires_in_us=1_000)  # 1 ms
    gworld.authorize()
    time.sleep(0.05)  # the checkout's time passes between authorize and the gate
    outcome = gworld.gate.run(checkout_id=gworld.checkout.id, current=gworld.checkout)
    assert isinstance(outcome, GateRejected) and outcome.reason == "checkout_expired"
    assert gworld.sim.count("/capture") == 0 and gworld.sim.count("/void") == 1


def test_the_gate_rejects_a_checkout_with_no_row(gworld: GateWorld, admin_engine: Engine) -> None:
    gworld.authorize()
    with admin_engine.begin() as conn:
        conn.execute(text("DELETE FROM checkout_sessions WHERE id = :i"), {"i": gworld.checkout.id})
    outcome = gworld.gate.run(checkout_id=gworld.checkout.id, current=gworld.checkout)
    assert isinstance(outcome, GateRejected) and outcome.reason == "checkout_missing"
    assert gworld.sim.count("/capture") == 0


def test_without_the_recheck_the_same_checkout_is_captured(gworld: GateWorld) -> None:
    """What the re-check adds: with it removed, a canceled checkout still gets its money taken."""
    gworld.authorize()
    set_status(gworld.engine, gworld.checkout.id, _status("canceled"))
    gate = gate_with(gworld, NoRecheckStore(gworld.engine, lambda: _now_us()))
    outcome = gate.run(checkout_id=gworld.checkout.id, current=gworld.checkout)
    assert isinstance(outcome, GatePassed), outcome
    assert gworld.sim.count("/capture") == 1  # canceled-with-capture: the contradiction


def _status(name: str) -> Any:
    from countersign.checkout.state import Status

    return Status(name)


def _now_us() -> int:
    return time.time_ns() // 1000


# ------------------------------------------------------------------ forced interleavings


def hold_at(
    hook: Hook, predicate: Callable[[str, list[str]], bool]
) -> tuple[Rendezvous, list[str]]:
    """Hold the calling request at the first PayPal call for which `predicate(op, seen)` is true."""
    rendezvous, seen = Rendezvous(), []
    mine: dict[str, int] = {}

    def before(op: str) -> None:
        me = threading.get_ident()
        if mine.setdefault("t", me) != me:
            return
        seen.append(op)
        if not rendezvous.arrived.is_set() and predicate(op, seen):
            rendezvous.hold()

    hook.before = before
    return rendezvous, seen


@pytest.mark.parametrize("config", CONFIGS)
def test_cancel_before_the_claim_wins_and_the_complete_is_refused(
    app_engine: Engine, admin_engine: Engine, config: str
) -> None:
    world, _ = build(app_engine, admin_engine, config)
    with world.client:
        body = new_checkout(world)
        pair = mandate_pair(world, body)
        assert ucp_cancel(world, body["id"]).json()["status"] == "canceled"
        late = ucp_complete(world, body["id"], complete_body(pair.cm, pair.pm))
        assert codes(late) == ["checkout_not_ready"]
        assert not world.sim.orders and not world.sim.authorizations
        assert assert_consistent(world, admin_engine, body["id"]) == "canceled"


@pytest.mark.parametrize("config", CONFIGS)
def test_cancel_after_the_claim_before_authorize_is_refused_and_the_purchase_completes(
    app_engine: Engine, admin_engine: Engine, config: str
) -> None:
    world, hook = build(app_engine, admin_engine, config)
    with world.client:
        body = new_checkout(world)
        pair = mandate_pair(world, body)
        rendezvous, _ = hold_at(hook, lambda op, seen: op == "create")
        out: dict[str, Any] = {}
        t = in_thread(
            lambda: service(world).complete(body["id"], CompleteRequest(pair.cm, pair.pm), None),
            "owner",
            out,
        )
        assert rendezvous.arrived.wait(10)
        refused = ucp_cancel(world, body["id"])  # the claim exists, no PayPal order yet
        assert codes(refused) == ["complete_in_progress"]
        assert acp_cancel(world, body["id"]).status_code == 405
        rendezvous.released.set()
        t.join(20)
        hook.before = lambda op: None
        assert not isinstance(out["owner"], BaseException), out
        (order_id,) = world.sim.orders
        world.sim.approve(order_id)
        assert ucp_complete(world, body["id"], {}).json()["status"] == "completed"
        assert assert_consistent(world, admin_engine, body["id"]) == "completed"
    assert world.sim.count("/void") == 0


@pytest.mark.parametrize("config", CONFIGS)
def test_cancel_after_authorize_before_the_gate_is_refused_and_the_purchase_completes(
    app_engine: Engine, admin_engine: Engine, config: str
) -> None:
    world, hook = build(app_engine, admin_engine, config)
    with world.client:
        body = approved_checkout(world)
        rendezvous, _ = hold_at(hook, lambda op, seen: "authorize" in seen and op != "authorize")
        out: dict[str, Any] = {}
        t = in_thread(lambda: service(world).complete(body["id"], EMPTY, None), "owner", out)
        assert rendezvous.arrived.wait(10)
        assert len(world.sim.authorizations) == 1 and not world.sim.captures
        refused = ucp_cancel(world, body["id"])
        assert codes(refused) == ["complete_in_progress"]
        assert acp_cancel(world, body["id"]).status_code == 405
        rendezvous.released.set()
        t.join(20)
        hook.before = lambda op: None
        assert not isinstance(out["owner"], BaseException), out
        assert out["owner"].record.status.value == "completed" and out["owner"].receipts
        assert assert_consistent(world, admin_engine, body["id"]) == "completed"
    assert world.sim.count("/void") == 0


@pytest.mark.parametrize("config", CONFIGS)
def test_cancel_at_the_capture_call_is_refused_and_after_it_reports_the_purchase(
    app_engine: Engine, admin_engine: Engine, config: str
) -> None:
    world, hook = build(app_engine, admin_engine, config)
    with world.client:
        body = approved_checkout(world)
        rendezvous, _ = hold_at(hook, lambda op, seen: op == "capture")
        out: dict[str, Any] = {}
        t = in_thread(lambda: service(world).complete(body["id"], EMPTY, None), "owner", out)
        assert rendezvous.arrived.wait(10)
        assert attempt(admin_engine, body["id"]).state == "capturing"
        assert codes(ucp_cancel(world, body["id"])) == ["complete_in_progress"]
        rendezvous.released.set()
        t.join(20)
        hook.before = lambda op: None
        assert not isinstance(out["owner"], BaseException), out
        assert out["owner"].record.status.value == "completed" and out["owner"].receipts
        after = ucp_cancel(world, body["id"])  # after the gate captured
        assert after.json()["status"] == "completed" and codes(after) == ["checkout_not_cancelable"]
        assert assert_consistent(world, admin_engine, body["id"]) == "completed"


def test_a_cancel_that_slips_past_the_guard_is_caught_by_the_gate_through_the_service(
    app_engine: Engine, admin_engine: Engine
) -> None:
    """A cancel written straight to the store after authorize (any path that bypasses the guard):
    the gate voids, the service reports the rejection on a canceled checkout, books stay consistent."""
    world, hook = build(app_engine, admin_engine, "full")
    with world.client:
        body = approved_checkout(world)
        rendezvous, _ = hold_at(hook, lambda op, seen: "authorize" in seen and op != "authorize")
        out: dict[str, Any] = {}
        t = in_thread(lambda: service(world).complete(body["id"], EMPTY, None), "owner", out)
        assert rendezvous.arrived.wait(10)
        force_status(admin_engine, body["id"], "canceled")
        rendezvous.released.set()
        t.join(20)
        hook.before = lambda op: None
    result = out["owner"]
    assert not isinstance(result, BaseException), result
    assert result.record.status.value == "canceled"
    assert [m["code"] for m in result.messages] == ["payment_failed"]
    assert not world.sim.captures and world.sim.count("/void") == 1
    row = attempt(admin_engine, body["id"])
    assert row.state == "voided" and row.gate_code == "G-CHECKOUT"
    assert assert_consistent(world, admin_engine, body["id"]) == "canceled"


def test_the_gate_recheck_waits_for_a_cancel_that_holds_the_row_lock(
    gworld: GateWorld, admin_engine: Engine
) -> None:
    """The check and the move to `capturing` are under the checkout row lock: a cancel that is
    mid-transaction is waited for, and its outcome is what the gate sees. Without the lock the gate
    reads the old committed status, captures, and the cancel then commits: canceled with a capture."""
    gworld.authorize()
    cid = gworld.checkout.id
    out: dict[str, Any] = {}
    with admin_engine.connect() as conn:
        tx = conn.begin()
        conn.execute(
            text("SELECT status FROM checkout_sessions WHERE id = :i FOR UPDATE"), {"i": cid}
        )
        conn.execute(
            text("UPDATE checkout_sessions SET status = 'canceled', version = version + 1 "
                 "WHERE id = :i"), {"i": cid},
        )  # fmt: skip
        thread = in_thread(
            lambda: gworld.gate.run(checkout_id=cid, current=gworld.checkout), "gate", out
        )
        thread.join(1.5)
        assert thread.is_alive(), "the gate did not wait for the row lock"
        assert gworld.sim.count("/capture") == 0
        tx.commit()
    thread.join(20)
    outcome = out["gate"]
    assert isinstance(outcome, GateRejected) and outcome.reason == "checkout_canceled", outcome
    assert gworld.sim.count("/capture") == 0 and gworld.sim.count("/void") == 1


def test_acp_baseline_cancel_while_the_seam_is_at_paypal_is_refused(
    app_engine: Engine, admin_engine: Engine
) -> None:
    """The baseline ACP seam moves money, so the session must be `complete_in_progress` BEFORE it
    calls PayPal; otherwise a cancel between the read and the capture ends canceled with a capture."""
    world, hook = build(app_engine, admin_engine, "baseline")
    with world.client:
        session = acp_post(
            world, "/checkout_sessions",
            {"line_items": [{"id": _item_id(), "quantity": 1}], "currency": "usd",
             "capabilities": {}},
            acp_headers(None),
        ).json()  # fmt: skip
        cid = session["id"]
        path = f"/checkout_sessions/{cid}/complete"
        rendezvous, _ = hold_at(hook, lambda op, seen: op == "create")
        out: dict[str, Any] = {}
        t = in_thread(lambda: acp_post(world, path, ACP_PAYMENT, acp_headers(None)), "owner", out)
        assert rendezvous.arrived.wait(10)
        assert status_of(world, cid) == "complete_in_progress"
        assert acp_cancel(world, cid).status_code == 405
        assert codes(ucp_cancel(world, cid)) == ["complete_in_progress"]
        rendezvous.released.set()
        t.join(20)
        hook.before = lambda op: None
        (order_id,) = world.sim.orders
        world.sim.approve(order_id)
        assert acp_post(world, path, ACP_PAYMENT, acp_headers(None)).json()["status"] == "completed"
        assert len(world.sim.captures) == 1 and status_of(world, cid) == "completed"


# ------------------------------------------------------------------ stress

ITERATIONS = 100


def burst(jobs: list[Callable[[], Any]]) -> list[Any]:
    from concurrent.futures import ThreadPoolExecutor

    barrier = threading.Barrier(len(jobs))

    def go(job: Callable[[], Any]) -> Any:
        barrier.wait()
        return job()

    with ThreadPoolExecutor(max_workers=len(jobs)) as pool:
        return list(pool.map(go, jobs))


def cancel_outcome(r: Any) -> str:
    """Classify a cancel response of either protocol."""
    if r.status_code == 405:
        return str(r.json()["code"])
    assert r.status_code == 200, r.text
    body = r.json()
    return (
        "canceled"
        if body["status"] == "canceled" and not body.get("messages")
        else str(codes(r)[0] if codes(r) else body["status"])
    )


def _ucp_iteration(world: World, admin: Engine, i: int, tally: dict[str, int]) -> None:
    body = new_checkout(world)
    pair = mandate_pair(world, body)
    cid = body["id"]

    def complete_with_mandates() -> Any:
        return ucp_complete(world, cid, complete_body(pair.cm, pair.pm))

    def complete_again() -> Any:
        return ucp_complete(world, cid, {})

    def u_cancel() -> Any:
        return ucp_cancel(world, cid)

    def a_cancel() -> Any:
        return acp_cancel(world, cid)

    jobs = [complete_with_mandates, u_cancel, a_cancel, u_cancel]
    results = burst(jobs if i % 2 else jobs[::-1])
    assert all(r.status_code in (200, 405) for r in results), [r.text for r in results]
    status = status_of(world, cid)
    if status == "canceled":
        assert not world.sim.orders, "canceled although a PayPal order exists"
        tally["canceled"] = tally.get("canceled", 0) + 1
    else:
        assert status == "complete_in_progress"
        (order_id,) = world.sim.orders
        world.sim.approve(order_id)
        second = burst([complete_again, u_cancel, a_cancel, complete_again])
        assert all(r.status_code in (200, 405) for r in second), [r.text for r in second]
        for r in second[1:3]:
            assert cancel_outcome(r) in (
                "complete_in_progress",
                "checkout_not_cancelable",
                "not_cancelable",
            ), cancel_outcome(r)
        tally["completed"] = tally.get("completed", 0) + 1
    final = assert_consistent(world, admin, cid)
    assert final == ("canceled" if status == "canceled" else "completed")


@pytest.mark.parametrize("config", CONFIGS)
def test_ucp_cancel_and_complete_bursts_end_in_one_consistent_outcome(
    app_engine: Engine, admin_engine: Engine, config: str
) -> None:
    tally: dict[str, int] = {}
    for i in range(ITERATIONS):
        reset(admin_engine)
        world = make_world(app_engine, settings_for(config))
        with world.client:
            _ucp_iteration(world, admin_engine, i, tally)
    print("stress cancel x complete", config, tally)
    assert sum(tally.values()) == ITERATIONS


def _acp_iteration(world: World, i: int, tally: dict[str, int]) -> None:
    session = acp_post(
        world, "/checkout_sessions",
        {"line_items": [{"id": _item_id(), "quantity": 1}], "currency": "usd", "capabilities": {}},
        acp_headers(None),
    ).json()  # fmt: skip
    cid = session["id"]
    path = f"/checkout_sessions/{cid}/complete"

    def acp_complete() -> Any:
        return acp_post(world, path, ACP_PAYMENT, acp_headers(None))

    delay = 0.004 * (i % 6)  # staggers the cancels so both outcomes occur across iterations

    def a_cancel() -> Any:
        time.sleep(delay)
        return acp_cancel(world, cid)

    def u_cancel() -> Any:
        time.sleep(delay)
        return ucp_cancel(world, cid)

    jobs = [acp_complete, a_cancel, u_cancel, a_cancel]
    results = burst(jobs if i % 2 else jobs[::-1])
    assert all(r.status_code in (200, 405, 409) for r in results), [r.text for r in results]
    status = status_of(world, cid)
    if status == "canceled":
        assert not world.sim.orders
        tally["canceled"] = tally.get("canceled", 0) + 1
    else:
        assert status == "complete_in_progress"
        (order_id,) = world.sim.orders
        world.sim.approve(order_id)
        second = burst([acp_complete, a_cancel, u_cancel, acp_complete])
        assert all(r.status_code in (200, 405, 409) for r in second), [r.text for r in second]
        tally["completed"] = tally.get("completed", 0) + 1
    final = status_of(world, cid)
    assert final == ("canceled" if status == "canceled" else "completed")
    assert bool(world.sim.captures) == (final == "completed")
    assert len(world.sim.captures) <= 1 and world.sim.count("/void") == 0


def test_acp_baseline_cancel_and_complete_bursts_end_in_one_consistent_outcome(
    app_engine: Engine, admin_engine: Engine
) -> None:
    tally: dict[str, int] = {}
    for i in range(ITERATIONS):
        reset(admin_engine)
        world = make_world(app_engine, settings_for("baseline"))
        with world.client:
            _acp_iteration(world, i, tally)
    print("stress acp baseline cancel x complete", tally)
    assert sum(tally.values()) == ITERATIONS


def _item_id() -> str:
    from tests.mode_support import ITEM

    return str(ITEM.id)


# ------------------------------------------------------------------ the property


def _minor(value: str) -> int:
    from decimal import Decimal

    return int(Decimal(value) * 100)


@settings(
    max_examples=500,
    deadline=None,
    suppress_health_check=[HealthCheck.function_scoped_fixture, HealthCheck.too_slow],
)
@given(
    picks=st.lists(st.integers(min_value=0, max_value=7), min_size=1, max_size=60),
    ops=st.lists(st.sampled_from(["complete", "cancel", "acp_cancel"]), min_size=2, max_size=5),
    start_phase=st.booleans(),
    approve=st.booleans(),
    owner_fails=st.booleans(),
    config=st.sampled_from(["full", "baseline"]),
)
def test_over_any_interleaving_no_checkout_is_both_canceled_and_captured(
    app_engine: Engine,
    admin_engine: Engine,
    picks: list[int],
    ops: list[str],
    start_phase: bool,
    approve: bool,
    owner_fails: bool,
    config: str,
) -> None:
    world, hook = build(app_engine, admin_engine, config)
    with world.client:
        body = new_checkout(world)
        pair = mandate_pair(world, body)
        cid = body["id"]
        svc = service(world)

        def job(kind: str, presented: bool) -> Callable[[], Any]:
            if kind == "complete":
                req = CompleteRequest(pair.cm, pair.pm) if presented else EMPTY
                return lambda: svc.complete(cid, req, None)
            if kind == "cancel":
                return lambda: svc.cancel(cid)
            return lambda: acp_cancel(world, cid)

        if start_phase:
            scheduler = TokenScheduler(len(ops), picks)
            hook.before = scheduler.before_paypal
            scheduler.run([job(k, True) for k in ops])
            hook.before = lambda op: None
        else:
            svc.complete(cid, CompleteRequest(pair.cm, pair.pm), None)
        if world.sim.orders:
            (order_id,) = world.sim.orders
            if approve:
                world.sim.approve(order_id)
            if owner_fails:
                world.sim.fail_when["authorize"] = lambda sim: True
            scheduler = TokenScheduler(len(ops), list(reversed(picks)))
            hook.before = scheduler.before_paypal
            scheduler.run([job(k, False) for k in ops])
            hook.before = lambda op: None
            world.sim.fail_when.clear()
        svc.complete(cid, EMPTY, None)  # a sequential retry
        status = status_of(world, cid)
        row = attempt(admin_engine, cid)

    sim = world.sim
    assert len(sim.orders) <= 1 and len(sim.authorizations) <= 1 and len(sim.captures) <= 1
    if status == "canceled":
        assert not sim.captures, "a checkout both canceled and captured"
    if sim.captures:
        assert status == "completed"
        assert row is not None and row.state == "captured" and row.receipt and row.capture_id
    if status == "completed":
        assert len(sim.captures) == 1
    if "cancel" in ops or "acp_cancel" in ops:
        pass  # the rules above hold whatever the cancels did
    held = sum(_minor(c["amount"]["value"]) for c in sim.captures.values())
    assert held <= _minor_total(body)


def _minor_total(body: dict[str, Any]) -> int:
    return int(next(t for t in body["totals"] if t["type"] == "total")["amount"])


_ = (PausingTransport, wait_for)
