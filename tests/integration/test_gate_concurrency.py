"""Races and crashes: the capture or the void happens exactly once (real Postgres).

Two gate objects over one database model two processes. The PayPal simulator counts the capture and
void requests that reach it, which is the ground truth: a gate that raced would show two.
"""

from __future__ import annotations

import threading
import time
from concurrent.futures import ThreadPoolExecutor
from typing import Any

import pytest
from sqlalchemy import Engine

from countersign.gate import (
    GatePassed,
    GatePending,
    GateRejected,
    GateUnresolved,
    revoke_mandate,
)
from countersign.gate.store import GateStore
from countersign.merchant.pg_reservations import PostgresReservationStore
from tests.gate_support import GateWorld, make_gate_world
from tests.merchant_support import make_checkout


@pytest.fixture
def world(app_engine: Engine, clean_payments: None) -> GateWorld:
    return make_gate_world(app_engine)


def slow_reads(world: GateWorld, times: int = 40, delay: float = 0.05) -> None:
    """Make the live order read slow so racing gates really overlap."""

    def hook(request: Any) -> None:
        time.sleep(delay)

    world.sim.inject("get_order", hook, times=times)


def race(world: GateWorld, count: int) -> list[Any]:
    gates = [world.new_gate() for _ in range(count)]
    barrier = threading.Barrier(count)

    def go(gate: Any) -> Any:
        barrier.wait()
        return gate.run(checkout_id=world.checkout.id, current=world.checkout)

    with ThreadPoolExecutor(count) as pool:
        return list(pool.map(go, gates))


def test_gates_racing_on_one_checkout_capture_exactly_once(world: GateWorld) -> None:
    world.authorize()
    slow_reads(world)
    outcomes = race(world, 6)
    assert world.sim.count("/capture") == 1 and world.sim.count("/void") == 0
    passed = [o for o in outcomes if isinstance(o, GatePassed)]
    assert len(passed) >= 1
    assert all(isinstance(o, GatePassed | GatePending) for o in outcomes)
    assert len({o.capture_id for o in passed}) == 1
    assert world.row().state == "captured"
    assert [e.state for e in world.spend()] == ["captured"]


def test_gates_racing_on_a_failing_checkout_void_exactly_once(world: GateWorld) -> None:
    mandates, _ = world.authorize()
    from countersign.canonical import sd_hash

    revoke_mandate(world.engine, sd_hash(mandates.payment.open_token), lambda: 1)
    slow_reads(world)
    outcomes = race(world, 6)
    assert world.sim.count("/void") == 1 and world.sim.count("/capture") == 0
    assert all(isinstance(o, GateRejected | GatePending) for o in outcomes)
    assert any(isinstance(o, GateRejected) for o in outcomes)
    assert world.row().state == "voided"
    assert [e.state for e in world.spend()] == ["voided"]


def test_a_purchase_racing_the_first_under_one_open_mandate_authorizes_and_captures_once(
    world: GateWorld,
) -> None:
    from countersign.cp import CpApprovalRequired, CpRejected

    # A budget with room for both: only the single-use open mandate can stop the second.
    first = world.base.mandates(maximum=30_000)
    other_checkout = make_checkout(checkout_id="chk_racing_second_0000")
    second = world.base.mandates(
        checkout=other_checkout, nonce="nonce-0002",
        reuse_open_payment=first.payment.open_token, reuse_checkout_open=first.checkout.open_token,
    )  # fmt: skip
    pairs = [(first, world.checkout), (second, other_checkout)]
    barrier = threading.Barrier(2)

    def start(pair: Any) -> Any:
        mandates, checkout = pair
        barrier.wait()
        return world.base.provider.start(
            payment_token=mandates.payment_token, checkout_mandate=mandates.checkout_mandate,
            current=checkout,
        )  # fmt: skip

    with ThreadPoolExecutor(2) as pool:
        results = list(pool.map(start, pairs))
    won = [r for r in results if isinstance(r, CpApprovalRequired)]
    lost = [r for r in results if isinstance(r, CpRejected)]
    assert len(won) == 1 and len(lost) == 1 and lost[0].reason == "open_mandate_in_use"
    assert len(world.sim.orders) == 1

    # Only the winner is authorized and captured, once.
    winner_checkout = world.checkout if results[0] is won[0] else other_checkout
    world.sim.approve(won[0].order_id)
    done = world.base.provider.finish(checkout_id=winner_checkout.id, current=winner_checkout)
    assert done.__class__.__name__ == "CpAuthorized"
    # (the Merchant reservation of the winner is made here, as complete would have made it)
    PostgresReservationStore(world.engine, "merchant").reserve(
        _merchant_request(winner_checkout.id, world, results[0] is won[0] and first or second)
    )
    outcome = world.gate.run(checkout_id=winner_checkout.id, current=winner_checkout)
    assert isinstance(outcome, GatePassed), outcome
    assert world.sim.count("/authorize") == 1 and world.sim.count("/capture") == 1
    # After the capture the mandate is consumed: a later purchase is refused too.
    again = world.base.provider.start(
        payment_token=second.payment_token, checkout_mandate=second.checkout_mandate,
        current=other_checkout,
    )  # fmt: skip
    assert isinstance(again, CpRejected)


def _merchant_request(checkout_id: str, world: GateWorld, mandates: Any) -> Any:
    from countersign.canonical import checkout_hash, sd_hash
    from countersign.merchant.authorization import checkout_jwt
    from countersign.merchant.reservations import ReservationRequest

    return ReservationRequest(
        checkout_id, checkout_hash(checkout_jwt(mandates.issued)),
        sd_hash(mandates.checkout.open_token), None,
    )  # fmt: skip


# ------------------------------------------------------------------------------ crashes


def test_a_crash_between_authorize_and_capture_is_finished_by_a_retry(world: GateWorld) -> None:
    world.authorize()
    assert world.row().state == "authorized"  # the process dies here; nothing ran the gate
    fresh = world.new_gate()  # a new process
    outcome = fresh.run(checkout_id=world.checkout.id, current=world.checkout)
    assert isinstance(outcome, GatePassed)
    assert world.sim.count("/capture") == 1 and world.sim.count("/void") == 0


def test_recovery_voids_an_authorization_nobody_gated_and_never_captures(world: GateWorld) -> None:
    world.authorize()
    touched = world.new_gate().recover(older_than_us=0)
    assert touched == [world.checkout.id]
    assert world.sim.count("/capture") == 0 and world.sim.count("/void") == 1
    assert world.row().state == "voided"
    assert [e.state for e in world.spend()] == ["voided"]
    assert world.new_gate().recover(older_than_us=0) == []  # nothing left to settle


def test_a_crash_inside_the_gate_is_taken_over_once_the_claim_is_stale(world: GateWorld) -> None:
    world.authorize()
    store = GateStore(world.engine, lambda: int(time.time() * 1_000_000))
    assert store.claim(world.checkout.id, expect=("authorized",))  # a gate claimed, then died
    # While the claim is fresh another gate waits.
    waiting = world.new_gate().run(checkout_id=world.checkout.id, current=world.checkout)
    assert isinstance(waiting, GatePending) and world.sim.calls[-1][0] != "POST"
    takeover = world.new_gate(claim_stale_us=0).run(
        checkout_id=world.checkout.id, current=world.checkout
    )
    assert isinstance(takeover, GatePassed)
    assert world.sim.count("/capture") == 1


def test_a_crash_between_capture_and_receipt_is_finished_without_a_second_capture(
    world: GateWorld, monkeypatch: pytest.MonkeyPatch
) -> None:
    world.authorize()

    def die(self: GateStore, *args: Any, **kwargs: Any) -> None:
        raise RuntimeError("process died after the capture")

    monkeypatch.setattr(GateStore, "finish_captured", die)
    first = world.gate.run(checkout_id=world.checkout.id, current=world.checkout)
    monkeypatch.undo()
    # Money moved; the books are not finished, so nothing is released and nothing is voided.
    assert isinstance(first, GateUnresolved) and first.reason == "bookkeeping_failed"
    assert world.sim.count("/capture") == 1 and world.sim.count("/void") == 0
    assert world.row().state == "unresolved"
    assert [e.state for e in world.spend()] == ["in_flight"]
    assert set(world.reservation_states().values()) == {"reserved"}

    finished = world.new_gate().run(checkout_id=world.checkout.id, current=world.checkout)
    assert isinstance(finished, GatePassed)
    assert world.sim.count("/capture") == 1 and world.sim.count("/void") == 0  # still exactly one
    assert [e.state for e in world.spend()] == ["captured"]
    assert world.row().state == "captured"


def test_recovery_finishes_a_capture_whose_books_were_left_open(
    world: GateWorld, monkeypatch: pytest.MonkeyPatch
) -> None:
    world.authorize()
    monkeypatch.setattr(
        GateStore, "finish_captured", lambda self, *a, **k: (_ for _ in ()).throw(RuntimeError)
    )
    world.gate.run(checkout_id=world.checkout.id, current=world.checkout)
    monkeypatch.undo()
    assert world.new_gate().recover(older_than_us=0) == [world.checkout.id]
    assert world.sim.count("/capture") == 1 and world.sim.count("/void") == 0
    assert world.row().state == "captured"


def test_paypal_unreadable_during_recovery_leaves_everything_reserved(world: GateWorld) -> None:
    world.authorize()
    world.sim.fail_when["get_order"] = lambda sim: True
    world.new_gate().recover(older_than_us=0)
    assert world.sim.count("/void") == 0 and world.sim.count("/capture") == 0
    assert world.row().state == "unresolved"
    assert set(world.reservation_states().values()) == {"reserved"}


# ------------------------------------------------------- a takeover reads PayPal first (Decision 41)


class Died(BaseException):
    """Stands for a process that dies: it is not an `Exception`, so no handler in the gate catches it."""


def writes(world: GateWorld) -> list[str]:
    return [p for m, p, _ in world.sim.calls if m == "POST" and not p.startswith("/v1/")]


def test_a_takeover_after_the_capture_landed_reads_paypal_and_never_captures_again(
    world: GateWorld, monkeypatch: pytest.MonkeyPatch
) -> None:
    from countersign.gate.gate import CaptureGate

    world.authorize()

    def die(self: Any, *args: Any, **kwargs: Any) -> None:
        raise Died

    monkeypatch.setattr(CaptureGate, "_confirm_and_finalize", die)
    with pytest.raises(Died):  # the capture reached PayPal, then the process died
        world.gate.run(checkout_id=world.checkout.id, current=world.checkout)
    monkeypatch.undo()
    assert world.row().state == "capturing" and world.sim.count("/capture") == 1

    calls_before = len(world.sim.calls)
    outcome = world.new_gate(claim_stale_us=0).run(
        checkout_id=world.checkout.id, current=world.checkout
    )
    assert isinstance(outcome, GatePassed)
    after = world.sim.calls[calls_before:]
    assert after[0][0] == "GET"  # the first thing a takeover does is read live state
    assert world.sim.count("/capture") == 1 and world.sim.count("/void") == 0
    assert [e.state for e in world.spend()] == ["captured"]


def test_a_takeover_before_the_capture_was_sent_reads_first_and_captures_once(
    world: GateWorld,
) -> None:
    world.authorize()
    store = GateStore(world.engine, lambda: int(time.time() * 1_000_000))
    assert store.claim(world.checkout.id, expect=("authorized",))
    assert store.set_state(
        world.checkout.id, "capturing", expect=("gating",)
    )  # died before sending
    calls_before = len(world.sim.calls)
    outcome = world.new_gate(claim_stale_us=0).run(
        checkout_id=world.checkout.id, current=world.checkout
    )
    assert isinstance(outcome, GatePassed)
    after = world.sim.calls[calls_before:]
    assert after[0][0] == "GET" and world.sim.count("/capture") == 1


def test_a_takeover_of_an_order_changed_meanwhile_voids_instead_of_capturing(
    world: GateWorld,
) -> None:
    world.authorize()
    store = GateStore(world.engine, lambda: int(time.time() * 1_000_000))
    assert store.claim(world.checkout.id, expect=("authorized",))
    world.sim.patch(world.row().order_id, item_name="Changed while the gate was dead")
    outcome = world.new_gate(claim_stale_us=0).run(
        checkout_id=world.checkout.id, current=world.checkout
    )
    assert isinstance(outcome, GateRejected) and outcome.code == "G-TERMS"
    assert world.sim.count("/capture") == 0 and world.sim.count("/void") == 1
