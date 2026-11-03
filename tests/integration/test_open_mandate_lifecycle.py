"""Open mandate identity, single use, budget and revocation on real Postgres (Decisions 86 and 88).

The real Merchant, Credential Provider and gate run on Postgres; only PayPal is the simulator. Every
test names a presentation or an ordering and asserts what PayPal and the books hold afterwards.
"""

from __future__ import annotations

import random
import threading
import time
from concurrent.futures import ThreadPoolExecutor
from typing import Any

import pytest
from sqlalchemy import Engine, select, text, update

from countersign.cp import CpApprovalRequired, CpAuthorized, CpRejected
from countersign.gate import GatePassed, GateRejected, revoke_mandate
from countersign.gate.store import GateStore
from countersign.merchant.verify import Accepted
from countersign.openmandates import ALREADY_USED, IN_FLIGHT, lock_row, revoke_in
from countersign.tables import open_mandate_revocations, payment_attempts
from tests.checkout_seed import seed_checkout
from tests.gate_support import GateWorld, make_gate_world
from tests.mandate_issuer import malleate_signature, open_identity
from tests.merchant_support import make_checkout


@pytest.fixture
def world(app_engine: Engine, clean_payments: None) -> GateWorld:
    return make_gate_world(app_engine)


def identities(mandates: Any) -> tuple[str, str]:
    return (
        open_identity(mandates.payment.open_token, "payment"),
        open_identity(mandates.checkout.open_token, "checkout"),
    )


def revocations(engine: Engine) -> list[Any]:
    with engine.connect() as conn:
        return list(conn.execute(select(open_mandate_revocations)).all())


def second_checkout(index: int) -> Any:
    return make_checkout(checkout_id=f"chk_second_{index:013d}xxxx")


def present(world: GateWorld, checkout: Any, mandates: Any) -> Any:
    """Merchant verify then CP start for a second presentation; returns the CP outcome."""
    seed_checkout(world.engine, checkout)
    verdict = world.merchant.verify(
        mandate=mandates.checkout_mandate, issued_checkout=None, current=checkout
    )
    if not isinstance(verdict, Accepted):
        return verdict
    return world.base.provider.start(
        payment_token=mandates.payment_token, checkout_mandate=mandates.checkout_mandate,
        current=checkout,
    )  # fmt: skip


# ------------------------------------------------------------------ single use across presentations


def test_a_fresh_presentation_of_a_used_open_mandate_cannot_buy_again(world: GateWorld) -> None:
    first, _ = world.authorize()
    outcome = world.gate.run(checkout_id=world.checkout.id, current=world.checkout)
    assert isinstance(outcome, GatePassed)
    # A new checkout, a new nonce, a new key binding; the same open mandates, re-presented.
    checkout = second_checkout(1)
    again = world.base.mandates(
        checkout=checkout, nonce="nonce-fresh",
        reuse_open_payment=first.payment.open_token,
        reuse_checkout_open=first.checkout.open_token,
    )  # fmt: skip
    result = present(world, checkout, again)
    assert not isinstance(result, CpApprovalRequired)
    assert world.sim.count("/orders") == 1  # one PayPal order ever, the first
    assert [e.state for e in world.spend()] == ["captured"]


def test_a_rewritten_issuer_signature_is_the_same_open_mandate(world: GateWorld) -> None:
    """The old key (digest of the presented serialization) let this through the Credential Provider."""
    first, _ = world.authorize()
    assert isinstance(
        world.gate.run(checkout_id=world.checkout.id, current=world.checkout), GatePassed
    )
    rewritten = malleate_signature(first.payment.open_token)
    checkout = second_checkout(2)
    again = world.base.mandates(
        checkout=checkout, nonce="nonce-rewritten", reuse_open_payment=rewritten,
        reuse_checkout_open=first.checkout.open_token,
    )  # fmt: skip
    # Straight to the Credential Provider: the Merchant would stop it on the checkout mandate's
    # identity, and this test is about the payment mandate's own key.
    seed_checkout(world.engine, checkout)
    started = world.base.provider.start(
        payment_token=again.payment_token, checkout_mandate=again.checkout_mandate,
        current=checkout,
    )  # fmt: skip
    assert isinstance(started, CpRejected), started
    assert world.sim.count("/orders") == 1
    assert [e.state for e in world.spend()] == ["captured"]


def test_the_budget_row_is_the_same_for_every_presentation(world: GateWorld) -> None:
    from countersign.mandates import VCT_PAYMENT, VCT_PAYMENT_OPEN, verify_chain

    first, _ = world.authorize()
    assert isinstance(
        world.gate.run(checkout_id=world.checkout.id, current=world.checkout), GatePassed
    )
    rewritten = malleate_signature(first.payment.open_token)
    again = world.base.mandates(
        checkout=second_checkout(3), nonce="nonce-budget", reuse_open_payment=rewritten,
        reuse_checkout_open=first.checkout.open_token,
    )  # fmt: skip
    from tests.mandate_issuer import NOW

    chains = [
        verify_chain(
            token,
            issuer_key=world.base.keys.issuer,
            expected_vcts=[VCT_PAYMENT_OPEN, VCT_PAYMENT],
            audience="credential-provider",
            clock=lambda: float(NOW),
        )
        for token in (first.payment_token, again.payment_token)
    ]
    assert chains[0].identity == chains[1].identity
    with world.engine.connect() as conn:
        view = world.base.ledger.view(conn, chains[1].identity, "USD")
    assert view.captured_minor == 8500  # the second presentation sees what the first spent


# ------------------------------------------------------------------ revocation: before, between, after


def test_revoking_before_any_presentation_stops_the_purchase_at_the_credential_provider(
    world: GateWorld,
) -> None:
    checkout = world.checkout
    seed_checkout(world.engine, checkout)
    m = world.base.mandates(checkout=checkout)
    payment_id, checkout_id = identities(m)
    assert revoke_mandate(world.engine, payment_id, checkout_id, lambda: 1).new is True
    started = world.base.provider.start(
        payment_token=m.payment_token, checkout_mandate=m.checkout_mandate, current=checkout
    )
    assert isinstance(started, CpRejected) and started.reason == "mandate_revoked"
    assert world.sim.orders == {}


def test_revoking_after_payer_approval_stops_the_authorization(world: GateWorld) -> None:
    checkout = world.checkout
    seed_checkout(world.engine, checkout)
    m = world.base.mandates(checkout=checkout)
    verdict = world.merchant.verify(
        mandate=m.checkout_mandate, issued_checkout=None, current=checkout
    )
    assert isinstance(verdict, Accepted)
    started = world.base.provider.start(
        payment_token=m.payment_token, checkout_mandate=m.checkout_mandate, current=checkout
    )
    assert isinstance(started, CpApprovalRequired)
    world.sim.approve(started.order_id)
    payment_id, checkout_id = identities(m)
    revoke_mandate(world.engine, payment_id, checkout_id, lambda: 1)
    done = world.base.provider.finish(checkout_id=checkout.id, current=checkout)
    assert isinstance(done, CpRejected) and done.reason == "preauthorize_mandate_revoked"
    assert world.sim.count("/authorize") == 0


def test_revoking_between_authorization_and_capture_voids_at_the_gate(world: GateWorld) -> None:
    m, done = world.authorize()
    assert isinstance(done, CpAuthorized)
    revoke_mandate(world.engine, *identities(m), lambda: 1)
    outcome = world.gate.run(checkout_id=world.checkout.id, current=world.checkout)
    assert isinstance(outcome, GateRejected) and outcome.reason == "mandate_revoked"
    assert world.sim.count("/capture") == 0 and world.sim.count("/void") == 1


def test_the_gate_checks_revocation_again_under_the_lock_that_moves_to_capturing(
    world: GateWorld,
) -> None:
    """A revocation that commits after every earlier gate step still stops the capture."""
    m, _ = world.authorize()
    store = GateStore(world.engine, lambda: 1)
    assert store.claim(world.checkout.id, expect=("authorized",))
    revoke_mandate(world.engine, *identities(m), lambda: 1)
    assert store.begin_capture(world.checkout.id) == "mandate_revoked"
    assert world.row().state == "gating"  # never moved to capturing


def test_revoking_after_the_capture_answers_already_used_and_changes_nothing(
    world: GateWorld,
) -> None:
    m, _ = world.authorize()
    assert isinstance(
        world.gate.run(checkout_id=world.checkout.id, current=world.checkout), GatePassed
    )
    out = revoke_mandate(world.engine, *identities(m), lambda: 1)
    assert out.code == ALREADY_USED and not out.new
    assert revocations(world.engine) == []


def test_revoking_is_idempotent_and_insert_only(world: GateWorld) -> None:
    m = world.base.mandates()
    first = revoke_mandate(world.engine, *identities(m), lambda: 1)
    second = revoke_mandate(world.engine, *identities(m), lambda: 2)
    assert first.new is True and second.new is False and second.code is None
    assert len(revocations(world.engine)) == 1
    with world.engine.begin() as conn, pytest.raises(Exception):  # noqa: B017
        conn.execute(text("DELETE FROM open_mandate_revocations"))
    with world.engine.begin() as conn, pytest.raises(Exception):  # noqa: B017
        conn.execute(text("UPDATE open_mandate_revocations SET revoked_us = 0"))
    assert len(revocations(world.engine)) == 1


# ------------------------------------------------------------------ in flight, deterministically


@pytest.mark.parametrize("state", ["capturing", "unresolved"])
def test_revoking_while_a_capture_is_under_way_answers_in_flight(
    world: GateWorld, state: str
) -> None:
    m, _ = world.authorize()
    with world.engine.begin() as conn:
        conn.execute(
            update(payment_attempts)
            .where(payment_attempts.c.checkout_id == world.checkout.id)
            .values(state=state)
        )
    out = revoke_mandate(world.engine, *identities(m), lambda: 1)
    assert out.code == IN_FLIGHT and revocations(world.engine) == []


@pytest.mark.parametrize(
    "state", ["reserved", "order_created", "authorizing", "authorized", "gating"]
)
def test_revoking_before_the_capture_is_claimed_is_effective(world: GateWorld, state: str) -> None:
    m, _ = world.authorize()
    with world.engine.begin() as conn:
        conn.execute(
            update(payment_attempts)
            .where(payment_attempts.c.checkout_id == world.checkout.id)
            .values(state=state)
        )
    out = revoke_mandate(world.engine, *identities(m), lambda: 1)
    assert out.code is None and out.new is True


def test_revoke_waits_for_a_gate_that_holds_the_open_mandate_row(world: GateWorld) -> None:
    """The gate's transaction holds the row FOR SHARE and moves the attempt to capturing; a revoke
    arriving meanwhile waits for it and then answers in_flight, writing nothing."""
    m, _ = world.authorize()
    payment_id, checkout_id = identities(m)
    answer: list[Any] = []
    with world.engine.connect() as holder:
        trans = holder.begin()
        lock_row(holder, payment_id, "USD", share=True)
        holder.execute(
            update(payment_attempts)
            .where(payment_attempts.c.checkout_id == world.checkout.id)
            .values(state="capturing")
        )
        worker = threading.Thread(
            target=lambda: answer.append(
                revoke_mandate(world.engine, payment_id, checkout_id, lambda: 1)
            )
        )
        worker.start()
        worker.join(0.5)
        assert worker.is_alive() and answer == []  # it is waiting on the row lock
        trans.commit()
    worker.join(5)
    assert answer[0].code == IN_FLIGHT and revocations(world.engine) == []


def test_the_gate_waits_for_a_revoke_that_holds_the_open_mandate_row(world: GateWorld) -> None:
    """A revoke holding the row (not yet committed) makes the gate wait; once it commits the gate
    sees the revocation and refuses to move to capturing."""
    m, _ = world.authorize()
    payment_id, checkout_id = identities(m)
    store = GateStore(world.engine, lambda: 1)
    assert store.claim(world.checkout.id, expect=("authorized",))
    answer: list[Any] = []
    with world.engine.connect() as holder:
        trans = holder.begin()
        assert revoke_in(
            holder, payment_identity=payment_id, checkout_identity=checkout_id, currency="USD",
            now_us=1,
        ).new  # fmt: skip
        worker = threading.Thread(
            target=lambda: answer.append(store.begin_capture(world.checkout.id))
        )
        worker.start()
        worker.join(0.5)
        assert worker.is_alive() and answer == []
        trans.commit()
    worker.join(5)
    assert answer == ["mandate_revoked"]
    assert world.row().state == "gating"


# ------------------------------------------------------------------ the race


def race_once(
    world: GateWorld, checkout: Any, payment_id: str, checkout_id: str, delay: float
) -> tuple[Any, Any]:
    """Run the gate and a revoke at once; the revoke starts `delay` seconds after the barrier."""
    barrier = threading.Barrier(2)

    def gate_side() -> Any:
        barrier.wait()
        return world.gate.run(checkout_id=checkout.id, current=checkout)

    def revoke_side() -> Any:
        barrier.wait()
        time.sleep(delay)
        return revoke_mandate(world.engine, payment_id, checkout_id, lambda: 1)

    with ThreadPoolExecutor(2) as pool:
        gate_future, revoke_future = pool.submit(gate_side), pool.submit(revoke_side)
        return gate_future.result(), revoke_future.result()


def test_revoke_concurrent_with_the_gate_ends_in_one_consistent_outcome(
    app_engine: Engine, clean_payments: None
) -> None:
    """Many interleavings. Either (revoked, nothing captured, the authorization voided) or (captured,
    the revoke refused). Never a capture with a revocation row beside it."""
    rng = random.Random(20261103)
    wins = {"revoked": 0, "captured": 0}
    for index in range(36):
        world = make_gate_world(app_engine)
        checkout = make_checkout(checkout_id=f"chk_race_{index:016d}xxx")
        world.base.checkout = checkout
        m, _ = world.authorize(checkout=checkout)
        payment_id, checkout_id = identities(m)
        # Slow the live reads a little so the two sides really overlap at different steps.
        world.sim.inject("get_order", lambda _r: time.sleep(rng.uniform(0, 0.03)), times=30)
        delay = 0.0 if index == 0 else 0.4 if index == 1 else rng.uniform(0, 0.12)
        outcome, answer = race_once(world, checkout, payment_id, checkout_id, delay)
        revoked_rows = [r for r in revocations(world.engine) if r.payment_identity == payment_id]
        row = world.row(checkout.id)
        if answer.code is None:
            assert answer.new and len(revoked_rows) == 1, (index, answer)
            assert not isinstance(outcome, GatePassed), (
                index,
                "captured after a revoke row exists",
            )
            assert row.state == "voided" and world.sim.count("/capture") == 0, (index, row.state)
            wins["revoked"] += 1
        else:
            assert answer.code in (IN_FLIGHT, ALREADY_USED), (index, answer)
            assert revoked_rows == [], (index, "a refused revoke left a row")
            assert isinstance(outcome, GatePassed) and row.state == "captured", (index, outcome)
            assert world.sim.count("/capture") == 1
            wins["captured"] += 1
        # Exactly one PayPal effect either way.
        assert world.sim.count("/capture") + world.sim.count("/void") == 1, index
    assert wins["revoked"] >= 1 and wins["captured"] >= 1, wins
