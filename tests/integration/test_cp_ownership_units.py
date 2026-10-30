"""The ownership guards one by one, on the real Postgres (docs/PROTOCOL.md Decision 67)."""

from __future__ import annotations

from typing import Any

import pytest
from sqlalchemy import Engine, select, update
from sqlalchemy.exc import IntegrityError

from countersign.completion import CompleteCoordinator
from countersign.cp import CpApprovalRequired, CpInProgress, CpRejected
from countersign.cp.provider import OWNED_BY_RECOVER, OWNED_BY_START, CredentialProvider
from countersign.ledger.store import entries_for_checkout
from countersign.tables import payment_attempts, reservations
from tests.cp_support import CpWorld, make_world


@pytest.fixture
def world(app_engine: Engine, clean_payments: None) -> CpWorld:
    return make_world(app_engine)


def started(world: CpWorld) -> Any:
    m = world.mandates()
    result = world.provider.start(
        payment_token=m.payment_token, checkout_mandate=m.checkout_mandate, current=world.checkout
    )
    assert isinstance(result, CpApprovalRequired)
    return m


def row(world: CpWorld) -> Any:
    with world.engine.connect() as conn:
        return conn.execute(
            select(payment_attempts).where(payment_attempts.c.checkout_id == world.checkout.id)
        ).one()


def kinds(world: CpWorld) -> list[str]:
    with world.engine.connect() as conn:
        return [e.kind for e in entries_for_checkout(conn, world.checkout.id)]


def test_a_finish_that_loses_the_claim_calls_nothing_and_changes_nothing(world: CpWorld) -> None:
    started(world)
    (order_id,) = world.sim.orders
    world.sim.approve(order_id)
    with world.engine.begin() as conn:  # another request holds the claim
        conn.execute(
            update(payment_attempts)
            .where(payment_attempts.c.checkout_id == world.checkout.id)
            .values(state="authorizing")
        )
    before = (len(world.sim.calls), row(world).updated_us)
    result = world.provider.finish(checkout_id=world.checkout.id, current=world.checkout)
    assert isinstance(result, CpInProgress) and result.state == "authorizing"
    assert (len(world.sim.calls), row(world).updated_us) == before  # no PayPal call, no write


def test_a_finish_that_sees_a_reserved_attempt_is_in_progress_not_a_rejection(
    world: CpWorld,
) -> None:
    started(world)
    with world.engine.begin() as conn:
        conn.execute(
            update(payment_attempts)
            .where(payment_attempts.c.checkout_id == world.checkout.id)
            .values(state="reserved")
        )
    result = world.provider.finish(checkout_id=world.checkout.id, current=world.checkout)
    assert isinstance(result, CpInProgress) and result.state == "reserved"


def test_the_owner_gives_the_claim_back_when_the_payer_has_not_approved(world: CpWorld) -> None:
    started(world)
    first = world.provider.finish(checkout_id=world.checkout.id, current=world.checkout)
    assert type(first).__name__ == "CpPending" and row(world).state == "order_created"
    (order_id,) = world.sim.orders
    world.sim.approve(order_id)
    later = world.provider.finish(checkout_id=world.checkout.id, current=world.checkout)
    assert type(later).__name__ == "CpAuthorized"  # the claim was free again


def test_a_cleanup_by_a_caller_that_does_not_own_the_state_does_nothing(world: CpWorld) -> None:
    started(world)
    (order_id,) = world.sim.orders
    world.sim.approve(order_id)
    world.provider.finish(checkout_id=world.checkout.id, current=world.checkout)
    assert row(world).state == "authorized"
    calls = len(world.sim.calls)
    # A caller that only owns the early states (a stale `start`) must not touch an authorized attempt.
    world.provider._cleanup(world.checkout.id, "stale", owned=("reserved", "order_created"))
    assert row(world).state == "authorized" and len(world.sim.calls) == calls
    assert "cp.cleanup.skipped" in kinds(world) and world.sim.count("/void") == 0


def test_the_end_of_a_cleanup_cannot_rewrite_an_attempt_that_changed_meanwhile(
    world: CpWorld, monkeypatch: pytest.MonkeyPatch
) -> None:
    """A stale read says `authorizing`; the gate has since claimed it. The statement that ends the
    cleanup is conditional on the owned states, so the attempt the gate holds stays with the gate."""
    started(world)
    (order_id,) = world.sim.orders
    world.sim.approve(order_id)
    world.provider.finish(checkout_id=world.checkout.id, current=world.checkout)
    stale = row(world)
    with world.engine.begin() as conn:
        conn.execute(
            update(payment_attempts)
            .where(payment_attempts.c.checkout_id == world.checkout.id)
            .values(state="gating")
        )
    monkeypatch.setattr(world.provider, "_row", lambda checkout_id: stale)
    world.provider._cleanup(world.checkout.id, "stale", owned=("authorized",))
    monkeypatch.undo()
    assert row(world).state == "gating"
    with world.engine.connect() as conn:
        held = {r.role: r.state for r in conn.execute(select(reservations)).all()}
    assert held["cp"] != "released"  # nothing was released by the non-owner


def test_a_recover_that_was_overtaken_by_the_owner_does_nothing(world: CpWorld) -> None:
    started(world)
    stale_us = row(world).updated_us - 1  # what recover read; the owner has written since
    calls = len(world.sim.calls)
    world.provider._cleanup(
        world.checkout.id, "recover:order_created", owned=OWNED_BY_RECOVER, fence_us=stale_us
    )
    assert row(world).state == "order_created" and len(world.sim.calls) == calls
    assert "cp.cleanup.skipped" in kinds(world)


def test_a_cleanup_that_cannot_record_unresolved_does_not_raise(
    world: CpWorld, monkeypatch: pytest.MonkeyPatch
) -> None:
    started(world)
    original = CredentialProvider._set_state

    def refuse(self: Any, checkout_id: str, state: str, **kw: Any) -> bool:
        if state == "unresolved":
            raise IntegrityError("UPDATE", {}, Exception("a finished payment attempt is final"))
        return bool(original(self, checkout_id, state, **kw))

    def boom(*_: Any, **__: Any) -> None:
        raise RuntimeError("the cleanup transaction fails")

    monkeypatch.setattr(CredentialProvider, "_set_state", refuse)
    monkeypatch.setattr(world.provider._ledger, "void", boom)
    world.provider._cleanup(world.checkout.id, "x", owned=OWNED_BY_START)  # must not raise


class _StubProvider:
    """Only what the coordinator calls on a continuing attempt."""

    def __init__(self, result: Any) -> None:
        self._result = result

    def attempt_state(self, checkout_id: str) -> str:
        return "order_created"

    def finish(self, **_: Any) -> Any:
        return self._result


class _RecordingStore:
    def __init__(self) -> None:
        self.released: list[str] = []

    def release_checkout(self, checkout_id: str) -> bool:
        self.released.append(checkout_id)
        return True


def rejection(*, cleaned: bool) -> CpRejected:
    return CpRejected(
        "receipt", [{"code": "payment_failed"}], "C8", "r", "payment_failed", "", "ref", cleaned
    )


def test_the_coordinator_releases_the_merchant_reservation_only_for_an_owner_rejection(
    world: CpWorld,
) -> None:
    store = _RecordingStore()
    for cleaned, released, kind in (
        (False, [], "in_progress"),
        (True, [world.checkout.id], "rejected"),
    ):
        store.released.clear()
        coordinator = CompleteCoordinator(
            None,
            store,
            _StubProvider(rejection(cleaned=cleaned)),  # type: ignore[arg-type]
        )
        outcome = coordinator.complete(
            checkout=world.checkout, mandate=None, payment_token=None, resume=True
        )
        assert outcome.kind == kind and store.released == released
