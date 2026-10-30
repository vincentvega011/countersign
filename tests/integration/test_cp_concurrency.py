"""Concurrency against the real Postgres: one mandate, one order, one authorization."""

from __future__ import annotations

import threading
from concurrent.futures import ThreadPoolExecutor
from typing import Any

import pytest
from sqlalchemy import Engine, select

from countersign.constraints import SpendView
from countersign.constraints import payment as payment_constraints
from countersign.constraints.payment import PaymentFacts
from countersign.cp import CpApprovalRequired, CpAuthorized, CpInProgress, CpPending, CpRejected
from countersign.cp.ledger import SpendLedger
from countersign.tables import reservations, spend_entries
from tests.cp_support import CpWorld, make_world

N = 20


@pytest.fixture
def world(app_engine: Engine, clean_payments: None) -> CpWorld:
    return make_world(app_engine)


def run_parallel(fn: Any, jobs: list[Any]) -> list[Any]:
    barrier = threading.Barrier(len(jobs))

    def go(job: Any) -> Any:
        barrier.wait()
        return fn(job)

    with ThreadPoolExecutor(max_workers=len(jobs)) as pool:
        return list(pool.map(go, jobs))


def test_twenty_parallel_completes_with_one_mandate_make_one_order_and_one_authorization(
    world: CpWorld,
) -> None:
    m = world.mandates(maximum=100_000)

    def start(_: int) -> Any:
        return world.provider.start(
            payment_token=m.payment_token, checkout_mandate=m.checkout_mandate, current=m.current
        )

    results = run_parallel(start, list(range(N)))
    assert sum(isinstance(r, CpApprovalRequired) for r in results) == 1
    losers = [r for r in results if isinstance(r, CpRejected)]
    assert len(losers) == N - 1
    assert {(r.step, r.reason) for r in losers} <= {
        ("C6", "checkout_hash_reused"), ("C6", "nonce_replayed"), ("C6", "open_mandate_in_use"),
    }  # fmt: skip
    assert len(world.sim.orders) == 1 and world.sim.count("/v2/checkout/orders") == 1

    (order_id,) = world.sim.orders
    world.sim.approve(order_id)

    def finish(_: int) -> Any:
        return world.provider.finish(checkout_id=world.checkout.id, current=world.checkout)

    done = run_parallel(finish, list(range(N)))
    assert all(isinstance(r, (CpAuthorized, CpPending, CpInProgress)) for r in done)
    assert not any(isinstance(r, CpRejected) for r in done)  # no racer rejects or cleans up
    assert sum(isinstance(r, CpAuthorized) for r in done) >= 1
    assert len(world.sim.authorizations) == 1
    assert len({rid for method, path, rid in world.sim.calls if path.endswith("/authorize")}) == 1
    with world.engine.connect() as conn:
        assert len(conn.execute(select(reservations).where(reservations.c.role == "cp")).all()) == 1
        assert len(conn.execute(select(spend_entries)).all()) == 1


def test_twenty_parallel_checkouts_under_a_budget_that_fits_three_make_exactly_three(
    app_engine: Engine, clean_payments: None
) -> None:
    """The check-and-reserve transaction of the Credential Provider: lock, read the spend view,
    evaluate `payment.budget`, reserve. Single use of the open mandate would admit only one
    purchase end to end, so the budget race is exercised at this layer (docs/PROTOCOL.md Decision 36)."""
    ledger = SpendLedger()
    digest, currency, maximum, amount = "open-digest-1", "USD", 10_000, 3_000
    constraint = {"type": "payment.budget", "max": maximum, "currency": currency}

    def attempt(n: int) -> bool:
        with app_engine.begin() as conn:
            ledger.lock(conn, digest, currency)
            view = ledger.view(conn, digest, currency)
            facts = PaymentFacts({}, amount, currency, None, None, None, view, frozenset())  # type: ignore[arg-type]
            if not payment_constraints.budget(constraint, facts).satisfied:
                return False
            ledger.reserve(conn, spend_id=f"sp_{n}", digest=digest, checkout_id=f"chk_{n}",
                           amount_minor=amount, currency=currency)  # fmt: skip
            return True

    results = run_parallel(attempt, list(range(N)))
    assert sum(results) == maximum // amount == 3
    with app_engine.connect() as conn:
        assert ledger.view(conn, digest, currency) == SpendView(currency, 0, 9_000)


def test_without_the_row_lock_the_race_would_over_spend(
    app_engine: Engine, clean_payments: None
) -> None:
    """The negative control: the same transaction without `lock` lets parallel checks read the
    same headroom, so the test above is not vacuous."""
    ledger = SpendLedger()
    digest, currency, maximum, amount = "open-digest-2", "USD", 10_000, 3_000
    constraint = {"type": "payment.budget", "max": maximum, "currency": currency}
    with app_engine.begin() as conn:
        ledger.lock(conn, digest, currency)  # the row exists; the racers below do not lock it
    gate = threading.Barrier(N)

    def attempt(n: int) -> bool:
        with app_engine.begin() as conn:
            view = ledger.view(conn, digest, currency)
            facts = PaymentFacts({}, amount, currency, None, None, None, view, frozenset())  # type: ignore[arg-type]
            passed = bool(payment_constraints.budget(constraint, facts).satisfied)
            gate.wait()  # everyone has read the same headroom before anyone reserves
            if passed:
                ledger.reserve(conn, spend_id=f"sp_{n}", digest=digest, checkout_id=f"chk2_{n}",
                               amount_minor=amount, currency=currency)  # fmt: skip
            return passed

    with ThreadPoolExecutor(max_workers=N) as pool:
        results = list(pool.map(attempt, range(N)))
    assert sum(results) > 3
