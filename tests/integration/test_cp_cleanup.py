"""Pre-authorize check, fail-closed cleanup and crash recovery of the Credential Provider."""

from __future__ import annotations

from typing import Any

import pytest
from sqlalchemy import Engine, select

from countersign.ablations import AblationRefused, Ablations
from countersign.cp import CpApprovalRequired, CpAuthorized, CpRejected
from countersign.merchant.decision_log import DecisionLogError
from countersign.tables import payment_attempts, reservations, spend_entries
from tests.cp_support import CpWorld, Mandates, make_world
from tests.merchant_support import make_checkout
from tests.paypal_sim import server_error, timeout


class SimulatedCrash(BaseException):  # not an Exception: no handler may swallow it
    pass


@pytest.fixture
def world(app_engine: Engine, clean_payments: None) -> CpWorld:
    return make_world(app_engine)


def begin(world: CpWorld, m: Mandates | None = None) -> tuple[Mandates, Any]:
    m = m or world.mandates(maximum=100_000)
    result = world.provider.start(
        payment_token=m.payment_token, checkout_mandate=m.checkout_mandate, current=m.current
    )
    return m, result


def states(world: CpWorld, checkout_id: str | None = None) -> dict[str, Any]:
    with world.engine.connect() as conn:
        attempt = conn.execute(
            select(payment_attempts).where(
                payment_attempts.c.checkout_id == (checkout_id or world.checkout.id)
            )
        ).one()
        spend = conn.execute(
            select(spend_entries).where(spend_entries.c.checkout_id == attempt.checkout_id)
        ).one()
        reservation = conn.execute(
            select(reservations).where(reservations.c.handle == attempt.reservation_handle)
        ).one()
    return {"attempt": attempt.state, "spend": spend.state, "reservation": reservation.state}


def retry_works(world: CpWorld, m: Mandates) -> None:
    """After a release the same open mandate backs a new checkout."""
    other = make_checkout(checkout_id="chk_" + "r" * 22)
    again = world.mandates(
        checkout=other, nonce="retry-nonce", maximum=100_000,
        reuse_open_payment=m.payment.open_token, reuse_checkout_open=m.checkout.open_token,
    )  # fmt: skip
    result = world.provider.start(
        payment_token=again.payment_token, checkout_mandate=again.checkout_mandate, current=other
    )
    assert isinstance(result, CpApprovalRequired), result


# ----- pre-authorize check (Decision 11) -----


@pytest.mark.parametrize(
    "change", [{"amount": "100.00"}, {"item_name": "Something else"}, {"custom_id": "cs1.forged"}]
)
def test_an_order_changed_while_approved_is_refused_and_nothing_is_authorized(
    world: CpWorld, change: dict[str, str]
) -> None:
    m, started = begin(world)
    world.sim.approve(started.order_id)
    world.sim.patch(started.order_id, **change)
    result = world.provider.finish(checkout_id=world.checkout.id, current=world.checkout)
    assert isinstance(result, CpRejected)
    assert (result.step, result.reason) == ("C8", "preauthorize_order_terms_differ")
    assert world.sim.count("/authorize") == 0 and world.sim.authorizations == {}
    assert states(world) == {"attempt": "abandoned", "spend": "voided", "reservation": "released"}
    retry_works(world, m)


def test_the_unchanged_order_is_authorized(world: CpWorld) -> None:
    _, started = begin(world)
    world.sim.approve(started.order_id)
    assert isinstance(
        world.provider.finish(checkout_id=world.checkout.id, current=world.checkout), CpAuthorized
    )


@pytest.mark.parametrize(
    ("change", "authorized_amount"),
    [({"amount": "100.00"}, "100.00"), ({"item_name": "Something else"}, "85.00"),
     ({"custom_id": "cs1.forged"}, "85.00")],
)  # fmt: skip
def test_with_the_ablation_the_same_change_gets_through(
    app_engine: Engine, clean_payments: None, change: dict[str, str], authorized_amount: str
) -> None:
    """Baseline behaviour (documented): without the pre-authorize check PayPal authorizes the
    patched order. The capture gate (P2.5) is then the only defence."""
    world = make_world(app_engine, ablations=Ablations(no_preauth_check=True))
    _, started = begin(world)
    world.sim.approve(started.order_id)
    world.sim.patch(started.order_id, **change)
    result = world.provider.finish(checkout_id=world.checkout.id, current=world.checkout)
    assert isinstance(result, CpAuthorized)
    assert world.sim.count("/authorize") == 1
    assert world.sim.authorizations[result.authorization_id]["amount"]["value"] == authorized_amount


def test_the_ablation_is_refused_in_a_demo_environment() -> None:
    with pytest.raises(AblationRefused):
        Ablations.from_env({"APP_ENV": "demo", "ABL_NO_PREAUTH_CHECK": "1"})
    assert Ablations.from_env({"APP_ENV": "dev", "ABL_NO_PREAUTH_CHECK": "1"}).no_preauth_check
    assert not Ablations.from_env({"APP_ENV": "demo"}).any
    with pytest.raises(AblationRefused):
        Ablations.from_env({"ABL_NO_GATE": "yes"})


def test_an_order_that_never_gets_approved_is_abandoned_not_authorized(world: CpWorld) -> None:
    m, _ = begin(world)
    touched = world.provider.recover(older_than_us=0)
    assert touched == [world.checkout.id]
    assert world.sim.count("/authorize") == 0
    assert states(world) == {"attempt": "abandoned", "spend": "voided", "reservation": "released"}
    retry_works(world, m)


# ----- create-order failures -----


@pytest.mark.parametrize("hook", [server_error, timeout])
def test_create_order_failure_releases_everything(world: CpWorld, hook: Any) -> None:
    world.sim.inject("create", hook, times=3)  # the client's three attempts
    m, result = begin(world)
    assert isinstance(result, CpRejected) and result.step == "C7"
    assert result.reason.startswith("paypal_error:") and result.ucp_code == "payment_failed"
    assert "signature" not in result.messages[0]["content"].lower()
    assert world.sim.orders == {}
    assert states(world) == {"attempt": "abandoned", "spend": "voided", "reservation": "released"}
    assert len({rid for method, path, rid in world.sim.calls if path == "/v2/checkout/orders"}) == 1
    retry_works(world, m)


# ----- authorize failures and outcome unknown -----


def approved(world: CpWorld) -> Any:
    _, started = begin(world)
    world.sim.approve(started.order_id)
    return started


def test_authorize_that_keeps_failing_is_cleaned_up(world: CpWorld) -> None:
    started = approved(world)
    world.sim.inject("authorize", server_error, times=6)
    result = world.provider.finish(checkout_id=world.checkout.id, current=world.checkout)
    assert isinstance(result, CpRejected) and result.step == "C8"
    assert world.sim.authorizations == {}
    assert states(world) == {"attempt": "abandoned", "spend": "voided", "reservation": "released"}
    assert started.order_id in world.sim.orders


def test_a_lost_authorize_response_resolves_without_a_second_authorization(world: CpWorld) -> None:
    approved(world)
    world.sim.lose_response("authorize")
    result = world.provider.finish(checkout_id=world.checkout.id, current=world.checkout)
    assert isinstance(result, CpAuthorized)
    assert len(world.sim.authorizations) == 1
    ids = {rid for method, path, rid in world.sim.calls if path.endswith("/authorize")}
    assert len(ids) == 1  # every attempt carried the same Request-Id


def test_authorize_outcome_unknown_is_resolved_by_get_before_any_retry(world: CpWorld) -> None:
    approved(world)
    world.sim.lose_response("authorize", times=3, replayable=False)  # takes effect, then 500s
    result = world.provider.finish(checkout_id=world.checkout.id, current=world.checkout)
    # The first call took effect; the client's retries could not tell; the GET found it.
    assert isinstance(result, CpAuthorized) and len(world.sim.authorizations) == 1


def test_an_authorize_that_never_arrived_is_retried_once_with_the_same_request_id(
    world: CpWorld,
) -> None:
    approved(world)
    world.sim.inject("authorize", server_error, times=3)  # nothing took effect
    result = world.provider.finish(checkout_id=world.checkout.id, current=world.checkout)
    assert isinstance(result, CpAuthorized) and len(world.sim.authorizations) == 1
    ids = [rid for method, path, rid in world.sim.calls if path.endswith("/authorize")]
    assert len(ids) == 4 and len(set(ids)) == 1


# ----- failure after authorization: void and confirm by GET -----


def break_log(world: CpWorld, kind: str) -> None:
    original = world.provider._append

    def failing(conn: Any, k: str, checkout_id: str, payload: dict[str, Any]) -> None:
        if k == kind:
            raise RuntimeError("ledger unavailable")
        original(conn, k, checkout_id, payload)

    world.provider._append = failing  # type: ignore[method-assign]


def test_a_log_failure_after_authorization_voids_it_and_confirms_with_get(world: CpWorld) -> None:
    m, started = begin(world)
    world.sim.approve(started.order_id)
    break_log(world, "cp.authorized")
    with pytest.raises(DecisionLogError):
        world.provider.finish(checkout_id=world.checkout.id, current=world.checkout)
    (auth,) = world.sim.authorizations.values()
    assert auth["status"] == "VOIDED"
    assert states(world) == {"attempt": "voided", "spend": "voided", "reservation": "released"}
    paths = [(method, path) for method, path, _ in world.sim.calls]
    void_at = max(i for i, c in enumerate(paths) if c[1].endswith("/void"))
    assert ("GET", f"/v2/payments/authorizations/{auth['id']}") in paths[void_at + 1 :]
    retry_works(world, m)


def test_void_with_a_lost_response_is_confirmed_by_get(world: CpWorld) -> None:
    approved(world)
    break_log(world, "cp.authorized")
    world.sim.lose_response("void", times=3, replayable=False)
    with pytest.raises(DecisionLogError):
        world.provider.finish(checkout_id=world.checkout.id, current=world.checkout)
    (auth,) = world.sim.authorizations.values()
    assert auth["status"] == "VOIDED"  # the void took effect although every response was lost
    assert states(world)["attempt"] == "voided"


def test_a_void_that_cannot_be_confirmed_leaves_the_attempt_unresolved_and_reserved(
    world: CpWorld,
) -> None:
    m = world.mandates(maximum=100_000)
    _, started = begin(world, m)
    world.sim.approve(started.order_id)
    break_log(world, "cp.authorized")
    world.sim.inject("void", server_error, times=3)
    with pytest.raises(DecisionLogError):
        world.provider.finish(checkout_id=world.checkout.id, current=world.checkout)
    (auth,) = world.sim.authorizations.values()
    assert auth["status"] == "CREATED"  # PayPal still holds it
    assert states(world) == {
        "attempt": "unresolved",
        "spend": "in_flight",
        "reservation": "reserved",
    }
    # Nothing is released while money might be held: the mandate stays in flight.
    other = make_checkout(checkout_id="chk_" + "q" * 22)
    again = world.mandates(
        checkout=other, nonce="n-q", maximum=100_000,
        reuse_open_payment=m.payment.open_token, reuse_checkout_open=m.checkout.open_token,
    )  # fmt: skip
    blocked = world.provider.start(
        payment_token=again.payment_token, checkout_mandate=again.checkout_mandate, current=other
    )
    assert isinstance(blocked, CpRejected) and blocked.reason == "open_mandate_in_use"
    # Reconciliation with PayPal available again settles it.
    world.provider._append = type(world.provider)._append.__get__(world.provider)  # type: ignore[method-assign]
    assert world.provider.recover(older_than_us=0) == [world.checkout.id]
    assert auth["status"] == "VOIDED"
    assert states(world) == {"attempt": "voided", "spend": "voided", "reservation": "released"}


# ----- log failures -----


def test_a_log_failure_before_a_paypal_call_means_the_call_is_not_made(world: CpWorld) -> None:
    m = world.mandates(maximum=100_000)
    break_log(world, "cp.paypal.create_order.started")
    with pytest.raises(DecisionLogError):
        begin(world, m)
    assert world.sim.calls == []  # not even the token request
    assert states(world) == {"attempt": "abandoned", "spend": "voided", "reservation": "released"}


def test_a_log_failure_at_the_reservation_leaves_no_trace(world: CpWorld) -> None:
    m = world.mandates()
    break_log(world, "cp.reserved")
    with pytest.raises(DecisionLogError):
        begin(world, m)
    with world.engine.connect() as conn:
        assert conn.execute(select(reservations)).all() == []
        assert conn.execute(select(spend_entries)).all() == []
        assert conn.execute(select(payment_attempts)).all() == []
    assert world.sim.calls == []


# ----- a crash between the reservation and the PayPal call -----


def test_a_crash_after_reserving_is_recovered(world: CpWorld) -> None:
    m = world.mandates(maximum=100_000)

    def crash(*_: Any, **__: Any) -> None:
        raise SimulatedCrash

    world.client.create_order = crash  # type: ignore[method-assign]
    with pytest.raises(SimulatedCrash):
        begin(world, m)
    assert states(world) == {"attempt": "reserved", "spend": "in_flight", "reservation": "reserved"}
    # While it is held, the open mandate cannot back another presentation.
    assert world.provider.recover(older_than_us=10**15) == []  # too recent to touch
    assert world.provider.recover(older_than_us=0) == [world.checkout.id]
    assert states(world) == {"attempt": "abandoned", "spend": "voided", "reservation": "released"}
    del world.client.create_order  # restore the class method
    retry_works(world, m)


def test_a_cleanup_that_cannot_read_paypal_keeps_everything_reserved(world: CpWorld) -> None:
    """If PayPal cannot be read, an authorization might exist: nothing is released."""
    begin(world)
    world.sim.inject("get_order", server_error, times=3)
    world.provider.recover(older_than_us=0)
    assert states(world) == {
        "attempt": "unresolved",
        "spend": "in_flight",
        "reservation": "reserved",
    }


def test_an_unexpected_exception_after_reserving_cleans_up_and_rejects(world: CpWorld) -> None:
    m = world.mandates(maximum=100_000)

    def boom(*_: Any, **__: Any) -> None:
        raise RuntimeError("boom")

    world.client.create_order = boom  # type: ignore[method-assign]
    _, result = begin(world, m)
    assert isinstance(result, CpRejected) and result.reason == "internal_error"
    assert result.ucp_code == "payment_failed" and result.messages[0]["severity"] == "recoverable"
    assert states(world) == {"attempt": "abandoned", "spend": "voided", "reservation": "released"}
