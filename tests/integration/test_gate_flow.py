"""The capture gate end to end against the PayPal simulator and the real Postgres.

Real: the mandates and both chain verifications, the constraint engine, the Postgres reservations
and spend ledger, the decision log and the gate. Only PayPal is the simulator, which models the
behaviour recorded in docs/PROTOCOL.md section 4.
"""

from __future__ import annotations

import json
from datetime import timedelta
from typing import Any

import httpx
import pytest
from sqlalchemy import Engine

from countersign.ablations import AblationRefused, Ablations
from countersign.gate import (
    CaptureGate,
    DenyAllLockPolicy,
    GatePassed,
    GateRejected,
    GateUnresolved,
    LockDecision,
    LockQuery,
    revoke_mandate,
)
from countersign.ledger.store import entries_for_checkout, verify_log
from countersign.merchant import receipts
from tests import paypal_sim
from tests.gate_support import GateWorld, make_gate_world


@pytest.fixture
def world(app_engine: Engine, clean_payments: None) -> GateWorld:
    return make_gate_world(app_engine)


def run(world: GateWorld, gate: CaptureGate | None = None) -> Any:
    return (gate or world.gate).run(checkout_id=world.checkout.id, current=world.checkout)


def kinds(world: GateWorld) -> list[str]:
    with world.engine.connect() as conn:
        return [e.kind for e in entries_for_checkout(conn, world.checkout.id)]


def steps_logged(world: GateWorld) -> list[tuple[str, str]]:
    with world.engine.connect() as conn:
        entries = [
            e for e in entries_for_checkout(conn, world.checkout.id) if e.kind == "gate.step"
        ]
    out = []
    for entry in entries:
        payload = json.loads(entry.payload)
        out.append((payload["code"], payload["outcome"]))
    return out


def claims(world: GateWorld, receipt: str) -> dict[str, Any]:
    return receipts.verify_receipt(
        receipt, [world.base.merchant_key.public_jwk], receipts.PAYMENT_RECEIPT_TYP
    )


def assert_voided_and_released(world: GateWorld, outcome: Any, code: str) -> None:
    assert isinstance(outcome, GateRejected), outcome
    assert outcome.code == code
    assert world.sim.count("/capture") == 0 and world.sim.count("/void") == 1
    (auth,) = world.sim.authorizations.values()
    assert auth["status"] == "VOIDED"
    row = world.row()
    assert row.state == "voided" and row.gate_code == code
    assert [e.state for e in world.spend()] == ["voided"]
    assert set(world.reservation_states().values()) == {"released"}
    claim = claims(world, outcome.receipt)
    assert claim["status"] == "Error" and claim["payment_id"] == world.checkout.id
    assert claim["error_description"] == outcome.reason


# ----------------------------------------------------------------------------- the clean path


def test_a_clean_flow_passes_every_step_and_captures_once(world: GateWorld) -> None:
    mandates, done = world.authorize()
    outcome = run(world)
    assert isinstance(outcome, GatePassed), outcome
    assert outcome.amount.minor == 8500 and outcome.authorization_id == done.authorization_id
    assert world.sim.count("/capture") == 1 and world.sim.count("/void") == 0

    # Every step is logged, in order, before the capture; the log chain verifies.
    assert steps_logged(world) == [
        ("G-FETCH", "pass"), ("G-STATUS", "pass"), ("G-REVERSE", "pass"), ("G-TERMS", "pass"),
        ("G-AMOUNT", "pass"), ("G-MANDATE", "pass"), ("G-BUDGET", "pass"), ("G-LOCK", "pass"),
    ]  # fmt: skip
    log = kinds(world)
    assert log.index("gate.step") < log.index("gate.paypal.capture.started")
    assert log.index("gate.paypal.capture.finished") < log.index("gate.captured")
    with world.engine.connect() as conn:
        assert verify_log(conn).ok

    # PayPal: the capture is the whole authorization with final_capture, confirmed by GET.
    (capture,) = world.sim.captures.values()
    assert capture["final_capture"] is True and capture["amount"]["value"] == "85.00"
    assert capture["status"] == "COMPLETED"
    paths = [p for m, p, _ in world.sim.calls if m == "GET"]
    after = paths[len(paths) - 2 :]
    assert after[0].startswith("/v2/payments/captures/") and after[1].startswith(
        "/v2/payments/authorizations/"
    )

    # Books: spend captured, both reservations consumed, attempt captured, receipt signed.
    row = world.row()
    assert row.state == "captured" and row.capture_id == outcome.capture_id
    assert [e.state for e in world.spend()] == ["captured"]
    assert set(world.reservation_states().values()) == {"consumed"}
    claim = claims(world, outcome.receipt)
    assert claim["status"] == "Success" and claim["psp_confirmation_id"] == outcome.capture_id
    assert claim["reference"] == receipts.reference_for(mandates.payment_token)

    # Request-Ids of the mutating calls are deterministic and within the limit (INV-11).
    ids = [rid for m, p, rid in world.sim.calls if m == "POST" and p.endswith("/capture")]
    assert (
        len(ids) == 1
        and ids[0] is not None
        and len(ids[0]) <= 108
        and ids[0].startswith("cs1.capture.")
    )


def test_a_second_run_returns_the_stored_result_without_calling_paypal(world: GateWorld) -> None:
    world.authorize()
    first = run(world)
    calls = len(world.sim.calls)
    again = run(world)
    assert isinstance(first, GatePassed) and again == first
    assert len(world.sim.calls) == calls and world.sim.count("/capture") == 1


def test_a_gate_with_no_lock_policy_denies_and_voids(world: GateWorld) -> None:
    world.authorize()
    outcome = run(world, world.new_gate(lock=DenyAllLockPolicy()))
    assert_voided_and_released(world, outcome, "G-LOCK")
    assert outcome.ucp_code == "mandate_required"


def test_a_run_before_authorization_does_nothing(world: GateWorld) -> None:
    outcome = run(world)
    assert type(outcome).__name__ == "GateNotApplicable"
    assert world.sim.calls == []


# ------------------------------------------------------------------- each step failing alone


class Scripted:
    """A lock policy that says what the test says (the real lock is built in the next step)."""

    def __init__(self, answer: Any) -> None:
        self.answer, self.seen = answer, []

    def check(self, query: LockQuery) -> LockDecision:
        self.seen.append(query)
        if isinstance(self.answer, Exception):
            raise self.answer
        return self.answer  # type: ignore[no-any-return]


def test_g_fetch_fails_when_paypal_cannot_be_read_then_the_void_is_confirmed(
    world: GateWorld,
) -> None:
    world.authorize()
    world.sim.inject("get_order", paypal_sim.server_error, times=3)  # the client's three attempts
    outcome = run(world)
    assert_voided_and_released(world, outcome, "G-FETCH")
    assert steps_logged(world)[-1] == ("G-FETCH", "fail")


def test_g_fetch_with_paypal_down_is_unresolved_and_keeps_the_money_reserved(
    world: GateWorld,
) -> None:
    world.authorize()
    world.sim.fail_when["get_order"] = lambda sim: True
    outcome = run(world)
    assert isinstance(outcome, GateUnresolved) and outcome.code == "G-FETCH"
    assert world.sim.count("/void") == 0 and world.sim.count("/capture") == 0
    row = world.row()
    assert row.state == "unresolved" and row.gate_code == "G-FETCH"
    assert [e.state for e in world.spend()] == ["in_flight"]
    assert set(world.reservation_states().values()) == {"reserved"}


def test_g_status_fails_for_an_expired_authorization(world: GateWorld) -> None:
    world.authorize()
    late = world.new_gate(paypal_now=lambda: paypal_sim.NOW + timedelta(days=40))
    outcome = run(world, late)
    assert outcome.reason == "authorization_expired"
    assert_voided_and_released(world, outcome, "G-STATUS")


def test_g_status_fails_when_the_order_holds_a_second_authorization(world: GateWorld) -> None:
    world.authorize()
    world.sim._make_authorization(_order_of(world))  # a second authorization appears at PayPal
    outcome = run(world)
    assert outcome.reason == "authorization_not_on_order"
    assert isinstance(outcome, GateRejected) and outcome.code == "G-STATUS"
    # Every authorization PayPal reports for the order is voided, not only the attempt's own.
    assert {a["status"] for a in world.sim.authorizations.values()} == {"VOIDED"}
    assert world.sim.count("/void") == 2 and world.sim.count("/capture") == 0


def test_g_reverse_fails_when_the_live_order_cannot_be_read_as_terms(world: GateWorld) -> None:
    world.authorize()
    del world.sim.orders[_order_of(world)]["unit"]["custom_id"]
    outcome = run(world)
    assert outcome.reason == "order_terms_unreadable"
    assert_voided_and_released(world, outcome, "G-REVERSE")


def _order_of(world: GateWorld) -> str:
    return str(world.row().order_id)


@pytest.mark.parametrize(
    "change,reason",
    [
        ({"item_name": "Something else"}, "order_terms_differ"),
        ({"custom_id": "cs1.tampered"}, "custom_id_differs"),
        ({"invoice_id": "chk_another_checkout_0000"}, "invoice_id_differs"),
    ],
)
def test_g_terms_fails_when_the_live_order_differs(
    world: GateWorld, change: dict[str, str], reason: str
) -> None:
    world.authorize()
    world.sim.patch(_order_of(world), **change)  # the simulator allows what PayPal refuses
    outcome = run(world)
    assert outcome.reason == reason
    assert_voided_and_released(world, outcome, "G-TERMS")


def test_g_amount_fails_when_the_authorized_amount_differs(
    app_engine: Engine, clean_payments: None
) -> None:
    world = make_gate_world(app_engine, cp_ablations=Ablations(no_preauth_check=True))
    world.sim.auth_amount_override = "95.00"
    world.authorize()
    outcome = run(world)
    assert outcome.reason == "authorization_amount_differs"
    assert_voided_and_released(world, outcome, "G-AMOUNT")
    assert steps_logged(world)[-2:] == [("G-TERMS", "pass"), ("G-AMOUNT", "fail")]


def test_g_mandate_fails_when_the_open_payment_mandate_is_revoked(world: GateWorld) -> None:
    mandates, _ = world.authorize()
    revoke_mandate(world.engine, _open_digest(mandates), lambda: 1)
    outcome = run(world)
    assert outcome.reason == "mandate_revoked"
    assert_voided_and_released(world, outcome, "G-MANDATE")


def _open_digest(mandates: Any) -> str:
    from countersign.canonical import sd_hash

    return sd_hash(mandates.payment.open_token)


def test_g_mandate_fails_when_the_checkout_open_mandate_is_revoked(world: GateWorld) -> None:
    from countersign.canonical import sd_hash

    mandates, _ = world.authorize()
    revoke_mandate(world.engine, sd_hash(mandates.checkout.open_token), lambda: 1)
    outcome = run(world)
    assert outcome.reason == "mandate_revoked"
    assert_voided_and_released(world, outcome, "G-MANDATE")


def test_g_mandate_fails_when_the_mandates_expired_after_authorization(world: GateWorld) -> None:
    world.authorize()
    world.tick.now += 100_000  # the open mandates expire one hour after issue
    outcome = run(world)
    assert "expired" in outcome.reason and outcome.ucp_code == "mandate_expired"
    assert_voided_and_released(world, outcome, "G-MANDATE")


def test_g_mandate_fails_when_the_merchant_reservation_is_no_longer_held(world: GateWorld) -> None:
    from countersign.merchant.pg_reservations import PostgresReservationStore

    world.authorize()
    assert PostgresReservationStore(world.engine, "merchant").release_checkout(world.checkout.id)
    outcome = run(world)
    assert outcome.reason == "reservation_not_held:merchant"
    assert isinstance(outcome, GateRejected) and outcome.code == "G-MANDATE"
    assert world.sim.count("/capture") == 0 and world.sim.count("/void") == 1


def test_g_budget_fails_when_the_ledger_no_longer_has_the_headroom(world: GateWorld) -> None:
    mandates, _ = world.authorize()
    digest = _open_digest(mandates)
    with world.engine.begin() as conn:  # money spent under the same mandate elsewhere
        ledger = world.base.ledger
        ledger.reserve(conn, spend_id="sp_other", digest=digest, checkout_id="chk_other",
                       amount_minor=5_000, currency="USD")  # fmt: skip
        ledger.capture(conn, "sp_other")
    outcome = run(world)
    assert outcome.reason == "constraint_violated"
    assert isinstance(outcome, GateRejected) and outcome.code == "G-BUDGET"
    assert world.sim.count("/capture") == 0 and world.sim.count("/void") == 1
    # The other purchase's captured money still counts; ours is released.
    assert sorted(e.state for e in world.spend()) == ["captured", "voided"]


def test_g_budget_does_not_count_the_checkouts_own_reservation_twice(world: GateWorld) -> None:
    # 8500 in flight against a 10000 budget: counting it twice (17000) would fail this gate.
    world.authorize()
    assert isinstance(run(world), GatePassed)


@pytest.mark.parametrize(
    "answer,reason",
    [
        (LockDecision(False, "agent_locked"), "lock_denied:agent_locked"),
        (RuntimeError("policy exploded"), "lock_policy_error"),
        ("yes", "lock_policy_bad"),
        (None, "lock_policy_bad"),
    ],
)
def test_g_lock_denies_on_a_no_an_error_or_a_malformed_answer(
    world: GateWorld, answer: Any, reason: str
) -> None:
    world.authorize()
    policy = Scripted(answer)
    outcome = run(world, world.new_gate(lock=policy))
    assert outcome.reason == reason
    assert_voided_and_released(world, outcome, "G-LOCK")
    assert policy.seen[0].checkout_id == world.checkout.id and policy.seen[0].principal


# --------------------------------------------------------------------- the fail path in detail


def test_a_void_that_cannot_be_confirmed_leaves_the_attempt_unresolved(world: GateWorld) -> None:
    world.authorize()
    # Once anything is voided, reading an authorization fails: the void cannot be confirmed.
    world.sim.fail_when["get_authorization"] = lambda sim: any(
        a["status"] == "VOIDED" for a in sim.authorizations.values()
    )
    outcome = run(world, world.new_gate(lock=DenyAllLockPolicy()))
    assert isinstance(outcome, GateUnresolved) and outcome.code == "G-LOCK"
    assert world.sim.count("/void") == 1 and world.sim.count("/capture") == 0
    row = world.row()
    assert row.state == "unresolved"
    assert [e.state for e in world.spend()] == ["in_flight"]
    assert set(world.reservation_states().values()) == {"reserved"}

    # When PayPal can be read again a retry settles it by reading, and releases.
    world.sim.fail_when.clear()
    settled = run(world, world.new_gate(lock=DenyAllLockPolicy()))
    assert isinstance(settled, GateRejected) and world.sim.count("/void") == 1
    assert [e.state for e in world.spend()] == ["voided"]


def test_a_log_failure_in_a_step_takes_the_fail_path(
    world: GateWorld, monkeypatch: pytest.MonkeyPatch
) -> None:
    world.authorize()
    from countersign.ledger import store as ledger_store

    real = ledger_store.append

    def broken(conn: Any, **kw: Any) -> Any:
        if kw["kind"] == "gate.step" and kw["payload"]["code"] == "G-AMOUNT":
            raise RuntimeError("log unavailable")
        return real(conn, **kw)

    monkeypatch.setattr(ledger_store, "append", broken)
    outcome = run(world)
    assert isinstance(outcome, GateRejected) and outcome.code == "G-AMOUNT"
    assert outcome.reason == "log_failure"
    assert world.sim.count("/capture") == 0 and world.sim.count("/void") == 1


def test_a_log_failure_when_voiding_cannot_void_and_is_unresolved(
    world: GateWorld, monkeypatch: pytest.MonkeyPatch
) -> None:
    world.authorize()
    from countersign.ledger import store as ledger_store

    real = ledger_store.append

    def broken(conn: Any, **kw: Any) -> Any:
        if kw["kind"].startswith("gate.") and kw["kind"] != "gate.unresolved":
            raise RuntimeError("log unavailable")
        return real(conn, **kw)

    monkeypatch.setattr(ledger_store, "append", broken)
    outcome = run(world)
    assert isinstance(outcome, GateUnresolved)
    # A PayPal call whose started entry cannot be written is not made (INV-12).
    assert world.sim.count("/capture") == 0 and world.sim.count("/void") == 0
    assert set(world.reservation_states().values()) == {"reserved"}


def test_a_definite_capture_refusal_voids(world: GateWorld) -> None:
    world.authorize()
    world.sim.inject(
        "capture",
        lambda request: httpx.Response(
            422,
            json={"name": "UNPROCESSABLE_ENTITY", "details": [{"issue": "AUTHORIZATION_VOIDED"}]},
        ),
    )
    outcome = run(world)
    assert outcome.reason == "capture_failed:AuthorizationVoided"
    assert isinstance(outcome, GateRejected) and outcome.code == "G-CAPTURE"
    assert world.sim.captures == {}
    assert [a["status"] for a in world.sim.authorizations.values()] == ["VOIDED"]


def test_a_capture_that_is_not_completed_is_unresolved_never_success_and_never_voided(
    world: GateWorld,
) -> None:
    world.authorize()
    world.sim.capture_status = "PENDING"
    outcome = run(world)
    assert isinstance(outcome, GateUnresolved) and outcome.code == "G-CAPTURE"
    assert world.sim.count("/capture") == 1 and world.sim.count("/void") == 0
    row = world.row()
    assert row.state == "unresolved" and row.capture_id is None
    assert [e.state for e in world.spend()] == ["in_flight"]  # the money may have moved: reserved


def test_a_capture_response_that_is_lost_is_confirmed_by_reading_paypal(world: GateWorld) -> None:
    world.authorize()
    world.sim.lose_response("capture", times=3, replayable=False)
    outcome = run(world)
    assert isinstance(outcome, GatePassed)
    assert world.sim.count("/capture") >= 1 and len(world.sim.captures) == 1
    assert world.sim.count("/void") == 0


# -------------------------------------------------------------- an order changed after approval


@pytest.mark.parametrize(
    "change",
    [{"amount": "140.00"}, {"item_name": "Cheaper item"}, {"custom_id": "cs1.other"}],
    ids=["amount", "items", "custom_id"],
)
def test_an_order_changed_before_authorization_is_voided_and_nothing_is_captured(
    app_engine: Engine, clean_payments: None, change: dict[str, str]
) -> None:
    world = make_gate_world(app_engine, cp_ablations=Ablations(no_preauth_check=True))
    world.authorize(between=lambda order_id: world.sim.patch(order_id, **change))
    outcome = run(world)
    assert isinstance(outcome, GateRejected) and outcome.code in ("G-TERMS", "G-AMOUNT")
    assert world.sim.count("/capture") == 0 and world.sim.captures == {}
    assert [a["status"] for a in world.sim.authorizations.values()] == ["VOIDED"]


def test_the_same_changed_order_is_captured_at_the_raised_amount_without_the_gate(
    app_engine: Engine, clean_payments: None
) -> None:
    """Documents the baseline: with ABL_NO_GATE the raised amount is captured."""
    world = make_gate_world(
        app_engine,
        cp_ablations=Ablations(no_preauth_check=True),
        gate_ablations=Ablations(no_gate=True),
    )
    world.authorize(between=lambda order_id: world.sim.patch(order_id, amount="140.00"))
    outcome = run(world)
    assert isinstance(outcome, GatePassed) and outcome.amount.minor == 14_000
    (capture,) = world.sim.captures.values()
    assert capture["amount"]["value"] == "140.00"
    assert steps_logged(world) == []  # no check ran


def test_no_gate_is_refused_when_the_app_env_is_demo() -> None:
    with pytest.raises(AblationRefused):
        Ablations.from_env({"ABL_NO_GATE": "1", "APP_ENV": "demo"})
    assert Ablations.from_env({"ABL_NO_GATE": "1", "APP_ENV": "dev"}).no_gate is True
    assert Ablations.from_env({"APP_ENV": "demo"}).no_gate is False


# ----------------------------------------------- release, retry with a new checkout, refunds


def test_a_void_frees_the_open_mandate_and_the_budget_for_a_new_checkout(
    world: GateWorld,
) -> None:
    from tests.merchant_support import make_checkout

    first, _ = world.authorize()
    world.sim.patch(_order_of(world), item_name="Changed")
    rejected = run(world)
    assert isinstance(rejected, GateRejected)

    # The first checkout's id, hash and nonce stay consumed; the open mandates are free again.
    second_checkout = make_checkout(checkout_id="chk_second_checkout_00000")
    again = world.base.mandates(
        checkout=second_checkout, nonce="nonce-0002",
        reuse_open_payment=first.payment.open_token, reuse_checkout_open=first.checkout.open_token,
    )  # fmt: skip
    world.base.checkout = second_checkout
    world.authorize(again, checkout=second_checkout)
    outcome = world.gate.run(checkout_id=second_checkout.id, current=second_checkout)
    assert isinstance(outcome, GatePassed), outcome
    assert world.sim.count("/capture") == 1
    assert sorted(e.state for e in world.spend()) == ["captured", "voided"]


def test_a_mandate_revoked_between_authorize_and_capture_voids_and_releases_the_open_mandate(
    world: GateWorld,
) -> None:
    from countersign.merchant.pg_reservations import PostgresReservationStore

    mandates, _ = world.authorize()
    revoke_mandate(world.engine, _open_digest(mandates), lambda: 1)
    outcome = run(world)
    assert_voided_and_released(world, outcome, "G-MANDATE")
    # The open mandate is no longer reserved or consumed (so a new checkout may be tried) ...
    states = {
        role: PostgresReservationStore(world.engine, role).release_checkout(world.checkout.id)
        for role in ("merchant", "cp")
    }
    assert states == {"merchant": False, "cp": False}  # nothing left in flight to release
    # ... but the revocation is recorded, so the gate refuses the retry as well.
    assert world.sim.count("/capture") == 0


def test_a_refund_after_capture_never_restores_headroom(world: GateWorld) -> None:
    mandates, _ = world.authorize()
    assert isinstance(run(world), GatePassed)
    digest = _open_digest(mandates)
    row = world.row()
    with world.engine.begin() as conn:
        before = world.base.ledger.view(conn, digest, "USD")
        world.base.ledger.refund(conn, row.spend_id, 8500)
        after = world.base.ledger.view(conn, digest, "USD")
    assert before == after and after.captured_minor == 8500


# ------------------------------------------------------------------ live state and the approval


def test_the_gate_reads_live_state_on_every_run_and_not_a_cache(world: GateWorld) -> None:
    world.authorize()
    reads = lambda: (
        sum(
            1 for m, p, _ in world.sim.calls if m == "GET" and p.startswith("/v2/checkout/orders/")
        ),
        sum(1 for m, p, _ in world.sim.calls if m == "GET" and "/authorizations/" in p),
    )
    before = reads()
    # The Credential Provider's last read of the order was clean. Change the live order now: a gate
    # that compared a remembered order would still pass.
    world.sim.patch(_order_of(world), item_name="Changed after the last read")
    outcome = run(world)
    after = reads()
    assert isinstance(outcome, GateRejected) and outcome.code == "G-TERMS"
    assert after[0] > before[0] and after[1] > before[1]
    # G-FETCH read both resources before any other step wrote its result.
    assert steps_logged(world)[0] == ("G-FETCH", "pass")


def test_capture_cannot_be_called_without_a_gate_approval(world: GateWorld) -> None:
    world.authorize()
    client = world.base.client
    for bogus in (None, "approve", {"checkout_id": world.checkout.id}, object()):
        with pytest.raises(TypeError):
            client.capture_authorization(bogus)  # type: ignore[arg-type]
    assert world.sim.count("/capture") == 0


def test_a_void_that_does_nothing_is_not_confirmed(world: GateWorld) -> None:
    """PayPal answers the void with success but the authorization is still `CREATED`."""
    world.authorize()
    world.sim.inject("void", lambda request: httpx.Response(204))
    outcome = run(world, world.new_gate(lock=DenyAllLockPolicy()))
    assert isinstance(outcome, GateUnresolved) and outcome.code == "G-LOCK"
    assert world.row().state == "unresolved"
    assert [e.state for e in world.spend()] == ["in_flight"]
    assert set(world.reservation_states().values()) == {"reserved"}


def test_a_completed_capture_for_another_amount_is_not_success(world: GateWorld) -> None:
    world.authorize()
    world.sim.capture_amount_override = "84.99"
    outcome = run(world)
    assert isinstance(outcome, GateUnresolved) and outcome.code == "G-CAPTURE"
    assert world.sim.count("/void") == 0
    assert [e.state for e in world.spend()] == ["in_flight"]


def test_a_capture_after_which_the_authorization_is_not_captured_is_not_success(
    world: GateWorld,
) -> None:
    world.authorize()
    world.sim.auth_status_after_capture = "PARTIALLY_CAPTURED"
    outcome = run(world)
    assert isinstance(outcome, GateUnresolved) and outcome.code == "G-CAPTURE"
    assert world.sim.count("/void") == 0 and world.row().state == "unresolved"


def test_g_mandate_fails_when_the_cp_reservation_holds_another_nonce(
    world: GateWorld, admin_engine: Engine
) -> None:
    """Defense in depth: the triggers stop the application role changing a nonce, an administrator can."""
    from sqlalchemy import text

    world.authorize()
    with admin_engine.begin() as conn:
        conn.execute(text("ALTER TABLE reservations DISABLE TRIGGER reservations_guard"))
        try:
            conn.execute(
                text(
                    "UPDATE reservations SET nonce_value = 'another-nonce' "
                    "WHERE role = 'cp' AND checkout_id = :c"
                ),
                {"c": world.checkout.id},
            )
        finally:
            conn.execute(text("ALTER TABLE reservations ENABLE TRIGGER reservations_guard"))
    outcome = run(world)
    assert outcome.reason == "nonce_not_reserved_by_checkout"
    assert isinstance(outcome, GateRejected) and outcome.code == "G-MANDATE"
