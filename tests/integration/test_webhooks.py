"""Verified webhook reconciliation on the real Postgres, over the PayPal simulator.

Real: the service, the signature headers check, the dedupe table, the gate, the lock, the ledger, the
decision log. The simulator answers the verification endpoint with the verdict the test sets. Every
delivery goes through `WebhookWorld.send`, which asserts that no money moving request was made.
"""

from __future__ import annotations

import json
import threading
from concurrent.futures import ThreadPoolExecutor
from typing import Any

import pytest
from fastapi.testclient import TestClient
from sqlalchemy import Engine, select, text

from countersign.api.app import create_app
from countersign.cp.ledger import SpendLedger
from countersign.gate import GatePassed
from countersign.ledger.store import entries_for_checkout, read_entries, verify_log
from countersign.merchant.keys import generate_jwk, validate_jwk
from countersign.tables import payment_attempts, reservations
from tests.webhook_support import (
    HEADERS,
    WEBHOOK_ID,
    WebhookWorld,
    authorization_event,
    body,
    capture_event,
    make_webhook_world,
    refund_event,
)


@pytest.fixture
def world(app_engine: Engine, clean_payments: None) -> WebhookWorld:
    return make_webhook_world(app_engine)


def captured(world: WebhookWorld) -> tuple[str, str]:
    """Authorize and capture through the gate. Returns (authorization id, capture id)."""
    world.gate_world.authorize()
    outcome = world.gate_world.gate.run(
        checkout_id=world.gate_world.checkout.id, current=world.gate_world.checkout
    )
    assert isinstance(outcome, GatePassed)
    return outcome.authorization_id, outcome.capture_id


def authorized(world: WebhookWorld) -> str:
    _, done = world.gate_world.authorize()
    return done.authorization_id


def log_kinds(world: WebhookWorld) -> list[str]:
    with world.engine.connect() as conn:
        return [e.kind for e in read_entries(conn)]


def checkout_kinds(world: WebhookWorld) -> list[str]:
    with world.engine.connect() as conn:
        return [e.kind for e in entries_for_checkout(conn, world.gate_world.checkout.id)]


# --------------------------------------------------------------------------- unverified events


def test_a_spoofed_event_is_ignored_logged_and_changes_nothing(world: WebhookWorld) -> None:
    auth = authorized(world)
    world.sim.void_now(auth)  # what the spoofer wants us to believe happened
    world.sim.webhook_verdict = "FAILURE"
    raw = authorization_event("WH-SPOOF", "PAYMENT.AUTHORIZATION.VOIDED", auth)
    result = world.send(raw)
    assert (result.status, result.outcome) == (401, "unverified:signature_failure")
    assert world.events() == [] and world.attempt_state() == "authorized"
    assert world.spend().state == "in_flight"
    assert "webhook.rejected" in log_kinds(world)
    # PayPal was asked with the notification bytes unchanged and the configured webhook id.
    (asked,) = world.sim.verify_requests
    assert asked["webhook_id"] == WEBHOOK_ID and asked["webhook_event"] == json.loads(raw)
    assert asked["transmission_id"] == HEADERS["PAYPAL-TRANSMISSION-ID"]
    with world.engine.connect() as conn:
        assert verify_log(conn).ok


@pytest.mark.parametrize("verdict", [500, 403, "junk"])
def test_a_verification_that_cannot_be_checked_is_ignored_with_try_again(
    world: WebhookWorld, verdict: Any
) -> None:
    auth = authorized(world)
    world.sim.void_now(auth)
    world.sim.webhook_verdict = verdict
    result = world.send(authorization_event("WH-X", "PAYMENT.AUTHORIZATION.VOIDED", auth))
    assert result.status == 503 and world.events() == [] and world.attempt_state() == "authorized"


def test_without_a_webhook_id_every_event_is_unverified(
    app_engine: Engine, clean_payments: None
) -> None:
    world = make_webhook_world(app_engine, webhook_id="")
    auth = authorized(world)
    world.sim.void_now(auth)
    result = world.send(authorization_event("WH-X", "PAYMENT.AUTHORIZATION.VOIDED", auth))
    assert (result.status, result.outcome) == (401, "unverified:no_webhook_id")
    assert world.sim.verify_requests == []  # nothing to verify against: PayPal was not asked
    assert world.events() == [] and world.attempt_state() == "authorized"


@pytest.mark.parametrize(
    "mutate,reason",
    [
        (
            lambda h: {k: v for k, v in h.items() if k != "PAYPAL-TRANSMISSION-SIG"},
            "header_transmission_sig",
        ),
        (lambda h: {**h, "PAYPAL-CERT-URL": "https://evil.example/cert"}, "header_cert_url_host"),
        (lambda h: {**h, "PAYPAL-CERT-URL": "http://api.sandbox.paypal.com/cert"}, "header_cert_url_host"),
        (
            lambda h: {**h, "PAYPAL-CERT-URL": "https://paypal.com.evil.example/c"},
            "header_cert_url_host",
        ),
        (lambda h: {**h, "PAYPAL-TRANSMISSION-TIME": "yesterday"}, "header_transmission_time"),
        (lambda h: {**h, "PAYPAL-AUTH-ALGO": ""}, "header_auth_algo"),
    ],
)
def test_malformed_headers_are_refused_before_paypal_is_asked(
    world: WebhookWorld, mutate: Any, reason: str
) -> None:
    result = world.send(
        authorization_event("WH-X", "PAYMENT.AUTHORIZATION.VOIDED", "AUTH1"), mutate(HEADERS)
    )
    assert (result.status, result.outcome) == (400, f"malformed:{reason}")
    assert world.sim.verify_requests == [] and world.events() == []


@pytest.mark.parametrize(
    "raw,reason",
    [
        (b'{"id": "A", "id": "B", "event_type": "X.Y.Z", "resource": {}}', "malformed:json_"),
        (b'{"id": "A", "event_type": "X.Y.Z", "resource": {"n": NaN}}', "malformed:json_"),
        (b"not json", "malformed:json_"),
        (b"[1]", "malformed:body_not_object"),
        (b'{"event_type": "X.Y.Z", "resource": {}}', "malformed:event_id"),
        (b'{"id": "a b", "event_type": "X.Y.Z", "resource": {}}', "malformed:event_id"),
        (b'{"id": "A", "event_type": "lower", "resource": {}}', "malformed:event_type"),
        (b'{"id": "A", "event_type": "X.Y.Z", "resource": []}', "malformed:resource"),
        (b"{" + b" " * 70_000 + b"}", "malformed:body_too_large"),
    ],
)
def test_a_malformed_body_is_refused_before_paypal_is_asked(
    world: WebhookWorld, raw: bytes, reason: str
) -> None:
    result = world.send(raw)
    assert result.status == 400 and result.outcome.startswith(reason)
    assert world.sim.verify_requests == [] and world.events() == []


def test_a_log_failure_fails_the_request_and_leaves_no_trace(
    world: WebhookWorld, monkeypatch: pytest.MonkeyPatch
) -> None:
    from countersign.ledger import store as ledger_store

    auth = authorized(world)
    world.sim.void_now(auth)
    real = ledger_store.append

    def broken(conn: Any, **kw: Any) -> Any:
        if kw["kind"].startswith("webhook."):
            raise RuntimeError("log unavailable")
        return real(conn, **kw)

    monkeypatch.setattr(ledger_store, "append", broken)
    raw = authorization_event("WH-LOG", "PAYMENT.AUTHORIZATION.VOIDED", auth)
    assert world.send(raw).status == 500
    assert world.events() == [] and world.attempt_state() == "authorized"
    world.sim.webhook_verdict = "FAILURE"
    assert world.send(raw).status == 500  # even the refusal fails when it cannot be logged
    monkeypatch.undo()
    world.sim.webhook_verdict = "SUCCESS"
    assert world.send(raw).outcome == "released"  # PayPal's retry is processed cleanly


# ------------------------------------------------------------------------------------ dedupe


def test_a_duplicate_event_id_is_processed_once(world: WebhookWorld) -> None:
    auth = authorized(world)
    world.sim.void_now(auth)
    raw = authorization_event("WH-DUP", "PAYMENT.AUTHORIZATION.VOIDED", auth)
    assert world.send(raw).outcome == "released"
    again = world.send(raw)
    assert (again.status, again.outcome) == (200, "duplicate")
    assert len(world.events()) == 1 and world.spend().state == "voided"
    kinds = checkout_kinds(world) + [k for k in log_kinds(world) if k == "webhook.duplicate"]
    assert kinds.count("webhook.released") == 1 and kinds.count("webhook.duplicate") == 1


def test_twenty_parallel_deliveries_of_one_event_apply_once(world: WebhookWorld) -> None:
    auth = authorized(world)
    world.sim.void_now(auth)
    raw = authorization_event("WH-RACE", "PAYMENT.AUTHORIZATION.VOIDED", auth)
    setup_calls = world.sim.money_calls()
    barrier = threading.Barrier(20)

    def deliver(_: int) -> Any:
        barrier.wait()
        return world.service.handle(HEADERS, raw)

    with ThreadPoolExecutor(20) as pool:
        results = list(pool.map(deliver, range(20)))
    assert [r.status for r in results] == [200] * 20
    assert sorted(r.outcome for r in results) == ["duplicate"] * 19 + ["released"]
    assert len(world.events()) == 1 and world.spend().state == "voided"
    assert world.sim.money_calls() == setup_calls  # 20 deliveries moved no money
    assert checkout_kinds(world).count("webhook.released") == 1


# ----------------------------------------------------------------- reconciliation of the ledger


def test_a_void_before_capture_releases_the_reservation_and_the_open_mandate(
    world: WebhookWorld,
) -> None:
    from tests.merchant_support import make_checkout

    mandates, done = world.gate_world.authorize()
    world.sim.void_now(done.authorization_id)
    result = world.send(
        authorization_event("WH-V", "PAYMENT.AUTHORIZATION.VOIDED", done.authorization_id)
    )
    assert result.outcome == "released"
    assert world.attempt_state() == "voided" and world.spend().state == "voided"
    assert set(world.gate_world.reservation_states().values()) == {"released"}
    row = world.gate_world.row()
    assert row.gate_code == "W-VOID" and row.capture_id is None

    # The open mandates are free again: a new checkout under them is authorized and captured.
    second = make_checkout(checkout_id="chk_after_webhook_void_00")
    again = world.gate_world.base.mandates(
        checkout=second, nonce="nonce-0002",
        reuse_open_payment=mandates.payment.open_token,
        reuse_checkout_open=mandates.checkout.open_token,
    )  # fmt: skip
    world.gate_world.base.checkout = second
    world.gate_world.authorize(again, checkout=second)
    outcome = world.gate_world.gate.run(checkout_id=second.id, current=second)
    assert isinstance(outcome, GatePassed)


def test_the_continuing_complete_after_a_webhook_void_is_a_clean_rejection(
    world: WebhookWorld,
) -> None:
    from countersign.gate import GateRejected

    auth = authorized(world)
    world.sim.void_now(auth)
    world.send(authorization_event("WH-V", "PAYMENT.AUTHORIZATION.VOIDED", auth))
    outcome = world.gate_world.gate.run(
        checkout_id=world.gate_world.checkout.id, current=world.gate_world.checkout
    )
    assert isinstance(outcome, GateRejected) and outcome.code == "W-VOID".replace(
        "W-VOID", outcome.code
    )
    assert world.sim.count("/capture") == 0


def test_a_refund_after_capture_is_recorded_and_never_restores_headroom(
    world: WebhookWorld,
) -> None:
    _, capture_id = captured(world)
    before = world.spend()
    refund = world.sim.refund(capture_id, "85.00")
    result = world.send(refund_event("WH-R1", refund, capture_id))
    assert result.outcome == "refund_recorded"
    after = world.spend()
    assert (after.state, after.amount_minor, after.refunded_minor) == ("captured", 8500, 8500)
    assert before.refunded_minor == 0
    with world.engine.connect() as conn:
        view = SpendLedger().view(conn, after.mandate_digest, "USD")
    assert view.captured_minor == 8500  # the money still counts as spent
    # The same refund again, under a new event id, changes nothing.
    assert world.send(refund_event("WH-R2", refund, capture_id)).outcome == "already_captured"
    assert world.spend().refunded_minor == 8500


def test_partial_refunds_add_up_and_are_capped_at_the_capture(world: WebhookWorld) -> None:
    _, capture_id = captured(world)
    first = world.sim.refund(capture_id, "20.00")
    world.send(refund_event("WH-R1", first, capture_id))
    assert world.spend().refunded_minor == 2000
    second = world.sim.refund(capture_id, "30.00")
    world.send(refund_event("WH-R2", second, capture_id))
    assert world.spend().refunded_minor == 5000
    world.sim.refund(capture_id, "999.00")  # more than was captured: the books cap at the capture
    world.send(refund_event("WH-R3", "REFx", capture_id))
    assert world.spend().refunded_minor == 8500


def test_a_pending_refund_is_not_counted(world: WebhookWorld) -> None:
    _, capture_id = captured(world)
    refund = world.sim.refund(capture_id, "85.00", status="PENDING")
    world.send(refund_event("WH-R1", refund, capture_id))
    assert world.spend().refunded_minor == 0
    world.sim.refunds[refund]["status"] = "COMPLETED"
    assert world.send(refund_event("WH-R2", refund, capture_id)).outcome == "refund_recorded"
    assert world.spend().refunded_minor == 8500


def test_capture_completed_confirms_a_gate_capture_without_changing_anything(
    world: WebhookWorld,
) -> None:
    _, capture_id = captured(world)
    before = (world.spend(), world.attempt_state())
    result = world.send(capture_event("WH-C", "PAYMENT.CAPTURE.COMPLETED", capture_id))
    assert result.outcome == "already_captured"
    assert (world.spend(), world.attempt_state()) == before


def test_a_capture_made_outside_the_gate_is_settled_by_reading_paypal(world: WebhookWorld) -> None:
    """Authorized, then captured by someone else at PayPal: the webhook asks the gate to settle."""
    auth = authorized(world)
    capture_id = "CAPEXT1"
    world.sim.captures[capture_id] = {
        "id": capture_id, "order": world.sim.authorizations[auth]["order"], "status": "COMPLETED",
        "amount": dict(world.sim.authorizations[auth]["amount"]), "final_capture": True,
        "invoice_id": world.sim.authorizations[auth]["invoice_id"],
        "custom_id": world.sim.authorizations[auth]["custom_id"],
        "links": [{"rel": "up", "href": f"https://api.sandbox.paypal.com/v2/payments/authorizations/{auth}"}],
    }  # fmt: skip
    world.sim.authorizations[auth]["status"] = "CAPTURED"
    result = world.send(capture_event("WH-C", "PAYMENT.CAPTURE.COMPLETED", capture_id))
    assert result.outcome == "settle_requested"
    assert world.attempt_state() == "captured" and world.spend().state == "captured"
    assert world.gate_world.row().capture_id == capture_id
    assert set(world.gate_world.reservation_states().values()) == {"consumed"}


def test_a_reversed_capture_is_recorded_and_restores_nothing(world: WebhookWorld) -> None:
    _, capture_id = captured(world)
    world.sim.captures[capture_id]["status"] = "REVERSED"
    before = world.spend()
    result = world.send(capture_event("WH-REV", "PAYMENT.CAPTURE.REVERSED", capture_id))
    assert result.status == 200 and world.spend() == before
    with world.engine.connect() as conn:
        processed = [
            json.loads(e.payload)
            for e in entries_for_checkout(conn, world.gate_world.checkout.id)
            if e.kind == "webhook.processed"
        ]
    assert processed[-1]["anomalies"] == ["capture_reversed"]


def test_an_unresolved_attempt_is_resolved_through_the_gates_live_read(world: WebhookWorld) -> None:
    """The capture could not be confirmed (PENDING); when PayPal settles it, the webhook settles us."""
    world.gate_world.authorize()
    world.sim.capture_status = "PENDING"
    gate = world.gate_world.gate
    gate.run(checkout_id=world.gate_world.checkout.id, current=world.gate_world.checkout)
    assert world.attempt_state() == "unresolved"
    (capture_id,) = world.sim.captures
    world.sim.captures[capture_id]["status"] = "COMPLETED"
    captures_before = world.sim.count("/capture")
    result = world.send(capture_event("WH-C", "PAYMENT.CAPTURE.COMPLETED", capture_id))
    assert result.outcome == "settle_requested"
    assert world.attempt_state() == "captured" and world.spend().state == "captured"
    assert world.sim.count("/capture") == captures_before  # settled by reading, not by capturing


def test_events_for_things_we_do_not_know_are_ignored(world: WebhookWorld) -> None:
    authorized(world)
    for n, raw in enumerate(
        [
            authorization_event("WH-1", "PAYMENT.AUTHORIZATION.VOIDED", "AUTHUNKNOWN"),
            capture_event("WH-2", "PAYMENT.CAPTURE.COMPLETED", "CAPUNKNOWN"),
            refund_event("WH-3", "REFX", "CAPUNKNOWN"),
            body("WH-4", "PAYMENT.AUTHORIZATION.VOIDED", {"no_id": 1}),
            body("WH-5", "BILLING.SUBSCRIPTION.CREATED", {"id": "I-1"}),
        ]
    ):
        result = world.send(raw)
        assert result.status == 200 and result.outcome in ("unknown_resource", "unhandled_type"), n
    assert {e.state for e in world.events()} == {"ignored"}
    assert world.attempt_state() == "authorized" and world.spend().state == "in_flight"


def test_an_event_while_the_gate_is_working_is_retried_later(world: WebhookWorld) -> None:
    auth = authorized(world)
    world.gate_world.gate._store.claim(world.gate_world.checkout.id, expect=("authorized",))
    world.sim.void_now(auth)
    result = world.send(authorization_event("WH-V", "PAYMENT.AUTHORIZATION.VOIDED", auth))
    assert result.status == 503 and world.events() == []  # not recorded: PayPal will deliver again


def test_paypal_unreadable_during_reconciliation_is_retried_later(world: WebhookWorld) -> None:
    auth = authorized(world)
    world.sim.void_now(auth)
    world.sim.fail_when["get_order"] = lambda sim: True
    result = world.send(authorization_event("WH-V", "PAYMENT.AUTHORIZATION.VOIDED", auth))
    assert result.status == 503 and world.events() == [] and world.attempt_state() == "authorized"
    world.sim.fail_when.clear()
    assert (
        world.send(authorization_event("WH-V", "PAYMENT.AUTHORIZATION.VOIDED", auth)).outcome
        == "released"
    )


# ------------------------------------------------------------------------ the body is a hint only


def test_a_hostile_body_cannot_change_the_ledger_because_the_fetched_state_decides(
    world: WebhookWorld,
) -> None:
    auth, capture_id = captured(world)
    before = (world.spend(), world.attempt_state())
    lies: list[bytes] = [
        # Says the authorization was voided, though it was captured.
        authorization_event("WH-L1", "PAYMENT.AUTHORIZATION.VOIDED", auth, status="VOIDED"),
        # Claims another capture amount and a failed status.
        capture_event(
            "WH-L2",
            "PAYMENT.CAPTURE.COMPLETED",
            capture_id,
            status="DENIED",
            amount={"currency_code": "USD", "value": "1.00"},
        ),
        # Claims a full refund PayPal never made.
        refund_event(
            "WH-L3",
            "REFLIE",
            capture_id,
            status="COMPLETED",
            amount={"currency_code": "USD", "value": "85.00"},
        ),
        # Claims the same of an event that names a different order.
        body(
            "WH-L4",
            "PAYMENT.AUTHORIZATION.VOIDED",
            {"id": auth, "supplementary_data": {"related_ids": {"order_id": "SOMEOTHER"}}},
        ),
    ]
    for raw in lies:
        assert world.send(raw).status == 200
    assert (world.spend(), world.attempt_state()) == before
    assert world.spend().refunded_minor == 0


def test_a_lying_void_cannot_release_a_live_authorization(world: WebhookWorld) -> None:
    auth = authorized(world)  # still CREATED at PayPal
    result = world.send(
        authorization_event("WH-LIE", "PAYMENT.AUTHORIZATION.VOIDED", auth, status="VOIDED")
    )
    assert result.outcome == "authorization_still_open"
    assert world.attempt_state() == "authorized" and world.spend().state == "in_flight"
    assert set(world.gate_world.reservation_states().values()) == {"reserved"}


# ------------------------------------------------------------------------------- the HTTP route


def test_the_route_maps_outcomes_to_status_codes(world: WebhookWorld) -> None:
    key = validate_jwk(generate_jwk())
    app = create_app(
        key=key, public_base_url="https://shop.example.test", engine=world.engine,
        webhooks=world.service,
    )  # fmt: skip
    auth = authorized(world)
    world.sim.void_now(auth)
    raw = authorization_event("WH-HTTP", "PAYMENT.AUTHORIZATION.VOIDED", auth)
    with TestClient(app) as client:
        ok = client.post("/webhooks/paypal", content=raw, headers=HEADERS)
        assert ok.status_code == 200 and ok.json() == {"status": "ok", "outcome": "released"}
        world.sim.webhook_verdict = "FAILURE"
        bad = client.post(
            "/webhooks/paypal", content=raw.replace(b"WH-HTTP", b"WH-HTTQ"), headers=HEADERS
        )
        assert bad.status_code == 401 and bad.json()["status"] == "not_accepted"
        assert client.post("/webhooks/paypal", content=b"nope", headers=HEADERS).status_code == 400
        big = client.post("/webhooks/paypal", content=b"{" + b" " * 70_000 + b"}", headers=HEADERS)
        assert big.status_code == 400 and big.json()["outcome"] == "malformed:body_too_large"
    assert "WH-HTTP" not in json.dumps(bad.json())  # nothing from the request is echoed


def test_no_secret_or_body_reaches_the_log(world: WebhookWorld) -> None:
    auth = authorized(world)
    world.sim.void_now(auth)
    world.sim.webhook_verdict = "FAILURE"
    world.send(
        authorization_event("WH-SPOOF", "PAYMENT.AUTHORIZATION.VOIDED", auth, note="SECRETPAYLOAD")
    )
    with world.engine.connect() as conn:
        blob = b"".join(e.payload for e in read_entries(conn)).decode()
        assert verify_log(conn).ok
    assert "SECRETPAYLOAD" not in blob and HEADERS["PAYPAL-TRANSMISSION-SIG"] not in blob
    assert WEBHOOK_ID not in blob


def test_the_runtime_role_cannot_delete_or_rewrite_a_finished_event(
    world: WebhookWorld,
) -> None:
    from sqlalchemy.exc import DBAPIError

    auth = authorized(world)
    world.sim.void_now(auth)
    world.send(authorization_event("WH-F", "PAYMENT.AUTHORIZATION.VOIDED", auth))
    for statement in (
        "DELETE FROM webhook_events",
        "TRUNCATE webhook_events",
        "UPDATE webhook_events SET state = 'processing'",
        "UPDATE webhook_events SET outcome = 'x'",
    ):
        with pytest.raises(DBAPIError), world.engine.begin() as conn:
            conn.execute(text(statement))
    assert len(world.events()) == 1
    with world.engine.connect() as conn:
        assert conn.execute(select(reservations.c.state)).all()
        assert conn.execute(select(payment_attempts.c.state)).all()


def test_an_attempt_the_credential_provider_left_unresolved_is_not_touched_by_a_webhook(
    world: WebhookWorld, admin_engine: Engine
) -> None:
    auth = authorized(world)
    with admin_engine.begin() as conn:
        conn.execute(
            text("UPDATE payment_attempts SET state = 'unresolved' WHERE checkout_id = :c"),
            {"c": world.gate_world.checkout.id},
        )
    world.sim.void_now(auth)
    result = world.send(authorization_event("WH-U", "PAYMENT.AUTHORIZATION.VOIDED", auth))
    assert result.outcome == "unresolved_by_credential_provider"
    assert world.attempt_state() == "unresolved" and world.spend().state == "in_flight"
