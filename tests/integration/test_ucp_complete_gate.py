"""UCP complete through the capture gate over HTTP: Merchant, Credential Provider, then the gate.

Everything is real but PayPal (the simulator). The response reflects the PayPal state the gate
confirmed: a completed checkout carries its order and the signed Payment Receipt, a refused one is
canceled and nothing is captured.
"""

from __future__ import annotations

from collections.abc import Iterator
from typing import Any

import pytest
from fastapi.testclient import TestClient
from sqlalchemy import Engine, select

from countersign.ablations import Ablations
from countersign.api.app import create_app
from countersign.completion import CompleteCoordinator, GateLockAdapter
from countersign.constraints import CheckoutConstraintEvaluator, PaymentConstraintEvaluator
from countersign.cp import CpConfig, CredentialProvider
from countersign.gate import CaptureGate
from countersign.lock import PrincipalLock
from countersign.merchant import receipts
from countersign.merchant.authorization import verify_authorization
from countersign.merchant.decision_log import LedgerDecisionLog
from countersign.merchant.keys import generate_jwk, validate_jwk
from countersign.merchant.pg_reservations import PostgresReservationStore
from countersign.merchant.policy import policy_hash
from countersign.merchant.verify import CheckoutMandateVerifier, MerchantConfig
from countersign.paypal.client import PayPalClient
from countersign.paypal.config import PayPalConfig
from countersign.tables import payment_attempts, spend_entries
from tests import paypal_sim
from tests.constraint_fixtures import MERCHANT
from tests.integration.test_ucp_complete import (
    BASE,
    CHECKOUT_V,
    ROOT,
    Clock,
    Stack,
    codes,
    complete,
    complete_body,
    mandates,
    new_checkout,
)
from tests.mandate_issuer import NOW, Keys
from tests.paypal_sim import PayPalSim


def build(
    engine: Engine, *, gate_ablations: Ablations | None = None
) -> tuple[Iterator[TestClient], Stack, Any, PrincipalLock]:
    merchant_key = validate_jwk(generate_jwk())
    keys, sim = Keys(), PayPalSim()
    paypal = PayPalClient(
        PayPalConfig(client_id="sim", client_secret="sim-secret"),
        transport=sim.transport(),
        sleep=lambda _: None,
        now=lambda: paypal_sim.NOW,
    )
    clock = Clock()
    config = CpConfig(
        issuer="https://merchant.example",
        signing_key=merchant_key,
        platform_key=keys.issuer,
        payee={"id": MERCHANT["id"], "name": MERCHANT["name"]},
        paypal_payee_merchant_id=paypal_sim.MERCHANT,
        return_url=BASE + "/return",
        cancel_url=BASE + "/cancel",
        ablations=gate_ablations or Ablations(),
    )
    merchant = CheckoutMandateVerifier(
        MerchantConfig(
            issuer="https://merchant.example",
            signing_key=merchant_key,
            published_keys=[merchant_key.public_jwk],
            platform_key=keys.issuer,
        ),
        PostgresReservationStore(engine, "merchant"),
        LedgerDecisionLog(engine, policy_hash(), clock),
        lambda: float(NOW),
        CheckoutConstraintEvaluator(MERCHANT["id"]),
    )
    cp = CredentialProvider(
        config, engine, paypal, clock=lambda: float(NOW), evaluator=PaymentConstraintEvaluator()
    )
    lock = PrincipalLock(engine, platform_key=keys.issuer, clock=lambda: float(NOW))
    gate = CaptureGate(
        config, engine, paypal, GateLockAdapter(lock),
        clock=lambda: float(NOW), paypal_now=lambda: paypal_sim.NOW,
    )  # fmt: skip
    coordinator = CompleteCoordinator(
        merchant, PostgresReservationStore(engine, "merchant"), cp, gate, lock
    )
    app = create_app(
        key=merchant_key, public_base_url=BASE, engine=engine, clock_us=clock,
        completion=coordinator,
        lock=lock,
    )  # fmt: skip
    client = TestClient(app, raise_server_exceptions=False)
    return iter([client]), Stack(client, sim, keys, engine, cp), merchant_key, lock


@pytest.fixture
def gated(app_engine: Engine, clean_payments: None) -> Iterator[tuple[Stack, Any]]:
    _, stack, key, _lock = build(app_engine)
    with stack.client:
        yield stack, key


def approve_and_complete(stack: Stack, body: dict[str, Any]) -> Any:
    (order_id,) = stack.sim.orders
    stack.sim.approve(order_id)
    return complete(stack, body["id"], {})


def test_a_gated_complete_captures_completes_the_checkout_and_returns_the_order_and_receipt(
    gated: tuple[Stack, Any],
) -> None:
    stack, key = gated
    body = new_checkout(stack)
    cm, pm = mandates(stack, body)
    first = complete(stack, body["id"], complete_body(cm, pm))
    assert first.json()["status"] == "complete_in_progress"
    assert stack.sim.count("/capture") == 0

    done = approve_and_complete(stack, body)
    out = done.json()
    assert done.status_code == 200 and out["status"] == "completed"
    assert out["order"]["id"] == body["id"]
    assert out["order"]["permalink_url"] == f"{BASE}{ROOT}/{body['id']}"
    CHECKOUT_V.validate(out)
    verify_authorization(out, [key.public_jwk])  # the order is inside the merchant signature
    assert stack.sim.count("/capture") == 1 and stack.sim.count("/void") == 0

    # The Payment Receipt is signed, binds the closed Payment Mandate and names the PayPal capture.
    (capture_id,) = stack.sim.captures
    claims = receipts.verify_receipt(
        out["ap2"]["payment_receipt"], [key.public_jwk], receipts.PAYMENT_RECEIPT_TYP
    )
    assert claims["status"] == "Success" and claims["psp_confirmation_id"] == capture_id
    assert claims["reference"] == receipts.reference_for(pm) and claims["payment_id"] == body["id"]

    # The Checkout Receipt binds the closed Checkout Mandate and names the order.
    checkout_claims = receipts.verify_receipt(out["ap2"]["checkout_receipt"], [key.public_jwk])
    assert checkout_claims["status"] == "Success" and checkout_claims["order_id"] == body["id"]
    assert checkout_claims["reference"] == receipts.reference_for(cm)

    # A later read shows the completed checkout and its order; a repeat complete captures nothing.
    got = stack.client.get(
        f"{ROOT}/{body['id']}", headers={"UCP-Agent": 'profile="https://p.example/x"'}
    )
    assert got.json()["status"] == "completed" and got.json()["order"]["id"] == body["id"]
    again = complete(stack, body["id"], {})
    assert again.json()["status"] == "completed" and stack.sim.count("/capture") == 1


def test_a_gate_rejection_cancels_the_checkout_and_captures_nothing(
    app_engine: Engine, clean_payments: None
) -> None:
    _, stack, _, _lock = build(app_engine, gate_ablations=Ablations(no_preauth_check=True))
    with stack.client:
        body = new_checkout(stack)
        cm, pm = mandates(stack, body)
        complete(stack, body["id"], complete_body(cm, pm))
        (order_id,) = stack.sim.orders
        stack.sim.approve(order_id)
        stack.sim.patch(order_id, amount="1.00")  # raised/lowered after approval, before authorize
        response = complete(stack, body["id"], {})
        assert "payment_failed" in codes(response)
        assert "checkout_canceled_after_rejection" in codes(response)
        assert response.json()["status"] == "canceled" and "order" not in response.json()
        assert stack.sim.count("/capture") == 0 and stack.sim.count("/void") == 1
        (auth,) = stack.sim.authorizations.values()
        assert auth["status"] == "VOIDED"
        with stack.engine.connect() as conn:
            assert [r.state for r in conn.execute(select(spend_entries)).all()] == ["voided"]
            assert [r.state for r in conn.execute(select(payment_attempts)).all()] == ["voided"]


def test_an_unresolved_payment_leaves_the_checkout_open_and_is_settled_by_a_later_complete(
    gated: tuple[Stack, Any],
) -> None:
    stack, _ = gated
    body = new_checkout(stack)
    cm, pm = mandates(stack, body)
    complete(stack, body["id"], complete_body(cm, pm))
    (order_id,) = stack.sim.orders
    stack.sim.approve(order_id)
    stack.sim.capture_status = "PENDING"  # the capture cannot be confirmed COMPLETED
    held = complete(stack, body["id"], {})
    assert held.json()["status"] == "complete_in_progress"
    assert codes(held) == ["payment_failed"]
    assert stack.sim.count("/void") == 0  # money may have moved: nothing is voided
    stack.sim.capture_status = "COMPLETED"
    for capture in stack.sim.captures.values():
        capture["status"] = "COMPLETED"  # PayPal settles the capture
    settled = complete(stack, body["id"], {})
    assert settled.json()["status"] == "completed"
    assert stack.sim.count("/capture") == 1  # settled by reading, not by capturing again
