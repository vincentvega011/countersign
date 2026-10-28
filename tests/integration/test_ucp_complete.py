"""UCP complete runs Merchant verification, then the Credential Provider, over HTTP.

Everything is real except PayPal (the simulator): the mandates, the chain verification, the
constraint engine, the Postgres reservations and spend ledger, the decision log and the signed
responses. The service runs as the restricted application role.
"""

from __future__ import annotations

from collections.abc import Iterator
from dataclasses import dataclass
from typing import Any

import pytest
from fastapi.testclient import TestClient
from sqlalchemy import Engine, select

from countersign.api.app import create_app
from countersign.catalog.catalog import load_catalog
from countersign.completion import CompleteCoordinator
from countersign.constraints import CheckoutConstraintEvaluator, PaymentConstraintEvaluator
from countersign.cp import CpConfig, CredentialProvider
from countersign.merchant.authorization import checkout_jwt
from countersign.merchant.decision_log import LedgerDecisionLog
from countersign.merchant.keys import generate_jwk, validate_jwk
from countersign.merchant.pg_reservations import PostgresReservationStore
from countersign.merchant.policy import policy_hash
from countersign.merchant.verify import CheckoutMandateVerifier, MerchantConfig
from countersign.paypal.client import PayPalClient
from countersign.paypal.config import PayPalConfig
from countersign.protocols.ucp.profile import PAYMENT_HANDLER_ID, REST_BASE_PATH
from countersign.tables import payment_attempts, reservations
from tests import paypal_sim
from tests.constraint_fixtures import (
    MERCHANT,
    checkout_constraints,
    closed_payment_values,
    line_items_constraint,
    payment_constraints,
)
from tests.mandate_issuer import NOW, Keys, issue
from tests.paypal_sim import PayPalSim
from tests.ucp_schemas import CHECKOUT, validator

BASE = "https://shop.example.test"
AGENT = {"UCP-Agent": 'profile="https://platform.example/profile"'}
ROOT = REST_BASE_PATH + "/checkout-sessions"
ITEM = load_catalog().items[0]
CHECKOUT_V = validator(CHECKOUT)


@dataclass
class Stack:
    client: TestClient
    sim: PayPalSim
    keys: Keys
    engine: Engine
    cp: CredentialProvider


class Clock:
    def __init__(self) -> None:
        self.now = 1_800_000_000_000_000

    def __call__(self) -> int:
        self.now += 1
        return self.now


@pytest.fixture
def stack(app_engine: Engine, clean_payments: None) -> Iterator[Stack]:
    merchant_key = validate_jwk(generate_jwk())
    keys, sim = Keys(), PayPalSim()
    paypal = PayPalClient(
        PayPalConfig(client_id="sim", client_secret="sim-secret"),
        transport=sim.transport(),
        sleep=lambda _: None,
    )
    clock = Clock()
    merchant = CheckoutMandateVerifier(
        MerchantConfig(
            issuer="https://merchant.example",
            signing_key=merchant_key,
            published_keys=[merchant_key.public_jwk],
            platform_key=keys.issuer,
        ),
        PostgresReservationStore(app_engine, "merchant"),
        LedgerDecisionLog(app_engine, policy_hash(), clock),
        lambda: float(NOW),
        CheckoutConstraintEvaluator(MERCHANT["id"]),
    )
    cp = CredentialProvider(
        CpConfig(
            issuer="https://merchant.example",
            signing_key=merchant_key,
            platform_key=keys.issuer,
            payee={"id": MERCHANT["id"], "name": MERCHANT["name"]},
            paypal_payee_merchant_id=paypal_sim.MERCHANT,
            return_url=BASE + "/return",
            cancel_url=BASE + "/cancel",
        ),
        app_engine,
        paypal,
        clock=lambda: float(NOW),
        evaluator=PaymentConstraintEvaluator(),
    )
    coordinator = CompleteCoordinator(
        merchant, PostgresReservationStore(app_engine, "merchant"), cp
    )
    app = create_app(
        key=merchant_key, public_base_url=BASE, engine=app_engine, clock_us=clock,
        completion=coordinator,
    )  # fmt: skip
    with TestClient(app, raise_server_exceptions=False) as client:
        yield Stack(client, sim, keys, app_engine, cp)


def new_checkout(stack: Stack) -> dict[str, Any]:
    response = stack.client.post(
        ROOT, json={"line_items": [{"item": {"id": ITEM.id}, "quantity": 1}]}, headers=AGENT
    )
    assert response.status_code == 201
    body: dict[str, Any] = response.json()
    return body


def mandates(stack: Stack, body: dict[str, Any], **kw: Any) -> tuple[str, str]:
    jwt = checkout_jwt(body)
    total = next(t for t in body["totals"] if t["type"] == "total")["amount"]

    def edit_open(content: dict[str, Any]) -> None:
        content["constraints"] = [
            line_items_constraint(ITEM.id, 1, ITEM.title),
            checkout_constraints()[1],
        ]

    cm = issue("checkout", keys=stack.keys, checkout_jwt_value=jwt, nonce="nc-1",
               edit_open_content=edit_open)  # fmt: skip
    from countersign.canonical import sd_hash

    digest = sd_hash(cm.open_token)

    def edit_payment(content: dict[str, Any]) -> None:
        content["constraints"] = payment_constraints(digest, 1_000_000)

    def edit_closed(content: dict[str, Any]) -> None:
        content.update(closed_payment_values(kw.get("amount", total), body["currency"]))

    pm = issue("payment", keys=stack.keys, audience="credential-provider", checkout_jwt_value=jwt,
               nonce="np-1", edit_open_content=edit_payment, edit_kb_content=edit_closed)  # fmt: skip
    return cm.token, pm.token


def complete_body(checkout_mandate: str | None, token: str | None) -> dict[str, Any]:
    body: dict[str, Any] = {}
    if checkout_mandate is not None:
        body["ap2"] = {"checkout_mandate": checkout_mandate}
    if token is not None:
        body["payment"] = {
            "instruments": [
                {
                    "id": "instr_1",
                    "handler_id": PAYMENT_HANDLER_ID,
                    "type": "ap2",
                    "credential": {"type": "ap2_payment_mandate", "token": token},
                }
            ]
        }
    return body


def complete(stack: Stack, checkout_id: str, body: dict[str, Any]) -> Any:
    return stack.client.post(f"{ROOT}/{checkout_id}/complete", json=body, headers=AGENT)


def codes(response: Any) -> list[str]:
    return [m["code"] for m in response.json().get("messages", [])]


def test_complete_verifies_both_mandates_and_authorizes_after_payer_approval(stack: Stack) -> None:
    body = new_checkout(stack)
    cm, pm = mandates(stack, body)
    first = complete(stack, body["id"], complete_body(cm, pm))
    assert first.status_code == 200
    out = first.json()
    assert out["status"] == "complete_in_progress"
    assert out["continue_url"].startswith("https://www.sandbox.paypal.com/")
    assert codes(first) == ["payer_approval_required"]
    CHECKOUT_V.validate(out)  # still a schema-valid, signed checkout response
    assert out["ucp"]["payment_handlers"]
    assert stack.sim.count("/authorize") == 0 and len(stack.sim.orders) == 1

    (order_id,) = stack.sim.orders
    stack.sim.approve(order_id)
    second = complete(stack, body["id"], {})
    assert codes(second) == ["payment_authorized"]
    assert second.json()["status"] == "complete_in_progress"  # capture belongs to the gate (P2.5)
    assert stack.sim.count("/authorize") == 1 and stack.sim.count("/capture") == 0
    again = complete(stack, body["id"], {})
    assert codes(again) == ["payment_authorized"] and stack.sim.count("/authorize") == 1


def test_a_complete_without_a_checkout_mandate_is_refused_and_leaves_the_checkout_open(
    stack: Stack,
) -> None:
    body = new_checkout(stack)
    _, pm = mandates(stack, body)
    response = complete(stack, body["id"], complete_body(None, pm))
    assert codes(response) == ["mandate_required"]
    assert response.json()["status"] == "ready_for_complete" and stack.sim.calls == []


def test_a_complete_without_a_payment_token_is_refused_before_anything_is_reserved(
    stack: Stack,
) -> None:
    body = new_checkout(stack)
    cm, _ = mandates(stack, body)
    response = complete(stack, body["id"], complete_body(cm, None))
    message = response.json()["messages"][0]
    assert message["code"] == "mandate_required" and message["path"] == "$.payment.instruments"
    assert response.json()["status"] == "ready_for_complete"
    with stack.engine.connect() as conn:
        assert conn.execute(select(reservations)).all() == []


def test_a_bad_checkout_mandate_is_refused_and_a_good_one_still_works(stack: Stack) -> None:
    body = new_checkout(stack)
    cm, pm = mandates(stack, body)
    bad = cm[: len(cm) // 2] + ("A" if cm[len(cm) // 2] != "A" else "B") + cm[len(cm) // 2 + 1 :]
    refused = complete(stack, body["id"], complete_body(bad, pm))
    assert codes(refused) == ["mandate_invalid_signature"]
    assert refused.json()["status"] == "ready_for_complete"
    accepted = complete(stack, body["id"], complete_body(cm, pm))
    assert codes(accepted) == ["payer_approval_required"]


def test_a_payment_rejection_after_the_merchant_reserved_cancels_the_checkout(stack: Stack) -> None:
    body = new_checkout(stack)
    cm, pm = mandates(stack, body, amount=1)  # a payment mandate for another amount
    response = complete(stack, body["id"], complete_body(cm, pm))
    assert "mandate_scope_mismatch" in codes(response)
    assert "checkout_canceled_after_rejection" in codes(response)
    assert response.json()["status"] == "canceled"
    assert stack.sim.orders == {}
    with stack.engine.connect() as conn:
        states = {r.role: r.state for r in conn.execute(select(reservations)).all()}
    assert states == {"merchant": "released"}  # the open mandate is usable again


def test_an_order_changed_before_authorization_is_refused_and_the_checkout_canceled(
    stack: Stack,
) -> None:
    body = new_checkout(stack)
    cm, pm = mandates(stack, body)
    complete(stack, body["id"], complete_body(cm, pm))
    (order_id,) = stack.sim.orders
    stack.sim.approve(order_id)
    stack.sim.patch(order_id, amount="1.00")
    response = complete(stack, body["id"], {})
    assert "mandate_scope_mismatch" in codes(response) and response.json()["status"] == "canceled"
    assert stack.sim.count("/authorize") == 0
    with stack.engine.connect() as conn:
        assert conn.execute(select(payment_attempts.c.state)).scalar_one() == "abandoned"
        merchant_state = conn.execute(
            select(reservations.c.state).where(reservations.c.role == "merchant")
        ).scalar_one()
    assert merchant_state == "released"


def test_a_complete_while_another_is_verifying_is_told_to_wait(stack: Stack) -> None:
    body = new_checkout(stack)
    from countersign.protocols.ucp.checkout_state import Status
    from countersign.protocols.ucp.store import load, save

    with stack.engine.begin() as conn:
        record = load(conn, body["id"], lock=True)
        assert record is not None
        save(
            conn, record.advanced(status=Status.COMPLETE_IN_PROGRESS, now_us=record.updated_us + 1)
        )
    response = complete(stack, body["id"], {})
    assert codes(response) == ["complete_in_progress"]


@pytest.mark.parametrize(
    "payment",
    [
        {"instruments": [{"id": "a", "handler_id": PAYMENT_HANDLER_ID, "type": "x",
                          "credential": {"type": "wrong", "token": "t"}}]},
        {"instruments": [{"id": "a", "handler_id": PAYMENT_HANDLER_ID, "type": "x",
                          "credential": {"type": "ap2_payment_mandate", "token": 5}}]},
        {"instruments": [{"id": "a", "handler_id": PAYMENT_HANDLER_ID, "type": "x"}]},
        {"instruments": [
            {"id": "a", "handler_id": PAYMENT_HANDLER_ID, "type": "x",
             "credential": {"type": "ap2_payment_mandate", "token": "t1"}},
            {"id": "b", "handler_id": PAYMENT_HANDLER_ID, "type": "x",
             "credential": {"type": "ap2_payment_mandate", "token": "t2"}},
        ]},
        {"instruments": "x"},
        "x",
    ],
)  # fmt: skip
def test_an_ambiguous_or_malformed_payment_member_is_a_protocol_error(
    stack: Stack, payment: Any
) -> None:
    body = new_checkout(stack)
    response = complete(stack, body["id"], {"payment": payment})
    assert response.status_code == 400 and response.json()["code"] == "invalid_request"


def test_instruments_of_other_handlers_are_ignored(stack: Stack) -> None:
    body = new_checkout(stack)
    other = {"payment": {"instruments": [{"id": "a", "handler_id": "gpay_1", "type": "card",
                                           "credential": {"type": "PAYMENT_GATEWAY", "token": "x"}}]}}  # fmt: skip
    response = complete(stack, body["id"], other)
    assert response.status_code == 200 and codes(response) == ["mandate_required"]


def test_a_paypal_failure_is_payment_failed_and_never_says_the_signature_is_invalid(
    stack: Stack,
) -> None:
    from tests.paypal_sim import server_error

    stack.sim.inject("create", server_error, times=3)
    body = new_checkout(stack)
    cm, pm = mandates(stack, body)
    response = complete(stack, body["id"], complete_body(cm, pm))
    message = next(m for m in response.json()["messages"] if m["code"] == "payment_failed")
    assert message["severity"] == "recoverable" and "signature" not in message["content"].lower()
    assert response.json()["status"] == "canceled"
