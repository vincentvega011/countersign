"""A whole app built by the composition root in any mode, over the PayPal simulator.

Nothing about the modes is mocked: the mode and the flags go through `RuntimeSettings` and
`countersign.composition.build_app`, and every role (Merchant, Credential Provider, gate or
immediate capture, lock, Postgres, decision log) is the real one. Only PayPal is the simulator.
"""

from __future__ import annotations

import json
from dataclasses import dataclass
from typing import Any

from fastapi.testclient import TestClient
from sqlalchemy import Engine, text

from countersign.ablations import Ablations
from countersign.canonical import sd_hash
from countersign.catalog.catalog import load_catalog
from countersign.composition import Wiring, build_app
from countersign.merchant.authorization import checkout_jwt
from countersign.merchant.keys import generate_jwk, validate_jwk
from countersign.paypal.client import PayPalClient
from countersign.paypal.config import PayPalConfig
from countersign.protocols.ucp.profile import AP2_CAPABILITY, PAYMENT_HANDLER_ID, REST_BASE_PATH
from countersign.runtime import Mode, RuntimeSettings
from tests import paypal_sim
from tests.constraint_fixtures import (
    MERCHANT,
    checkout_constraints,
    closed_payment_values,
    line_items_constraint,
    payment_constraints,
)
from tests.integration.test_ucp_complete import Clock
from tests.lock_support import delegation
from tests.mandate_issuer import NOW, Keys, issue
from tests.paypal_sim import PayPalSim

BASE = "https://shop.example.test"
UCP_ROOT = REST_BASE_PATH + "/checkout-sessions"
UCP_AGENT = {"UCP-Agent": 'profile="https://platform.example/profile"'}
ITEM = load_catalog().items[0]

FLAGS = {
    "ABL_NO_GATE": "no_gate",
    "ABL_NO_PREAUTH_CHECK": "no_preauth_check",
    "ABL_NO_PRINCIPAL_LOCK": "no_principal_lock",
    "ABL_NO_BUDGET_RECON": "no_budget_recon",
    "ABL_NO_GLOBAL_NONCE": "no_global_nonce",
    "ABL_NO_STRICT_JSON": "no_strict_json",
}
CONFIGS = ("full", "baseline", *FLAGS)


def settings_for(config: str, *, app_env: str = "dev") -> RuntimeSettings:
    if config == "full":
        return RuntimeSettings(Mode.FULL, app_env)
    if config == "baseline":
        return RuntimeSettings(Mode.BASELINE, app_env)
    return RuntimeSettings(Mode.FULL, app_env, Ablations(**{FLAGS[config]: True}))


def reset(admin: Engine) -> None:
    with admin.begin() as conn:
        conn.execute(
            text(
                "TRUNCATE reservations, spend_entries, open_payment_mandates, "
                "payment_attempts, payer_vault, attempt_mandates, mandate_revocations, "
                "lock_events, lock_policies, webhook_events, "
                "checkout_sessions, decision_log CASCADE"
            )
        )


@dataclass
class World:
    client: TestClient
    sim: PayPalSim
    keys: Keys
    engine: Engine


def make_world(
    engine: Engine, settings: RuntimeSettings, *, webhook_id: str | None = None
) -> World:
    key = validate_jwk(generate_jwk())
    keys, sim = Keys(), PayPalSim()
    paypal = PayPalClient(
        PayPalConfig(client_id="sim", client_secret="sim-secret"),
        transport=sim.transport(),
        sleep=lambda _: None,
        now=lambda: paypal_sim.NOW,
    )
    app = build_app(
        settings,
        Wiring(
            engine=engine, merchant_key=key, platform_key=keys.issuer, paypal=paypal,
            public_base_url=BASE, payee={"id": MERCHANT["id"], "name": MERCHANT["name"]},
            paypal_payee_merchant_id=paypal_sim.MERCHANT, merchant_constraint_id=MERCHANT["id"],
            webhook_id=webhook_id, issuer="https://merchant.example",
            clock=lambda: float(NOW), clock_us=Clock(), paypal_now=lambda: paypal_sim.NOW,
        ),
    )  # fmt: skip
    return World(TestClient(app, raise_server_exceptions=False), sim, keys, engine)


# ------------------------------------------------------------------ UCP helpers


def new_checkout(world: World, **headers: str) -> dict[str, Any]:
    response = world.client.post(
        UCP_ROOT,
        json={"line_items": [{"item": {"id": ITEM.id}, "quantity": 1}]},
        headers={**UCP_AGENT, **headers},
    )
    assert response.status_code == 201, response.text
    body: dict[str, Any] = response.json()
    return body


def total_of(body: dict[str, Any]) -> int:
    return int(next(t for t in body["totals"] if t["type"] == "total")["amount"])


@dataclass
class Pair:
    cm: str
    pm: str
    open_checkout: str
    open_payment: str
    nonce_checkout: str = ""
    nonce_payment: str = ""


def mandate_pair(
    world: World,
    body: dict[str, Any],
    *,
    open_exp: int | None = None,
    nonce_checkout: str = "nc-1",
    nonce_payment: str = "np-1",
    budget: int = 1_000_000,
    amount: int | None = None,
    reuse: Pair | None = None,
    sub: str | None = None,
    checkout_issue: dict[str, Any] | None = None,
) -> Pair:
    jwt = checkout_jwt(body)
    total = total_of(body)

    def edit_open(content: dict[str, Any]) -> None:
        content["constraints"] = [
            line_items_constraint(ITEM.id, 1, ITEM.title),
            checkout_constraints()[1],
        ]

    def edit_payload(payload: dict[str, Any]) -> None:
        if sub is not None:
            payload["sub"] = sub

    extra: dict[str, Any] = {} if open_exp is None else {"open_exp": open_exp}
    cm = issue("checkout", keys=world.keys, checkout_jwt_value=jwt, nonce=nonce_checkout,
               edit_open_content=edit_open, edit_open_payload=edit_payload,
               reuse_open_token=reuse.open_checkout if reuse else None,
               **extra, **(checkout_issue or {}))  # fmt: skip
    digest = sd_hash(cm.open_token)

    def edit_payment(content: dict[str, Any]) -> None:
        content["constraints"] = payment_constraints(digest, budget)

    def edit_closed(content: dict[str, Any]) -> None:
        content.update(closed_payment_values(amount if amount is not None else total, "USD"))

    pm = issue("payment", keys=world.keys, audience="credential-provider",
               checkout_jwt_value=jwt, nonce=nonce_payment, edit_open_content=edit_payment,
               edit_kb_content=edit_closed, edit_open_payload=edit_payload,
               reuse_open_token=reuse.open_payment if reuse else None, **extra)  # fmt: skip
    return Pair(cm.token, pm.token, cm.open_token, pm.open_token, nonce_checkout, nonce_payment)


def complete_body(cm: str | None, token: str | None) -> dict[str, Any]:
    body: dict[str, Any] = {}
    if cm is not None:
        body["ap2"] = {"checkout_mandate": cm}
    if token is not None:
        body["payment"] = {
            "instruments": [
                {
                    "id": "instr_1", "handler_id": PAYMENT_HANDLER_ID, "type": "ap2",
                    "credential": {"type": "ap2_payment_mandate", "token": token},
                }
            ]
        }  # fmt: skip
    return body


def ucp_complete(world: World, checkout_id: str, body: dict[str, Any]) -> Any:
    return world.client.post(f"{UCP_ROOT}/{checkout_id}/complete", json=body, headers=UCP_AGENT)


def codes(response: Any) -> list[str]:
    return [m["code"] for m in response.json().get("messages", [])]


def purchase(world: World, body: dict[str, Any], pair: Pair) -> Any:
    """Complete, let the payer approve if asked, complete again. Returns the last response."""
    first = ucp_complete(world, body["id"], complete_body(pair.cm, pair.pm))
    if "payer_approval_required" not in codes(first):
        return first
    (order_id,) = [o for o in world.sim.orders if _unapproved(world, o)]
    world.sim.approve(order_id)
    return ucp_complete(world, body["id"], {})


def _unapproved(world: World, order_id: str) -> bool:
    return bool(world.sim.orders[order_id]["status"] != "APPROVED") and not any(
        a["order"] == order_id for a in world.sim.authorizations.values()
    )


# ------------------------------------------------------------------ ACP helpers

ACP_HEADERS = {"Content-Type": "application/json", "Idempotency-Key": "k-1"}


def acp_headers(token: str | None, *, capability: bool = False) -> dict[str, str]:
    out = dict(ACP_HEADERS)
    if token:
        out["Countersign-Delegation"] = token
    if capability:
        out["Countersign-Capabilities"] = AP2_CAPABILITY
    return out


def acp_post(world: World, path: str, body: Any, headers: dict[str, str]) -> Any:
    content = body if isinstance(body, bytes) else json.dumps(body).encode()
    return world.client.post(path, content=content, headers=headers)


def acp_create(world: World, token: str | None, *, capability: bool) -> Any:
    return acp_post(
        world, "/checkout_sessions",
        {"line_items": [{"id": ITEM.id, "quantity": 1}], "currency": "usd", "capabilities": {}},
        acp_headers(token, capability=capability),
    )  # fmt: skip


def acp_session(world: World, token: str | None, *, capability: bool) -> dict[str, Any]:
    response = acp_create(world, token, capability=capability)
    assert response.status_code == 201, response.text
    out: dict[str, Any] = response.json()
    return out


def lock_principal(world: World, token: str) -> None:
    """Negotiate AP2 over UCP as this principal, which records the lock (in modes that record it)."""
    new_checkout(
        world, **{"Countersign-Delegation": token, "Countersign-Capabilities": AP2_CAPABILITY}
    )


__all__ = ["delegation"]
