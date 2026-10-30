"""Shared setup for Credential Provider tests: a PayPal simulator, real Postgres, real mandates."""

from __future__ import annotations

from collections.abc import Callable
from dataclasses import dataclass, field
from typing import Any

from sqlalchemy import Engine

from countersign.canonical import sd_hash
from countersign.canonical.models import Checkout
from countersign.cp import CpConfig, CredentialProvider
from countersign.cp.ledger import SpendLedger
from countersign.merchant.authorization import checkout_jwt
from countersign.merchant.keys import MerchantKey, generate_jwk, validate_jwk
from countersign.paypal.client import PayPalClient
from countersign.paypal.config import PayPalConfig
from tests import paypal_sim
from tests.constraint_fixtures import (
    checkout_constraints,
    closed_payment_values,
    payment_constraints,
)
from tests.mandate_issuer import NOW, Issued, Keys, issue
from tests.merchant_support import make_checkout, signed_response
from tests.paypal_sim import PayPalSim

PAYMENT_AUD = "credential-provider"


@dataclass
class Mandates:
    checkout_mandate: str
    payment_token: str
    payment: Issued
    checkout: Issued
    issued: dict[str, Any]
    current: Checkout


@dataclass
class CpWorld:
    engine: Engine
    sim: PayPalSim
    client: PayPalClient
    provider: CredentialProvider
    config: CpConfig
    merchant_key: MerchantKey
    keys: Keys
    checkout: Checkout
    ledger: SpendLedger = field(default_factory=SpendLedger)

    def mandates(
        self,
        *,
        checkout: Checkout | None = None,
        nonce: str = "nonce-0001",
        maximum: int = 10_000,
        values: dict[str, Any] | None = None,
        constraints: Callable[[str], list[dict[str, Any]]] | None = None,
        transaction_id: str | None = None,
        reuse_open_payment: str | None = None,
        payment_kwargs: dict[str, Any] | None = None,
        checkout_kwargs: dict[str, Any] | None = None,
        reuse_checkout_open: str | None = None,
    ) -> Mandates:
        current = checkout or self.checkout
        issued = signed_response(current, self.merchant_key)
        jwt = checkout_jwt(issued)

        def edit_checkout(content: dict[str, Any]) -> None:
            content["constraints"] = checkout_constraints()

        cm = issue(
            "checkout", keys=self.keys, checkout_jwt_value=jwt, nonce=f"{nonce}-c",
            edit_open_content=edit_checkout, reuse_open_token=reuse_checkout_open,
            **(checkout_kwargs or {}),
        )  # fmt: skip
        digest = sd_hash(cm.open_token)

        def edit_open(content: dict[str, Any]) -> None:
            content["constraints"] = (
                constraints(digest) if constraints else payment_constraints(digest, maximum)
            )

        def edit_closed(content: dict[str, Any]) -> None:
            total = next(t.amount for t in current.totals if t.type == "total")
            content.update(closed_payment_values(total.minor, total.currency))
            content.update(values or {})

        pm = issue(
            "payment", keys=self.keys, audience=PAYMENT_AUD, checkout_jwt_value=jwt, nonce=nonce,
            checkout_hash_value=transaction_id, edit_open_content=edit_open,
            edit_kb_content=edit_closed, reuse_open_token=reuse_open_payment,
            **(payment_kwargs or {}),
        )  # fmt: skip
        return Mandates(cm.token, pm.token, pm, cm, issued, current)


def make_world(
    engine: Engine,
    *,
    checkout: Checkout | None = None,
    ablations: Any = None,
    enroll_vault: bool = False,
) -> CpWorld:
    from countersign.ablations import Ablations

    sim = PayPalSim()
    client = PayPalClient(
        PayPalConfig(client_id="sim-client", client_secret="sim-secret"),
        transport=sim.transport(),
        sleep=lambda _: None,
        now=lambda: paypal_sim.NOW,
    )
    merchant_key = validate_jwk(generate_jwk())
    keys = Keys()
    config = CpConfig(
        issuer="https://merchant.example",
        signing_key=merchant_key,
        platform_key=keys.issuer,
        payee={"id": "m-demo", "name": "Demo Store"},
        paypal_payee_merchant_id=paypal_sim.MERCHANT,
        return_url="https://merchant.example/return",
        cancel_url="https://merchant.example/cancel",
        enroll_vault=enroll_vault,
        ablations=ablations or Ablations(),
    )
    from countersign.constraints import PaymentConstraintEvaluator

    provider = CredentialProvider(
        config, engine, client, clock=lambda: float(NOW), evaluator=PaymentConstraintEvaluator()
    )
    return CpWorld(
        engine, sim, client, provider, config, merchant_key, keys, checkout or make_checkout()
    )
