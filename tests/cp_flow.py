"""The Credential Provider happy path as one reusable flow (recording, replay and simulator tests).

`scripts/record_cp_cassette.py` runs it against the real PayPal sandbox (a person approves the order
once), the cassette replay test runs the same code against the recording, and a simulator test runs
it against `tests.paypal_sim`. All three therefore make the same calls in the same order.

The mandates are generated once, at recording time, and saved next to the cassette: their digests
are inside the `custom_id` of the recorded create-order request, so a replay must present the same
tokens. They hold public keys and signatures only; the private keys are discarded after signing.
"""

from __future__ import annotations

import json
from collections.abc import Callable
from dataclasses import asdict, dataclass
from typing import Any

from joserfc.jwk import ECKey
from sqlalchemy import Engine

from countersign.ablations import Ablations
from countersign.canonical import sd_hash
from countersign.canonical.models import Checkout
from countersign.catalog.catalog import Catalog, load_catalog
from countersign.constraints import PaymentConstraintEvaluator
from countersign.cp import (
    CpApprovalRequired,
    CpAuthorized,
    CpConfig,
    CpOutcome,
    CredentialProvider,
)
from countersign.merchant.authorization import checkout_jwt
from countersign.merchant.keys import generate_jwk, validate_jwk
from countersign.paypal.client import PayPalClient
from tests.constraint_fixtures import (
    closed_payment_values,
    line_items_constraint,
    payment_constraints,
)
from tests.mandate_issuer import NOW, Keys, issue
from tests.merchant_support import signed_response

RETURN_URL = "https://example.com/return"
CANCEL_URL = "https://example.com/cancel"
PAYEE = {"id": "m-demo", "name": "Demo Store"}


@dataclass(frozen=True)
class FlowFixture:
    checkout_id: str
    checkout_mandate: str
    payment_token: str
    platform_jwk: dict[str, Any]  # public
    now: int
    merchant_jwk: dict[str, Any] | None = None  # public key that signed the checkout JWT

    def to_json(self) -> str:
        return json.dumps(asdict(self), indent=1, sort_keys=True) + "\n"

    @classmethod
    def from_json(cls, text: str) -> FlowFixture:
        return cls(**json.loads(text))


def flow_checkout(checkout_id: str, catalog: Catalog | None = None) -> Checkout:
    from tests.ungated_capture_cycle import cycle_checkout

    return cycle_checkout(checkout_id, catalog or load_catalog())[0]


def build_fixture(checkout_id: str, catalog: Catalog | None = None) -> FlowFixture:
    """Sign a checkout, an open and closed Checkout Mandate and Payment Mandate for it."""
    catalog = catalog or load_catalog()
    checkout = flow_checkout(checkout_id, catalog)
    merchant_key = validate_jwk(generate_jwk())
    keys = Keys()
    jwt = checkout_jwt(signed_response(checkout, merchant_key))
    total = next(t.amount for t in checkout.totals if t.type == "total")

    def open_checkout(content: dict[str, Any]) -> None:
        content["constraints"] = [
            line_items_constraint(line.item.id, line.quantity, line.item.title)
            for line in checkout.line_items[:1]
        ]

    cm = issue("checkout", keys=keys, checkout_jwt_value=jwt, nonce="rec-checkout",
               edit_open_content=open_checkout)  # fmt: skip
    digest = sd_hash(cm.open_token)

    def open_payment(content: dict[str, Any]) -> None:
        content["constraints"] = payment_constraints(digest, total.minor * 10)

    def closed_payment(content: dict[str, Any]) -> None:
        content.update(closed_payment_values(total.minor, total.currency))

    pm = issue("payment", keys=keys, audience="credential-provider", checkout_jwt_value=jwt,
               nonce="rec-payment", edit_open_content=open_payment,
               edit_kb_content=closed_payment)  # fmt: skip
    return FlowFixture(
        checkout_id, cm.token, pm.token, dict(keys.issuer.as_dict(private=False)), NOW,
        dict(merchant_key.public_jwk),
    )  # fmt: skip


def make_config(
    fixture: FlowFixture, *, payee_merchant_id: str, ablations: Ablations | None = None
) -> CpConfig:
    return CpConfig(
        issuer="https://merchant.example",
        signing_key=validate_jwk(generate_jwk()),
        platform_key=ECKey.import_key(fixture.platform_jwk),
        payee=PAYEE,
        paypal_payee_merchant_id=payee_merchant_id,
        return_url=RETURN_URL,
        cancel_url=CANCEL_URL,
        ablations=ablations or Ablations(),
    )


def make_provider(
    engine: Engine,
    client: PayPalClient,
    fixture: FlowFixture,
    *,
    payee_merchant_id: str,
    config: CpConfig | None = None,
) -> CredentialProvider:
    config = config or make_config(fixture, payee_merchant_id=payee_merchant_id)
    return CredentialProvider(
        config, engine, client, clock=lambda: float(fixture.now),
        evaluator=PaymentConstraintEvaluator(),
    )  # fmt: skip


def run_flow(
    provider: CredentialProvider,
    fixture: FlowFixture,
    approve: Callable[[str], None],
    catalog: Catalog | None = None,
) -> tuple[CpOutcome, CpOutcome]:
    """start, the payer approves (by the caller), finish."""
    checkout = flow_checkout(fixture.checkout_id, catalog)
    started = provider.start(
        payment_token=fixture.payment_token,
        checkout_mandate=fixture.checkout_mandate,
        current=checkout,
    )
    if not isinstance(started, CpApprovalRequired):
        return started, started
    approve(started.approval_url)
    finished = provider.finish(checkout_id=fixture.checkout_id, current=checkout)
    return started, finished


def authorized(outcome: CpOutcome) -> CpAuthorized:
    assert isinstance(outcome, CpAuthorized), outcome
    return outcome
