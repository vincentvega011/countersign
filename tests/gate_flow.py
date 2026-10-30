"""Two capture gate scenarios as one reusable flow (recording, replay).

`scripts/record_gate_cassette.py` runs them against the real PayPal sandbox (a person approves each
order once), the replay test runs the same code against the recording, so both make the same calls
in the same order.

Scenario A, a clean flow: Merchant verification, Credential Provider, payer approval, authorization,
then the gate passes and captures, and the capture and the authorization are read back.

Scenario B, an order changed after approval: the order is created and approved, then PATCHed up while
`APPROVED` (the window recorded in docs/PROTOCOL.md 4.3), then authorized with the Credential
Provider's pre-authorize check switched off so that PayPal authorizes the raised amount. The gate must
catch it, void the authorization and confirm the void by GET. Nothing is ever captured in B.

The PATCH is made here and not by the product: the client has no PATCH on purpose.
"""

from __future__ import annotations

from collections.abc import Callable
from dataclasses import asdict, dataclass
from datetime import datetime
from typing import Any

import httpx
from joserfc.jwk import ECKey
from sqlalchemy import Engine

from countersign.ablations import Ablations
from countersign.canonical import sd_hash
from countersign.canonical.money import Money
from countersign.catalog.catalog import Catalog, load_catalog
from countersign.completion import GateLockAdapter
from countersign.constraints import CheckoutConstraintEvaluator
from countersign.cp import CpApprovalRequired, CpAuthorized, CpConfig, CpOutcome, CredentialProvider
from countersign.gate import CaptureGate, GateOutcome
from countersign.lock import PrincipalLock
from countersign.merchant.authorization import checkout_jwt
from countersign.merchant.decision_log import LedgerDecisionLog
from countersign.merchant.keys import generate_jwk, validate_jwk
from countersign.merchant.pg_reservations import PostgresReservationStore
from countersign.merchant.policy import policy_hash
from countersign.merchant.verify import Accepted, CheckoutMandateVerifier, MerchantConfig
from countersign.paypal.client import PayPalClient
from countersign.paypal.config import PayPalConfig
from countersign.paypal.errors import PayPalError
from tests.constraint_fixtures import (
    checkout_constraints,
    closed_payment_values,
    line_items_constraint,
    payment_constraints,
)
from tests.cp_flow import PAYEE, FlowFixture, flow_checkout, make_config, make_provider
from tests.mandate_issuer import NOW, Keys, issue
from tests.merchant_support import signed_response

REFERENCE = "/purchase_units/@reference_id=='default'"
RAISE_BY_MINOR = 2_000


@dataclass(frozen=True)
class GateFixtures:
    clean: FlowFixture
    changed: FlowFixture

    def to_json(self) -> str:
        import json

        return json.dumps(asdict(self), indent=1, sort_keys=True) + "\n"

    @classmethod
    def from_json(cls, text: str) -> GateFixtures:
        import json

        raw = json.loads(text)
        return cls(FlowFixture(**raw["clean"]), FlowFixture(**raw["changed"]))


def build_gate_fixture(checkout_id: str, catalog: Catalog | None = None) -> FlowFixture:
    """Sign a checkout and both mandates. The checkout mandate covers every line item."""
    catalog = catalog or load_catalog()
    checkout = flow_checkout(checkout_id, catalog)
    merchant_key = validate_jwk(generate_jwk())
    keys = Keys()
    jwt = checkout_jwt(signed_response(checkout, merchant_key))
    total = next(t.amount for t in checkout.totals if t.type == "total")

    def open_checkout(content: dict[str, Any]) -> None:
        content["constraints"] = [
            *(
                line_items_constraint(line.item.id, line.quantity, line.item.title)
                for line in checkout.line_items
            ),
            checkout_constraints()[1],
        ]

    # One acceptable-items entry per line, with distinct constraint ids.
    def open_checkout_numbered(content: dict[str, Any]) -> None:
        open_checkout(content)
        lines = [c for c in content["constraints"] if c["type"] == "checkout.line_items"]
        content["constraints"] = [
            {
                "type": "checkout.line_items",
                "items": [
                    {
                        "id": f"line_{n}",
                        "acceptable_items": [{"id": line.item.id, "title": line.item.title}],
                        "quantity": line.quantity,
                    }
                    for n, line in enumerate(checkout.line_items, start=1)
                ],
            },
            checkout_constraints()[1],
        ]
        assert lines

    cm = issue("checkout", keys=keys, checkout_jwt_value=jwt, nonce=f"gate-c-{checkout_id[-8:]}",
               edit_open_content=open_checkout_numbered)  # fmt: skip
    digest = sd_hash(cm.open_token)

    def open_payment(content: dict[str, Any]) -> None:
        content["constraints"] = payment_constraints(digest, total.minor * 10)

    def closed_payment(content: dict[str, Any]) -> None:
        content.update(closed_payment_values(total.minor, total.currency))

    pm = issue("payment", keys=keys, audience="credential-provider", checkout_jwt_value=jwt,
               nonce=f"gate-p-{checkout_id[-8:]}", edit_open_content=open_payment,
               edit_kb_content=closed_payment)  # fmt: skip
    return FlowFixture(
        checkout_id, cm.token, pm.token, dict(keys.issuer.as_dict(private=False)), NOW,
        dict(merchant_key.public_jwk),
    )  # fmt: skip


def make_merchant(
    engine: Engine, fixture: FlowFixture, config: CpConfig
) -> CheckoutMandateVerifier:
    assert fixture.merchant_jwk is not None
    return CheckoutMandateVerifier(
        MerchantConfig(
            issuer=config.issuer,
            signing_key=config.signing_key,
            published_keys=[fixture.merchant_jwk],
            platform_key=ECKey.import_key(fixture.platform_jwk),
        ),
        PostgresReservationStore(engine, "merchant"),
        LedgerDecisionLog(engine, policy_hash(), lambda: 1_800_000_000_000_000),
        lambda: float(fixture.now),
        CheckoutConstraintEvaluator(PAYEE["id"]),
    )


@dataclass(frozen=True)
class Stack:
    provider: CredentialProvider
    gate: CaptureGate
    merchant: CheckoutMandateVerifier


def make_stack(
    engine: Engine,
    client: PayPalClient,
    fixture: FlowFixture,
    *,
    payee_merchant_id: str,
    paypal_now: Callable[[], datetime],
    cp_ablations: Ablations | None = None,
) -> Stack:
    config = make_config(fixture, payee_merchant_id=payee_merchant_id, ablations=cp_ablations)
    gate_config = make_config(fixture, payee_merchant_id=payee_merchant_id)
    provider = make_provider(
        engine, client, fixture, payee_merchant_id=payee_merchant_id, config=config
    )
    lock = PrincipalLock(
        engine,
        platform_key=ECKey.import_key(fixture.platform_jwk),
        clock=lambda: float(fixture.now),
    )
    gate = CaptureGate(
        gate_config, engine, client, GateLockAdapter(lock),
        clock=lambda: float(fixture.now), paypal_now=paypal_now,
    )  # fmt: skip
    return Stack(provider, gate, make_merchant(engine, fixture, config))


def patch_raise(
    client: PayPalClient, transport: httpx.BaseTransport, base_url: str, order_id: str
) -> Money:
    """PATCH the approved order up by 20.00: the first item costs more, the amount grows to match.

    The item count and every other item field stay as they were, so the order still reads as terms and
    it is the comparison, not the reading, that has to catch it. Returns the new total. The access
    token is the client's own cached one: the PATCH has to be made with the merchant app's credentials
    (docs/PROTOCOL.md 4.3), and the client has no PATCH.
    """
    order = client.get_order(order_id)
    unit = order.purchase_units[0]
    old = unit.amount
    new = Money(old.currency, old.minor + RAISE_BY_MINOR)
    items: list[dict[str, Any]] = []
    for index, item in enumerate(unit.items):
        price = item.unit_amount
        if index == 0:
            if item.quantity != "1":
                raise RuntimeError("the first item must have quantity 1 for a +20.00 raise")
            price = Money(price.currency, price.minor + RAISE_BY_MINOR)
        entry: dict[str, Any] = {
            "name": item.name,
            "quantity": item.quantity,
            "unit_amount": {"currency_code": price.currency, "value": price.to_paypal()},
        }
        for key in ("sku", "category"):
            if getattr(item, key) is not None:
                entry[key] = getattr(item, key)
        items.append(entry)
    item_total = Money(old.currency, sum(i.unit_amount.minor * int(i.quantity) for i in unit.items)
                       + RAISE_BY_MINOR)  # fmt: skip
    value = {"currency_code": new.currency, "value": new.to_paypal()}
    ops = [
        {"op": "replace", "path": f"{REFERENCE}/items", "value": items},
        {
            "op": "replace",
            "path": f"{REFERENCE}/amount",
            "value": {
                **value,
                "breakdown": {
                    "item_total": {
                        "currency_code": item_total.currency,
                        "value": item_total.to_paypal(),
                    }
                },
            },
        },
    ]
    token = client._access_token()  # a test helper: reuse the client's token, no extra OAuth call
    with httpx.Client(base_url=base_url, transport=transport) as http:
        response = http.patch(
            f"/v2/checkout/orders/{order_id}",
            json=ops,
            headers={"Authorization": f"Bearer {token}"},
        )
    if response.status_code != 204:
        raise RuntimeError(f"PayPal refused the PATCH with HTTP {response.status_code}")
    return new


def authorize_flow(
    stack: Stack,
    fixture: FlowFixture,
    approve: Callable[[str], None],
    *,
    between: Callable[[str], None] | None = None,
    catalog: Catalog | None = None,
) -> tuple[CpOutcome, CpOutcome]:
    """Merchant verify, CP start, payer approval, optional `between(order_id)`, CP finish."""
    checkout = flow_checkout(fixture.checkout_id, catalog)
    verdict = stack.merchant.verify(
        mandate=fixture.checkout_mandate, issued_checkout=None, current=checkout
    )
    if not isinstance(verdict, Accepted):
        raise TypeError(f"the Merchant refused the mandate: {verdict}")
    started = stack.provider.start(
        payment_token=fixture.payment_token,
        checkout_mandate=fixture.checkout_mandate,
        current=checkout,
    )
    if not isinstance(started, CpApprovalRequired):
        return started, started
    approve(started.approval_url)
    if between is not None:
        between(started.order_id)
    return started, stack.provider.finish(checkout_id=fixture.checkout_id, current=checkout)


def run_gate(stack: Stack, fixture: FlowFixture, catalog: Catalog | None = None) -> GateOutcome:
    checkout = flow_checkout(fixture.checkout_id, catalog)
    return stack.gate.run(checkout_id=fixture.checkout_id, current=checkout)


def authorized(outcome: CpOutcome) -> CpAuthorized:
    assert isinstance(outcome, CpAuthorized), outcome
    return outcome


def paypal_config() -> PayPalConfig:
    return PayPalConfig(client_id="replay-client-id", client_secret="replay-client-secret")


def probe_refusal(client: PayPalClient, checkout_id: str, authorization_id: str) -> PayPalError:
    """Void an already voided authorization to get a real PayPal 422 error body.

    The recorded exchange shows where PayPal puts the specific error code (`name` or
    `details[].issue`). A different checkout id gives a different Request-Id, because PayPal replays
    the first result for a repeated one (docs/PROTOCOL.md 4.2) and would answer 204 again.
    """
    try:
        client.void_authorization(f"{checkout_id}-probe", authorization_id)
    except PayPalError as error:
        return error
    raise RuntimeError("PayPal accepted a second void of the same authorization")
