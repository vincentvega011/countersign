"""SANDBOX RECORDING AND TEST ONLY: an authorize-and-capture cycle with no capture gate.

This runs create, authorize and capture with no mandate and no gate, and mints its own capture
approval. It exists so the sandbox cassette can be recorded and replayed. It is deliberately not part
of the `countersign` package: nothing in `src/` may import it (tests/unit/test_capture_surface.py
enforces that), and the product captures only through the capture gate.

The authorize-and-capture cycle that the cassette is recorded from and replayed against.

`scripts/record_paypal_cassette.py` runs it live (a person approves the order on the sandbox) and the
replay test runs the same code against the recording, so both make exactly the same calls in the same
order. Every state is read back with a GET; no mutation response is used for state.
"""

from __future__ import annotations

from collections.abc import Callable
from dataclasses import dataclass

from countersign.canonical.hashing import b64url, domain_hash
from countersign.canonical.models import Checkout
from countersign.canonical.money import Money
from countersign.catalog.catalog import Catalog, load_catalog
from countersign.paypal.approval import mint_capture_approval
from countersign.paypal.client import PayPalClient
from countersign.paypal.models import (
    Authorization,
    Capture,
    ExperienceContext,
    Order,
    OrderItem,
    OrderRequest,
)

RETURN_URL = "https://example.com/return"
CANCEL_URL = "https://example.com/cancel"


@dataclass(frozen=True)
class CycleResult:
    checkout: Checkout
    custom_id: str
    approval_url: str | None
    approved: Order
    authorized: Order
    authorization: Authorization
    captured_authorization: Authorization
    capture: Capture
    final_order: Order


def cycle_checkout(checkout_id: str, catalog: Catalog) -> tuple[Checkout, OrderRequest, str]:
    """Two catalog items, one of them twice, as a checkout and the PayPal order for it."""
    first, second = catalog.items[0], catalog.items[1]
    checkout = Checkout.from_lines(
        checkout_id,
        catalog.currency,
        [("li_1", first.to_item(), 1), ("li_2", second.to_item(), 2)],
    )
    custom_id = "cs1." + b64url(domain_hash("cs.cassette.v1", checkout_id.encode()))
    items = tuple(
        OrderItem(
            name=line.item.title,
            quantity=line.quantity,
            unit_amount=line.item.price,
            sku=line.item.id,
            category="DIGITAL_GOODS",
        )
        for line in checkout.line_items
    )
    total = next(t.amount for t in checkout.totals if t.type == "total")
    request = OrderRequest(
        amount=Money(total.currency, total.minor),
        invoice_id=checkout_id,
        custom_id=custom_id,
        items=items,
        experience_context=ExperienceContext(return_url=RETURN_URL, cancel_url=CANCEL_URL),
        description="Countersign sandbox cassette",
    )
    return checkout, request, custom_id


def run_cycle(
    client: PayPalClient,
    checkout_id: str,
    *,
    approve: Callable[[str], None],
    catalog: Catalog | None = None,
) -> CycleResult:
    """create, approve (by the caller), authorize, capture; every state re-fetched."""
    checkout, request, custom_id = cycle_checkout(checkout_id, catalog or load_catalog())
    total = request.amount

    created = client.create_order(checkout_id, request, terms_hash=checkout.terms_hash())
    if created.approval_url is None:
        raise RuntimeError("PayPal returned no approval link")
    approve(created.approval_url)
    approved = client.get_order(created.resource_id)

    client.authorize_order(checkout_id, created.resource_id)
    authorized = client.get_order(created.resource_id)
    (authorization_ref,) = authorized.authorizations
    authorization = client.get_authorization(authorization_ref.id)

    approval = mint_capture_approval(  # recording and tests only: there is no gate here
        checkout_id=checkout_id,
        authorization_id=authorization.id,
        expected_total=total,
        invoice_id=checkout_id,
        custom_id=custom_id,
    )
    client.capture_authorization(approval)
    final_order = client.get_order(created.resource_id)
    (capture_ref,) = final_order.captures
    capture = client.get_capture(capture_ref.id)
    captured_authorization = client.get_authorization(authorization.id)
    return CycleResult(
        checkout=checkout,
        custom_id=custom_id,
        approval_url=created.approval_url,
        approved=approved,
        authorized=authorized,
        authorization=authorization,
        captured_authorization=captured_authorization,
        capture=capture,
        final_order=final_order,
    )
