"""The create-and-read flow that the order-terms cassette is recorded from and replayed against.

`scripts/record_paypal_order_terms.py` runs it live and the replay test runs the same code against the
recording. No payer approval is needed: an order is created from a canonical checkout and read back
with a GET, and the terms re-derived from what PayPal returns must equal the checkout that was sent.
Two checkouts are used, one with only items and one with tax, shipping, handling and a discount, so
the recording shows which breakdown fields PayPal echoes.
"""

from __future__ import annotations

from dataclasses import dataclass

from countersign.canonical.hashing import b64url, domain_hash
from countersign.canonical.models import Checkout, LineItem, Total
from countersign.canonical.money import Money
from countersign.catalog.catalog import Catalog, load_catalog
from countersign.paypal.client import PayPalClient
from countersign.paypal.models import ExperienceContext, Order
from countersign.paypal.translate import (
    OrderTerms,
    order_request_from_checkout,
    paypal_order_to_canonical_terms,
)

RETURN_URL = "https://example.com/return"
CANCEL_URL = "https://example.com/cancel"
KINDS = ("plain", "rich")


@dataclass(frozen=True)
class TermsResult:
    kind: str
    checkout: Checkout
    custom_id: str
    order: Order
    terms: OrderTerms


def terms_checkout(kind: str, checkout_id: str, catalog: Catalog) -> Checkout:
    first, second = catalog.items[0].to_item(), catalog.items[1].to_item()
    if kind == "plain":
        return Checkout.from_lines(
            checkout_id, catalog.currency, [("li_1", first, 1), ("li_2", second, 2)]
        )
    if kind != "rich":
        raise ValueError(f"unknown kind {kind!r}")
    currency = catalog.currency
    lines = []
    for line_id, item, quantity, unit_tax in (("li_1", first, 2, 100), ("li_2", second, 1, 50)):
        subtotal = item.price * quantity
        tax = Money(currency, unit_tax * quantity)
        lines.append(
            LineItem(
                id=line_id,
                item=item,
                quantity=quantity,
                totals=(
                    Total(type="subtotal", amount=subtotal),
                    Total(type="tax", amount=tax),
                    Total(type="total", amount=subtotal + tax),
                ),
            )
        )
    entries = [
        Total(type="subtotal", amount=Money.sum((li.totals[0].amount for li in lines), currency)),
        Total(type="fulfillment", amount=Money(currency, 499)),
        Total(type="tax", amount=Money(currency, 250)),
        Total(type="fee", amount=Money(currency, 100)),
        Total(type="discount", amount=Money(currency, -300)),
    ]
    total = Money.sum((e.amount for e in entries), currency)
    return Checkout(
        id=checkout_id,
        currency=currency,
        line_items=tuple(lines),
        totals=(*entries, Total(type="total", amount=total)),
    )


def run_terms_flow(
    client: PayPalClient, kind: str, checkout_id: str, *, catalog: Catalog | None = None
) -> TermsResult:
    """Create an order from the checkout, read it back, and re-derive its terms."""
    checkout = terms_checkout(kind, checkout_id, catalog or load_catalog())
    custom_id = "cs1." + b64url(domain_hash("cs.cassette.v1", checkout_id.encode()))
    request = order_request_from_checkout(
        checkout,
        custom_id=custom_id,
        experience_context=ExperienceContext(RETURN_URL, CANCEL_URL),
        description="Countersign order terms cassette",
    )
    created = client.create_order(checkout_id, request, terms_hash=checkout.terms_hash())
    order = client.get_order(created.resource_id)
    terms = paypal_order_to_canonical_terms(
        order, line_ids=[line.id for line in checkout.line_items]
    )
    return TermsResult(kind, checkout, custom_id, order, terms)
