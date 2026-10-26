"""Translation between a canonical checkout and a PayPal order, in both directions.

Forward: `order_request_from_checkout` builds the create-order request for a canonical `Checkout`.
Reverse: `paypal_order_to_canonical_terms` derives the same canonical terms from a live order as
returned by `PayPalClient.get_order`. The capture gate and the pre-authorize check compare the two
with `OrderTerms.terms_hash()`; equal hashes mean the live order still says what was signed.

Security reasoning. The reverse direction reads data an attacker with the merchant app's
credentials could have changed (docs/PROTOCOL.md Decision 11), so it trusts nothing it cannot
re-derive and fails closed:

- Every amount is a `Money`. Any parse failure, currency mismatch, negative value or unsupported
  currency is an error, never a default.
- The breakdown must add up: `item_total` equals the sum of the items, `tax_total` equals the sum of
  the item taxes (and is absent when no item has tax), and `amount` equals the breakdown total. A
  breakdown entry this mapping does not produce (`insurance`, `shipping_discount`) is an error, so
  money cannot hide in a field that is never compared.
- The number of items must equal the number of signed lines. PayPal cannot carry a line item id, so
  the caller supplies the signed ids in order and PayPal's item order is relied on (it is preserved,
  see docs/PROTOCOL.md Decision 20). An item without a line, or a line without an item, is an error.
- The forward direction refuses a checkout it cannot represent exactly (a line-level discount, a
  total type PayPal has no field for, a tax that does not divide by the quantity, a HUF or TWD amount
  with a fractional unit). It never truncates or rounds, so a checkout that is accepted reverses to
  the same terms.
- The payee, `invoice_id` and `custom_id` are part of the terms. `invoice_id` is the checkout id,
  `custom_id` is the evidence reference the Credential Provider set.
"""

from __future__ import annotations

import re
from collections.abc import Sequence
from dataclasses import dataclass
from typing import Any, Literal

from countersign.canonical.hashing import domain_hash
from countersign.canonical.jcs import canonicalize
from countersign.canonical.models import Checkout, Item, LineItem, Total
from countersign.canonical.money import Money
from countersign.paypal.limits import check_custom_id, check_invoice_id
from countersign.paypal.models import (
    ExperienceContext,
    ItemView,
    Order,
    OrderItem,
    OrderRequest,
)

ORDER_TERMS_DOMAIN = "cs.paypal.terms.v1"

# The only order in which canonical totals can be reproduced from a PayPal breakdown, which has no
# order of its own.
_ORDER_TOTALS = ("subtotal", "fulfillment", "tax", "fee", "discount", "total")
_LINE_TOTALS = ("subtotal", "tax", "total")
_QUANTITY = re.compile(r"[1-9][0-9]{0,9}", re.ASCII)
# `expected_terms` builds a request only to prove the checkout is representable; the URLs are not sent.
_UNUSED_CONTEXT = ExperienceContext("https://example.invalid/r", "https://example.invalid/c")


class TranslationError(ValueError):
    """The checkout or the PayPal order cannot be translated exactly. Nothing was approximated."""

    code = "paypal_translation"


@dataclass(frozen=True)
class OrderTerms:
    """What a PayPal order says, in the form the gate compares.

    `checkout` carries the money terms (Decision 14). The other members are what PayPal holds
    beside them and what the gate also requires to be unchanged.
    """

    checkout: Checkout
    payee_merchant_id: str
    invoice_id: str
    custom_id: str

    def terms(self) -> dict[str, Any]:
        return {
            "checkout": self.checkout.terms(),
            "payee": {"merchant_id": self.payee_merchant_id},
            "invoice_id": self.invoice_id,
            "custom_id": self.custom_id,
        }

    def terms_bytes(self) -> bytes:
        return canonicalize(self.terms())

    def terms_hash(self) -> bytes:
        return domain_hash(ORDER_TERMS_DOMAIN, self.terms_bytes())


def expected_terms(checkout: Checkout, *, payee_merchant_id: str, custom_id: str) -> OrderTerms:
    """The terms a live order must have for `checkout`, made by the same rules as the order itself.

    Fails if `checkout` could not have been sent to PayPal exactly, so a checkout that has no exact
    PayPal form cannot be signed and then compared against something looser.
    """
    order_request_from_checkout(
        checkout,
        custom_id=custom_id,
        experience_context=_UNUSED_CONTEXT,
    )
    if not payee_merchant_id:
        raise TranslationError("the payee merchant id is empty")
    return OrderTerms(
        checkout=checkout,
        payee_merchant_id=payee_merchant_id,
        invoice_id=checkout.id,
        custom_id=custom_id,
    )


# ---------------------------------------------------------------- forward


def order_request_from_checkout(
    checkout: Checkout,
    *,
    custom_id: str,
    experience_context: ExperienceContext,
    category: Literal["DIGITAL_GOODS", "PHYSICAL_GOODS", "DONATION"] = "DIGITAL_GOODS",
    description: str | None = None,
) -> OrderRequest:
    """The create-order request for `checkout`: `invoice_id` is the checkout id.

    Raises `TranslationError` for any checkout PayPal cannot hold without loss.
    """
    try:
        request = _forward(checkout, custom_id, experience_context, category, description)
        request.to_json()  # forces every amount into PayPal's decimal form (HUF and TWD included)
        return request
    except TranslationError:
        raise
    except ValueError as exc:
        raise TranslationError(str(exc)) from exc


def _forward(
    checkout: Checkout,
    custom_id: str,
    context: ExperienceContext,
    category: Literal["DIGITAL_GOODS", "PHYSICAL_GOODS", "DONATION"],
    description: str | None,
) -> OrderRequest:
    currency = checkout.currency
    order_entries = _entries(checkout.totals, _ORDER_TOTALS, "the checkout totals")
    items: list[OrderItem] = []
    line_tax_total = Money.zero(currency)
    any_line_tax = False
    for line in checkout.line_items:
        entries = _entries(line.totals, _LINE_TOTALS, f"line item {line.id!r}")
        tax = entries.get("tax")
        unit_tax: Money | None = None
        if tax is not None:
            any_line_tax = True
            whole, remainder = divmod(tax.amount.minor, line.quantity)
            if remainder:
                raise TranslationError(
                    f"line item {line.id!r} tax is not a whole amount per unit: PayPal takes tax per unit"
                )
            unit_tax = Money(currency, whole)
            line_tax_total = line_tax_total + tax.amount
        items.append(
            OrderItem(
                name=line.item.title,
                quantity=line.quantity,
                unit_amount=line.item.price,
                tax=unit_tax,
                sku=line.item.id,
                category=category,
            )
        )
    order_tax = order_entries.get("tax")
    if any_line_tax != (order_tax is not None) or (
        order_tax is not None and order_tax.amount != line_tax_total
    ):
        raise TranslationError("the order tax is not the sum of the line item taxes")
    discount = order_entries.get("discount")
    return OrderRequest(
        amount=order_entries["total"].amount,
        invoice_id=check_invoice_id(checkout.id),
        custom_id=check_custom_id(custom_id),
        items=tuple(items),
        experience_context=context,
        description=description,
        shipping=_amount(order_entries.get("fulfillment")),
        handling=_amount(order_entries.get("fee")),
        discount=None if discount is None else -discount.amount,
    )


def _amount(entry: Total | None) -> Money | None:
    return None if entry is None else entry.amount


def _entries(totals: Sequence[Total], allowed: tuple[str, ...], where: str) -> dict[str, Total]:
    """Each type at most once, only allowed types, in the one order a PayPal breakdown reproduces."""
    found: dict[str, Total] = {}
    last = -1
    for entry in totals:
        if entry.type not in allowed:
            raise TranslationError(f"{where} has a {entry.type!r} entry, which PayPal cannot hold")
        position = allowed.index(entry.type)
        if entry.type in found or position < last:
            raise TranslationError(
                f"{where} must list its entries once each, in the order {', '.join(allowed)}"
            )
        found[entry.type] = entry
        last = position
    return found


# ---------------------------------------------------------------- reverse


def paypal_order_to_canonical_terms(order: Order, *, line_ids: Sequence[str]) -> OrderTerms:
    """Derive the canonical terms of a live PayPal order.

    `line_ids` are the signed checkout's line item ids, in order: PayPal cannot carry them, so they
    are applied by position and the evidence reference in `custom_id` covers them
    (docs/PROTOCOL.md Decision 20). Raises `TranslationError` on anything missing, unparseable,
    unsupported or inconsistent.
    """
    try:
        return _reverse(order, line_ids)
    except TranslationError:
        raise
    except ValueError as exc:
        raise TranslationError(str(exc)) from exc


def _reverse(order: Order, line_ids: Sequence[str]) -> OrderTerms:
    if order.intent != "AUTHORIZE":
        raise TranslationError(f"the order intent is {order.intent!r}, not AUTHORIZE")
    if len(order.purchase_units) != 1:
        raise TranslationError("the order must have exactly one purchase unit")
    unit = order.purchase_units[0]
    currency = unit.amount.currency
    breakdown = unit.breakdown
    if breakdown is None or breakdown.item_total is None:
        raise TranslationError("the order has no item_total breakdown")
    if breakdown.insurance is not None or breakdown.shipping_discount is not None:
        raise TranslationError("the breakdown has an entry this mapping never produces")
    if not unit.items:
        raise TranslationError("the order has no items")
    if len(unit.items) != len(line_ids):
        raise TranslationError(
            f"the order has {len(unit.items)} items but the checkout has {len(line_ids)} lines"
        )
    invoice_id = _required(unit.invoice_id, "invoice_id")
    custom_id = _required(unit.custom_id, "custom_id")
    merchant = _required(unit.payee.merchant_id if unit.payee else None, "payee merchant_id")

    lines = tuple(_line(item, line_id, currency) for item, line_id in zip(unit.items, line_ids))
    item_total = Money.sum((m for line in lines for m in line.amounts("subtotal")), currency)
    line_tax = Money.sum((m for line in lines for m in line.amounts("tax")), currency)
    any_tax = any(line.amounts("tax") for line in lines)
    _check(breakdown.item_total, currency, "item_total")
    if breakdown.item_total != item_total:
        raise TranslationError("item_total is not the sum of the items")
    if any_tax:
        if breakdown.tax_total is None:
            raise TranslationError("items carry tax but the breakdown has no tax_total")
        _check(breakdown.tax_total, currency, "tax_total")
        if breakdown.tax_total != line_tax:
            raise TranslationError("tax_total is not the sum of the item taxes")
    elif breakdown.tax_total is not None:
        raise TranslationError("the breakdown has a tax_total but no item has tax")

    totals = [Total(type="subtotal", amount=item_total)]
    if breakdown.shipping is not None:
        totals.append(
            Total(type="fulfillment", amount=_check(breakdown.shipping, currency, "shipping"))
        )
    if any_tax:
        totals.append(Total(type="tax", amount=line_tax))
    if breakdown.handling is not None:
        totals.append(Total(type="fee", amount=_check(breakdown.handling, currency, "handling")))
    if breakdown.discount is not None:
        totals.append(
            Total(type="discount", amount=-_check(breakdown.discount, currency, "discount"))
        )
    total = Money.sum((t.amount for t in totals), currency)
    if _check(unit.amount, currency, "amount") != total:
        raise TranslationError("the order amount is not the breakdown total")
    checkout = Checkout(
        id=invoice_id,
        currency=currency,
        line_items=lines,
        totals=(*totals, Total(type="total", amount=total)),
    )
    return OrderTerms(checkout, merchant, invoice_id, custom_id)


def _line(item: ItemView, line_id: str, currency: str) -> LineItem:
    if not _QUANTITY.fullmatch(item.quantity):
        raise TranslationError(f"item quantity {item.quantity!r} is not a positive whole number")
    quantity = int(item.quantity)
    price = _check(item.unit_amount, currency, "unit_amount")
    sku = _required(item.sku, "item sku")
    subtotal = price * quantity
    totals = [Total(type="subtotal", amount=subtotal)]
    line_total = subtotal
    if item.tax is not None:
        tax = _check(item.tax, currency, "item tax") * quantity
        totals.append(Total(type="tax", amount=tax))
        line_total = line_total + tax
    return LineItem(
        id=line_id,
        item=Item(id=sku, title=_required(item.name, "item name"), price=price),
        quantity=quantity,
        totals=(*totals, Total(type="total", amount=line_total)),
    )


def _check(money: Money, currency: str, what: str) -> Money:
    if money.currency != currency:
        raise TranslationError(f"{what} is in {money.currency}, the order is in {currency}")
    return money


def _required(value: str | None, what: str) -> str:
    if not isinstance(value, str) or not value:
        raise TranslationError(f"the order has no {what}")
    return value


__all__ = [
    "ORDER_TERMS_DOMAIN",
    "OrderTerms",
    "TranslationError",
    "expected_terms",
    "order_request_from_checkout",
    "paypal_order_to_canonical_terms",
]
