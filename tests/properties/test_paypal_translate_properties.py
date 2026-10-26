"""Forward then reverse is exact for generated checkouts; tampering never goes unnoticed."""

from __future__ import annotations

from hypothesis import assume, given
from hypothesis import strategies as st

from countersign.canonical.models import Checkout, Item, LineItem, Total
from countersign.canonical.money import Money
from countersign.paypal.translate import (
    TranslationError,
    expected_terms,
    order_request_from_checkout,
    paypal_order_to_canonical_terms,
)
from tests.paypal_orders import CONTEXT, MERCHANT, live_order_json, parse_order

CURRENCIES = ["USD", "EUR", "GBP", "JPY", "HUF", "TWD"]
text = st.text(
    alphabet=st.characters(
        min_codepoint=0x20, max_codepoint=0x2FFF, blacklist_categories=("Cc", "Cs")
    ),
    min_size=1,
    max_size=30,
)


@st.composite
def checkouts(draw):
    currency = draw(st.sampled_from(CURRENCIES))
    step = 100 if currency in ("HUF", "TWD") else 1  # whole units where PayPal has no decimals
    n = draw(st.integers(min_value=1, max_value=4))
    ids = draw(st.lists(text, min_size=n, max_size=n, unique=True))
    lines = []
    for line_id in ids:
        price = Money(currency, step * draw(st.integers(min_value=1, max_value=50_000)))
        quantity = draw(st.integers(min_value=1, max_value=9))
        subtotal = price * quantity
        totals = [Total(type="subtotal", amount=subtotal)]
        line_total = subtotal
        if draw(st.booleans()):
            unit_tax = Money(currency, step * draw(st.integers(min_value=0, max_value=5_000)))
            totals.append(Total(type="tax", amount=unit_tax * quantity))
            line_total = line_total + unit_tax * quantity
        totals.append(Total(type="total", amount=line_total))
        lines.append(
            LineItem(
                id=line_id,
                item=Item(id=draw(text), title=draw(text), price=price),
                quantity=quantity,
                totals=tuple(totals),
            )
        )
    entries = [
        Total(
            type="subtotal",
            amount=Money.sum((line.totals[0].amount for line in lines), currency),
        )
    ]
    if draw(st.booleans()):
        entries.append(
            Total(type="fulfillment", amount=Money(currency, step * draw(st.integers(0, 5_000))))
        )
    line_tax = Money.sum((m for line in lines for m in line.amounts("tax")), currency)
    if any(line.amounts("tax") for line in lines):
        entries.append(Total(type="tax", amount=line_tax))
    if draw(st.booleans()):
        entries.append(
            Total(type="fee", amount=Money(currency, step * draw(st.integers(0, 5_000))))
        )
    if draw(st.booleans()):
        cut = step * draw(st.integers(min_value=1, max_value=50_000))
        entries.append(Total(type="discount", amount=Money(currency, -cut)))
    total = Money.sum((e.amount for e in entries), currency)
    assume(total.minor > 0)
    return Checkout(
        id=draw(text),
        currency=currency,
        line_items=tuple(lines),
        totals=(*entries, Total(type="total", amount=total)),
    )


def build(checkout: Checkout, custom_id: str = "cs1.x"):
    request = order_request_from_checkout(checkout, custom_id=custom_id, experience_context=CONTEXT)
    return request, live_order_json(request)


@given(checkouts())
def test_forward_then_reverse_round_trips_exactly(checkout: Checkout) -> None:
    _, raw = build(checkout)
    line_ids = [line.id for line in checkout.line_items]
    terms = paypal_order_to_canonical_terms(parse_order(raw), line_ids=line_ids)
    assert terms.checkout.terms_bytes() == checkout.terms_bytes()
    assert terms.checkout.terms_hash() == checkout.terms_hash()
    want = expected_terms(checkout, payee_merchant_id=MERCHANT, custom_id="cs1.x")
    assert terms.terms_hash() == want.terms_hash()


@given(checkouts(), st.integers(min_value=0, max_value=3), st.integers(min_value=1, max_value=999))
def test_raising_one_amount_never_goes_unnoticed(
    checkout: Checkout, which: int, delta: int
) -> None:
    """Add to one money value of the live order: the result is an error or different terms."""
    _, raw = build(checkout)
    line_ids = [line.id for line in checkout.line_items]
    good = paypal_order_to_canonical_terms(parse_order(raw), line_ids=line_ids).terms_hash()
    unit = raw["purchase_units"][0]
    targets = [
        unit["amount"],
        unit["amount"]["breakdown"]["item_total"],
        unit["items"][0]["unit_amount"],
    ]
    if "tax" in unit["items"][0]:
        targets.append(unit["items"][0]["tax"])
    target = targets[which % len(targets)]
    currency = target["currency_code"]
    changed = Money.from_paypal(target["value"], currency) + Money(
        currency, delta * (100 if currency in ("HUF", "TWD") else 1)
    )
    target["value"] = changed.to_paypal()
    try:
        after = paypal_order_to_canonical_terms(parse_order(raw), line_ids=line_ids).terms_hash()
    except ValueError:
        return
    assert after != good


@given(checkouts())
def test_a_removed_item_is_always_an_error(checkout: Checkout) -> None:
    _, raw = build(checkout)
    raw["purchase_units"][0]["items"].pop()
    line_ids = [line.id for line in checkout.line_items]
    try:
        paypal_order_to_canonical_terms(parse_order(raw), line_ids=line_ids)
    except TranslationError:
        return
    raise AssertionError("an order with a missing item was accepted")
