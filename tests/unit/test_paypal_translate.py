"""Forward and reverse translation between a canonical checkout and a PayPal order."""

from __future__ import annotations

import copy
from typing import Any

import pytest

from countersign.canonical.models import Checkout, EachQuantityUnit, Item, LineItem, Total
from countersign.canonical.money import Money
from countersign.paypal.models import Order
from countersign.paypal.translate import (
    OrderTerms,
    TranslationError,
    expected_terms,
    order_request_from_checkout,
    paypal_order_to_canonical_terms,
)
from tests.paypal_orders import CONTEXT, MERCHANT, live_order_json, parse_order

CUSTOM = "cs1.evidence-reference"
LINES = ["li_1", "li_2"]


def usd(minor: int) -> Money:
    return Money("USD", minor)


def rich_checkout(*, currency: str = "USD") -> Checkout:
    """Two lines, tax on both, shipping, handling and a discount: every field PayPal can carry."""
    unit = 100 if currency in ("HUF", "TWD") else 1
    a = Item(id="sku-a", title="Headphones", price=Money(currency, 2500 * unit))
    b = Item(id="sku-b", title="Cable", price=Money(currency, 900 * unit))
    lines = []
    for line_id, item, quantity, tax in (("li_1", a, 2, 400 * unit), ("li_2", b, 3, 300 * unit)):
        subtotal = item.price * quantity
        lines.append(
            LineItem(
                id=line_id,
                item=item,
                quantity=quantity,
                totals=(
                    Total(type="subtotal", amount=subtotal),
                    Total(type="tax", amount=Money(currency, tax)),
                    Total(type="total", amount=subtotal + Money(currency, tax)),
                ),
            )
        )
    subtotal = Money.sum((line.totals[0].amount for line in lines), currency)
    entries = [
        Total(type="subtotal", amount=subtotal),
        Total(type="fulfillment", amount=Money(currency, 500 * unit)),
        Total(type="tax", amount=Money(currency, 700 * unit)),
        Total(type="fee", amount=Money(currency, 200 * unit)),
        Total(type="discount", amount=Money(currency, -1000 * unit)),
    ]
    total = Money.sum((e.amount for e in entries), currency)
    return Checkout(
        id="chk_rich",
        currency=currency,
        line_items=tuple(lines),
        totals=(*entries, Total(type="total", amount=total)),
    )


def plain_checkout() -> Checkout:
    return Checkout.from_lines(
        "chk_plain",
        "USD",
        [
            ("li_1", Item(id="sku-a", title="Headphones", price=usd(2500)), 1),
            ("li_2", Item(id="sku-b", title="Cable", price=usd(900)), 2),
        ],
    )


def forward(checkout: Checkout) -> Any:
    return order_request_from_checkout(checkout, custom_id=CUSTOM, experience_context=CONTEXT)


def live(checkout: Checkout) -> dict[str, Any]:
    return live_order_json(forward(checkout))


def reverse(raw: dict[str, Any] | Order, line_ids: list[str] | None = None) -> OrderTerms:
    order = parse_order(raw) if isinstance(raw, dict) else raw
    return paypal_order_to_canonical_terms(order, line_ids=line_ids or LINES)


# ---------------------------------------------------------------- round trip


@pytest.mark.parametrize("make", [plain_checkout, rich_checkout], ids=["plain", "rich"])
def test_forward_then_reverse_is_exact(make) -> None:
    checkout = make()
    terms = reverse(live(checkout))
    want = expected_terms(checkout, payee_merchant_id=MERCHANT, custom_id=CUSTOM)
    assert terms.checkout.terms() == checkout.terms()
    assert terms.checkout.terms_hash() == checkout.terms_hash()
    assert terms.terms_hash() == want.terms_hash()
    assert terms.invoice_id == checkout.id and terms.custom_id == CUSTOM
    assert terms.payee_merchant_id == MERCHANT


@pytest.mark.parametrize("currency", ["HUF", "TWD", "JPY"])
def test_zero_decimal_currencies_round_trip(currency: str) -> None:
    checkout = rich_checkout(currency=currency)
    raw = live(checkout)
    amount = raw["purchase_units"][0]["amount"]
    assert "." not in amount["value"]
    assert reverse(raw).checkout.terms_hash() == checkout.terms_hash()


@pytest.mark.parametrize("currency", ["HUF", "TWD"])
def test_a_fractional_unit_in_huf_or_twd_is_refused_not_rounded(currency: str) -> None:
    item = Item(id="s", title="t", price=Money(currency, 1050))  # 10.50 in ISO minor units
    checkout = Checkout.from_lines("c", currency, [("li_1", item, 1)])
    with pytest.raises(TranslationError, match="whole units"):
        forward(checkout)


def test_the_request_carries_invoice_id_custom_id_sku_and_breakdown() -> None:
    body = forward(rich_checkout()).to_json()["purchase_units"][0]
    assert body["invoice_id"] == "chk_rich" and body["custom_id"] == CUSTOM
    assert [(i["name"], i["sku"], i["quantity"]) for i in body["items"]] == [
        ("Headphones", "sku-a", "2"),
        ("Cable", "sku-b", "3"),
    ]
    assert body["items"][0]["tax"]["value"] == "2.00" and body["items"][1]["tax"]["value"] == "1.00"
    assert body["amount"]["breakdown"] == {
        "item_total": {"currency_code": "USD", "value": "77.00"},
        "tax_total": {"currency_code": "USD", "value": "7.00"},
        "shipping": {"currency_code": "USD", "value": "5.00"},
        "handling": {"currency_code": "USD", "value": "2.00"},
        "discount": {"currency_code": "USD", "value": "10.00"},
    }
    assert body["amount"]["value"] == "81.00"


# ---------------------------------------------------------------- forward refusals


def test_a_title_over_the_name_limit_cannot_be_built() -> None:
    with pytest.raises(ValueError):
        Item(id="s", title="x" * 128, price=usd(1))


def test_a_checkout_id_over_the_invoice_limit_is_refused_not_truncated() -> None:
    checkout = Checkout.from_lines(
        "c" * 128, "USD", [("li_1", Item(id="s", title="t", price=usd(100)), 1)]
    )
    with pytest.raises(TranslationError, match="invoice_id"):
        forward(checkout)


def test_an_overlong_custom_id_is_refused() -> None:
    with pytest.raises(TranslationError, match="custom_id"):
        order_request_from_checkout(
            plain_checkout(), custom_id="x" * 256, experience_context=CONTEXT
        )


def test_a_zero_total_is_refused() -> None:
    item = Item(id="s", title="t", price=usd(0))
    with pytest.raises(TranslationError, match="positive"):
        forward(Checkout.from_lines("c", "USD", [("li_1", item, 1)]))


def replace_totals(checkout: Checkout, totals: list[Total]) -> Checkout:
    return Checkout(
        id=checkout.id,
        currency=checkout.currency,
        line_items=checkout.line_items,
        totals=tuple(totals),
    )


def test_a_total_type_paypal_has_no_field_for_is_refused() -> None:
    base = plain_checkout()
    line = base.line_items[0]
    discounted = LineItem(
        id=line.id,
        item=line.item,
        quantity=line.quantity,
        totals=(
            Total(type="subtotal", amount=usd(2500)),
            Total(type="items_discount", amount=usd(-100)),
            Total(type="total", amount=usd(2400)),
        ),
    )
    checkout = Checkout(
        id="c",
        currency="USD",
        line_items=(discounted,),
        totals=(
            Total(type="subtotal", amount=usd(2500)),
            Total(type="items_discount", amount=usd(-100)),
            Total(type="total", amount=usd(2400)),
        ),
    )
    with pytest.raises(TranslationError, match="items_discount"):
        forward(checkout)


def test_totals_out_of_the_reproducible_order_are_refused() -> None:
    base = rich_checkout()
    swapped = list(base.totals)
    swapped[1], swapped[3] = swapped[3], swapped[1]  # fee before tax, fulfillment last
    with pytest.raises(TranslationError, match="order"):
        forward(replace_totals(base, swapped))


def test_a_repeated_total_type_is_refused() -> None:
    base = plain_checkout()
    totals = [
        Total(type="subtotal", amount=usd(4300)),
        Total(type="fee", amount=usd(100)),
        Total(type="fee", amount=usd(100)),
        Total(type="total", amount=usd(4500)),
    ]
    with pytest.raises(TranslationError, match="once each"):
        forward(replace_totals(base, totals))


def test_a_tax_that_does_not_divide_by_the_quantity_is_refused() -> None:
    item = Item(id="s", title="t", price=usd(1000))
    line = LineItem(
        id="li_1",
        item=item,
        quantity=3,
        totals=(
            Total(type="subtotal", amount=usd(3000)),
            Total(type="tax", amount=usd(100)),
            Total(type="total", amount=usd(3100)),
        ),
    )
    checkout = Checkout(
        id="c",
        currency="USD",
        line_items=(line,),
        totals=(
            Total(type="subtotal", amount=usd(3000)),
            Total(type="tax", amount=usd(100)),
            Total(type="total", amount=usd(3100)),
        ),
    )
    with pytest.raises(TranslationError, match="per unit"):
        forward(checkout)


def test_an_order_tax_that_is_not_the_sum_of_line_taxes_is_refused() -> None:
    base = plain_checkout()
    totals = [
        Total(type="subtotal", amount=usd(4300)),
        Total(type="tax", amount=usd(100)),
        Total(type="total", amount=usd(4400)),
    ]
    with pytest.raises(TranslationError, match="sum of the line item taxes"):
        forward(replace_totals(base, totals))


def test_an_explicit_each_unit_is_allowed_and_not_part_of_the_terms() -> None:
    unit = EachQuantityUnit(unit="C62", display_text="each")
    item = Item(id="s", title="t", price=usd(100), quantity_unit=unit)
    checkout = Checkout.from_lines("c", "USD", [("li_1", item, 1)])
    terms = reverse(live(checkout), ["li_1"])
    assert terms.checkout.terms_hash() == checkout.terms_hash()


def test_expected_terms_refuses_a_checkout_without_an_exact_paypal_form() -> None:
    item = Item(id="s", title="t", price=usd(0))
    with pytest.raises(TranslationError):
        expected_terms(
            Checkout.from_lines("c", "USD", [("li_1", item, 1)]),
            payee_merchant_id=MERCHANT,
            custom_id=CUSTOM,
        )
    with pytest.raises(TranslationError, match="payee"):
        expected_terms(plain_checkout(), payee_merchant_id="", custom_id=CUSTOM)


# ---------------------------------------------------------------- reverse fails closed


def mutate(checkout: Checkout, change) -> dict[str, Any]:
    raw = live(checkout)
    change(raw["purchase_units"][0], raw)
    return raw


def outcome(raw: dict[str, Any], line_ids: list[str] | None = None) -> bytes | str:
    """The terms hash, or "error" when the order cannot be parsed or translated."""
    try:
        return reverse(raw, line_ids).terms_hash()
    except ValueError:
        return "error"


def original(checkout: Checkout) -> bytes:
    return reverse(live(checkout)).terms_hash()


def set_value(path: list[Any], value: Any):
    def change(unit: dict[str, Any], _raw: dict[str, Any]) -> None:
        node: Any = unit
        for key in path[:-1]:
            node = node[key]
        node[path[-1]] = value

    return change


def set_all_currencies(code: str):
    def change(unit: dict[str, Any], _raw: dict[str, Any]) -> None:
        unit["amount"]["currency_code"] = code
        for entry in unit["amount"]["breakdown"].values():
            entry["currency_code"] = code
        for item in unit["items"]:
            item["unit_amount"]["currency_code"] = code
            if "tax" in item:
                item["tax"]["currency_code"] = code

    return change


def remove_item(unit: dict[str, Any], _raw: dict[str, Any]) -> None:
    del unit["items"][1]


def add_item(unit: dict[str, Any], _raw: dict[str, Any]) -> None:
    unit["items"].append(copy.deepcopy(unit["items"][0]))


def swap_items(unit: dict[str, Any], _raw: dict[str, Any]) -> None:
    unit["items"].reverse()


def drop_key(path: list[Any]):
    def change(unit: dict[str, Any], _raw: dict[str, Any]) -> None:
        node: Any = unit
        for key in path[:-1]:
            node = node[key]
        del node[path[-1]]

    return change


ERROR_TAMPERS = {
    "amount up": set_value(["amount", "value"], "82.00"),
    "item_total up": set_value(["amount", "breakdown", "item_total", "value"], "78.00"),
    "tax_total up": set_value(["amount", "breakdown", "tax_total", "value"], "8.00"),
    "shipping up": set_value(["amount", "breakdown", "shipping", "value"], "6.00"),
    "quantity changed": set_value(["items", 0, "quantity"], "3"),
    "unit price changed": set_value(["items", 0, "unit_amount", "value"], "26.00"),
    "tax changed": set_value(["items", 1, "tax", "value"], "2.00"),
    "quantity zero": set_value(["items", 0, "quantity"], "0"),
    "quantity text": set_value(["items", 0, "quantity"], "1e1"),
    "quantity leading zero": set_value(["items", 0, "quantity"], "02"),
    "quantity fullwidth digit": set_value(["items", 0, "quantity"], "\uff12"),
    "quantity spaced": set_value(["items", 0, "quantity"], " 2"),
    "amount currency only": set_value(["amount", "currency_code"], "EUR"),
    "item currency only": set_value(["items", 0, "unit_amount", "currency_code"], "EUR"),
    "tax currency only": set_value(["items", 0, "tax", "currency_code"], "EUR"),
    "breakdown currency only": set_value(
        ["amount", "breakdown", "shipping", "currency_code"], "EUR"
    ),
    "item removed": remove_item,
    "item added": add_item,
    "insurance added": set_value(
        ["amount", "breakdown", "insurance"], {"currency_code": "USD", "value": "0.00"}
    ),
    "shipping discount added": set_value(
        ["amount", "breakdown", "shipping_discount"], {"currency_code": "USD", "value": "0.00"}
    ),
    "item_total missing": drop_key(["amount", "breakdown", "item_total"]),
    "tax_total missing": drop_key(["amount", "breakdown", "tax_total"]),
    "breakdown missing": drop_key(["amount", "breakdown"]),
    "invoice_id missing": drop_key(["invoice_id"]),
    "custom_id missing": drop_key(["custom_id"]),
    "payee missing": drop_key(["payee"]),
    "payee id missing": set_value(["payee"], {}),
    "sku missing": drop_key(["items", 0, "sku"]),
    "name missing": drop_key(["items", 0, "name"]),
    "empty invoice_id": set_value(["invoice_id"], ""),
    "zero discount": set_value(["amount", "breakdown", "discount", "value"], "0.00"),
    "amount not decimal": set_value(["amount", "value"], "81.0.0"),
    "amount as float": set_value(["amount", "value"], 81.0),
}


@pytest.mark.parametrize("name", ERROR_TAMPERS)
def test_tampered_order_is_an_error(name: str) -> None:
    raw = mutate(rich_checkout(), ERROR_TAMPERS[name])
    assert outcome(raw) == "error"


def test_an_extra_purchase_unit_is_an_error() -> None:
    raw = live(rich_checkout())
    raw["purchase_units"].append(copy.deepcopy(raw["purchase_units"][0]))
    assert outcome(raw) == "error"


def test_a_wrong_intent_is_an_error() -> None:
    raw = live(rich_checkout())
    raw["intent"] = "CAPTURE"
    assert outcome(raw) == "error"


def test_line_ids_that_do_not_match_the_items_are_an_error() -> None:
    raw = live(rich_checkout())
    assert outcome(raw, ["li_1"]) == "error"
    assert outcome(raw, ["li_1", "li_2", "li_3"]) == "error"
    assert outcome(raw, ["li_1", "li_1"]) == "error"  # duplicate ids


def test_swapped_identifying_fields_change_the_terms() -> None:
    checkout = rich_checkout()
    for path, value in (
        (["items", 0, "name"], "Other"),
        (["items", 0, "sku"], "sku-z"),
        (["invoice_id"], "chk_other"),
        (["custom_id"], "cs1.other"),
        (["payee", "merchant_id"], "ATTACKER"),
    ):
        raw = mutate(checkout, set_value(path, value))
        assert outcome(raw) not in ("error", original(checkout)), path


def test_items_in_a_different_order_change_the_terms() -> None:
    checkout = rich_checkout()
    assert outcome(mutate(checkout, swap_items)) != original(checkout)


def test_whole_order_currency_change_changes_the_terms_or_errors() -> None:
    checkout = rich_checkout()
    assert outcome(mutate(checkout, set_all_currencies("EUR"))) != original(checkout)


def test_tax_moved_between_lines_changes_the_terms() -> None:
    a = Item(id="a", title="A", price=usd(1000))
    b = Item(id="b", title="B", price=usd(1000))

    def build(tax_a: int, tax_b: int) -> Checkout:
        lines = []
        for line_id, item, tax in (("li_1", a, tax_a), ("li_2", b, tax_b)):
            totals = [Total(type="subtotal", amount=usd(1000))]
            if tax:
                totals.append(Total(type="tax", amount=usd(tax)))
            totals.append(Total(type="total", amount=usd(1000 + tax)))
            lines.append(LineItem(id=line_id, item=item, quantity=1, totals=tuple(totals)))
        return Checkout(
            id="c",
            currency="USD",
            line_items=tuple(lines),
            totals=(
                Total(type="subtotal", amount=usd(2000)),
                Total(type="tax", amount=usd(tax_a + tax_b)),
                Total(type="total", amount=usd(2000 + tax_a + tax_b)),
            ),
        )

    first, moved = build(200, 100), build(100, 200)
    assert first.terms_hash() != moved.terms_hash()
    # The same PayPal totals, with the tax on the other line: only the per-item tax differs.
    raw = live(first)
    raw["purchase_units"][0]["items"] = live(moved)["purchase_units"][0]["items"]
    assert outcome(raw) == reverse(live(moved), ["li_1", "li_2"]).terms_hash()
    assert outcome(raw) != reverse(live(first), ["li_1", "li_2"]).terms_hash()


def test_quantity_changed_with_matching_totals_changes_the_terms() -> None:
    checkout = plain_checkout()  # li_2 has quantity 2
    raw = live(checkout)
    unit = raw["purchase_units"][0]
    unit["items"][1]["quantity"] = "3"
    unit["amount"]["breakdown"]["item_total"]["value"] = "52.00"
    unit["amount"]["value"] = "52.00"
    changed = outcome(raw)
    assert changed != "error" and changed != original(checkout)


def test_fields_paypal_may_add_are_not_relied_on() -> None:
    raw = live(rich_checkout())
    raw["purchase_units"][0]["shipping"] = {"name": {"full_name": "X"}}
    raw["purchase_units"][0]["items"][0]["category"] = "PHYSICAL_GOODS"
    raw["payer"] = {"email_address": "x@example.com"}
    assert outcome(raw) == original(rich_checkout())


def test_translation_error_is_a_value_error_with_a_code() -> None:
    assert TranslationError.code == "paypal_translation"
    assert issubclass(TranslationError, ValueError)


@pytest.mark.parametrize(
    "name",
    ["amount currency only", "item currency only", "tax currency only", "breakdown currency only"],
)
def test_a_currency_mismatch_is_named_as_such(name: str) -> None:
    raw = mutate(rich_checkout(), ERROR_TAMPERS[name])
    with pytest.raises(TranslationError, match=r"is in [A-Z]{3}, the order is in [A-Z]{3}"):
        reverse(raw)


# ---------------------------------------------------------------- the request model's new fields


def request_with(**extra: Any):
    from countersign.paypal.models import OrderItem, OrderRequest

    return OrderRequest(
        amount=extra.pop("amount"),
        invoice_id="c",
        custom_id="x",
        items=(OrderItem("n", 1, usd(1000), sku="s"),),
        experience_context=CONTEXT,
        **extra,
    )


def test_order_request_breakdown_must_add_up_with_shipping_handling_and_discount() -> None:
    from countersign.paypal.limits import LimitError

    good = request_with(amount=usd(1150), shipping=usd(300), handling=usd(50), discount=usd(200))
    assert good.to_json()["purchase_units"][0]["amount"]["value"] == "11.50"
    for amount in (usd(1149), usd(1151), usd(1000)):
        with pytest.raises(LimitError, match="breakdown total"):
            request_with(amount=amount, shipping=usd(300), handling=usd(50), discount=usd(200))


def test_order_request_refuses_negative_or_foreign_currency_extras() -> None:
    from countersign.paypal.limits import LimitError

    with pytest.raises(LimitError, match="non-negative"):
        request_with(amount=usd(900), discount=usd(-100))
    with pytest.raises(LimitError, match="non-negative"):
        request_with(amount=usd(1100), shipping=Money("EUR", 100))
