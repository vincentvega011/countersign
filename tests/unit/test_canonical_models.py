"""Canonical checkout model: consistency rules, rejections and the terms hash."""

from __future__ import annotations

import copy
import hashlib

import pytest
from pydantic import ValidationError

from countersign.canonical import canonicalize, domain_hash
from countersign.canonical.models import (
    MAX_TEXT,
    Checkout,
    EachQuantityUnit,
    Item,
    LineItem,
    Total,
    UcpShapeError,
)
from countersign.canonical.money import MAX_MINOR, Money, MoneyError


def usd(minor: int) -> Money:
    return Money("USD", minor)


def checkout() -> Checkout:
    """Two lines, a shipping charge and a tax line: subtotal 6850, total 7500."""
    phones = Item(id="hp-1", title="Orbit Wired Headphones", price=usd(2500))
    cable = Item(id="cb-1", title="USB-C Cable 1 m", price=usd(1850))
    return Checkout.from_lines(
        "chk_1",
        "USD",
        [("li_1", phones, 2), ("li_2", cable, 1)],
        [
            Total(type="fulfillment", amount=usd(400), display_text="Shipping"),
            Total(type="tax", amount=usd(250)),
        ],
    )


def ucp() -> dict:
    return copy.deepcopy(checkout().to_ucp())


# ---- the happy path ----


def test_from_lines_builds_the_expected_totals():
    c = checkout()
    assert [(t.type, t.amount.minor) for t in c.totals] == [
        ("subtotal", 6850),
        ("fulfillment", 400),
        ("tax", 250),
        ("total", 7500),
    ]
    assert [(t.type, t.amount.minor) for t in c.line_items[0].totals] == [
        ("subtotal", 5000),
        ("total", 5000),
    ]


def test_ucp_round_trip():
    c = checkout()
    assert Checkout.from_ucp(c.to_ucp()) == c
    assert Checkout.from_ucp(c.to_ucp()).canonical_bytes() == c.canonical_bytes()


def test_to_ucp_is_plain_json_with_integer_amounts():
    def walk(node):
        if isinstance(node, dict):
            for v in node.values():
                walk(v)
        elif isinstance(node, list):
            for v in node:
                walk(v)
        else:
            assert type(node) in (int, str), node

    walk(checkout().to_ucp())


def test_top_level_members_that_are_not_terms_are_ignored_by_from_ucp():
    data = ucp()
    data.update(
        {"status": "ready_for_complete", "links": [], "ucp": {"version": "x"}, "messages": []}
    )
    assert Checkout.from_ucp(data) == checkout()


def test_line_discounts_roll_up_into_the_order_items_discount():
    item = Item(id="a", title="A", price=usd(1000))
    line = LineItem(
        id="l",
        item=item,
        quantity=2,
        totals=(
            Total(type="subtotal", amount=usd(2000)),
            Total(type="items_discount", amount=usd(-300)),
            Total(type="total", amount=usd(1700)),
        ),
    )
    c = Checkout(
        id="c",
        currency="USD",
        line_items=(line,),
        totals=(
            Total(type="subtotal", amount=usd(2000)),
            Total(type="items_discount", amount=usd(-300)),
            Total(type="total", amount=usd(1700)),
        ),
    )
    assert c.totals[-1].amount.minor == 1700


# ---- consistency rules: each broken in turn ----


def reject(mutator, match: str | None = None):
    data = ucp()
    mutator(data)
    with pytest.raises((ValidationError, ValueError)) as info:
        Checkout.from_ucp(data)
    if match:
        assert match in str(info.value)


def test_line_subtotal_must_be_price_times_quantity():
    def consistent_but_wrong(d):
        # Keep subtotal and total equal to each other, so only price times quantity is violated.
        d["line_items"][0]["totals"][0]["amount"] = 5001
        d["line_items"][0]["totals"][1]["amount"] = 5001

    reject(consistent_but_wrong, "unit price times quantity")
    reject(lambda d: d["line_items"][0].update(quantity=3), "unit price times quantity")
    reject(lambda d: d["line_items"][0]["item"].update(price=2501), "unit price times quantity")


def test_line_total_must_equal_the_sum_of_its_entries():
    reject(lambda d: d["line_items"][0]["totals"][1].update(amount=5001), "does not equal the sum")


def test_line_totals_need_exactly_one_subtotal_and_one_total():
    reject(lambda d: d["line_items"][0]["totals"].pop(0), "exactly one subtotal")
    reject(lambda d: d["line_items"][0]["totals"].pop(1), "exactly one total")
    reject(
        lambda d: d["line_items"][0]["totals"].append({"type": "total", "amount": 5000}),
        "exactly one total",
    )
    reject(
        lambda d: d["line_items"][0]["totals"].append({"type": "subtotal", "amount": 0}),
        "exactly one subtotal",
    )


def test_order_total_must_equal_the_sum_of_its_entries():
    reject(lambda d: d["totals"][-1].update(amount=7501), "does not equal the sum")
    reject(lambda d: d["totals"][1].update(amount=401), "does not equal the sum")
    reject(lambda d: d["totals"].pop(1), "does not equal the sum")


def test_order_totals_need_exactly_one_subtotal_and_one_total():
    reject(lambda d: d["totals"].pop(0), "exactly one subtotal")
    reject(lambda d: d["totals"].pop(), "exactly one total")
    reject(
        lambda d: d["totals"].insert(1, {"type": "subtotal", "amount": 0}), "exactly one subtotal"
    )
    reject(lambda d: d["totals"].insert(1, {"type": "total", "amount": 0}), "exactly one total")


def test_order_subtotal_must_be_the_sum_of_line_subtotals():
    def lower(d):
        d["totals"][0]["amount"] = 6849
        d["totals"][-1]["amount"] = 7499

    reject(lower, "sum of the line item subtotals")


def test_order_items_discount_must_roll_up_the_line_discounts():
    def add(d):
        d["totals"].insert(1, {"type": "items_discount", "amount": -100})
        d["totals"][-1]["amount"] = 7400

    reject(add, "items_discount")


def test_signs_follow_the_ucp_rules():
    def positive_discount(d):
        d["totals"].insert(1, {"type": "discount", "amount": 100})
        d["totals"][-1]["amount"] = 7600

    reject(positive_discount, "must be negative")

    def zero_discount(d):
        d["totals"].insert(1, {"type": "discount", "amount": 0})

    reject(zero_discount, "must be negative")

    def negative_tax(d):
        d["totals"][2]["amount"] = -250
        d["totals"][-1]["amount"] = 7000

    reject(negative_tax, "must not be negative")
    reject(lambda d: d["totals"][-1].update(amount=-1), "must not be negative")


def test_a_negative_order_discount_is_accepted():
    data = ucp()
    data["totals"].insert(1, {"type": "discount", "amount": -500})
    data["totals"][-1]["amount"] = 7000
    assert Checkout.from_ucp(data).totals[-1].amount.minor == 7000


def test_all_amounts_must_share_the_checkout_currency():
    item_eur = Item(id="a", title="A", price=Money("EUR", 100))
    with pytest.raises((ValidationError, MoneyError)):
        Checkout.from_lines("c", "USD", [("l", item_eur, 1)])

    good = checkout()
    mixed = good.model_dump()  # not used for construction; build a mixed total directly instead
    del mixed
    with pytest.raises(ValidationError, match="checkout currency"):
        Checkout(
            id="c",
            currency="USD",
            line_items=good.line_items,
            totals=(
                Total(type="subtotal", amount=Money("EUR", 6850)),
                Total(type="total", amount=Money("EUR", 6850)),
            ),
        )
    item = Item(id="a", title="A", price=usd(100))
    with pytest.raises(ValidationError, match="item's currency"):
        LineItem(
            id="l",
            item=item,
            quantity=1,
            totals=(
                Total(type="subtotal", amount=Money("EUR", 100)),
                Total(type="total", amount=Money("EUR", 100)),
            ),
        )


def test_line_items_in_another_currency_are_rejected_by_the_checkout():
    eur_item = Item(id="a", title="A", price=Money("EUR", 100))
    eur_line = LineItem(
        id="l",
        item=eur_item,
        quantity=1,
        totals=(
            Total(type="subtotal", amount=Money("EUR", 100)),
            Total(type="total", amount=Money("EUR", 100)),
        ),
    )
    with pytest.raises(ValidationError, match="every line item must use the checkout currency"):
        Checkout(
            id="c",
            currency="USD",
            line_items=(eur_line,),
            totals=(
                Total(type="subtotal", amount=usd(100)),
                Total(type="total", amount=usd(100)),
            ),
        )


def test_unsupported_checkout_currency_is_rejected():
    reject(lambda d: d.update(currency="KWD"))
    reject(lambda d: d.update(currency="usd"))


def test_line_item_ids_must_be_unique():
    reject(lambda d: d["line_items"][1].update(id="li_1"), "unique")


def test_at_least_one_line_item():
    with pytest.raises(ValidationError):
        Checkout(id="c", currency="USD", line_items=(), totals=checkout().totals)


@pytest.mark.parametrize("quantity", [0, -1, MAX_MINOR + 1, True, 2.0, "2", None])
def test_quantity_must_be_a_positive_integer(quantity):
    reject(lambda d: d["line_items"][0].update(quantity=quantity))


def test_amount_must_be_an_integer_not_a_float_bool_or_string():
    for bad in (74.5, 74.0, True, "74", None):
        reject(lambda d, bad=bad: d["totals"][0].update(amount=bad))
        reject(lambda d, bad=bad: d["line_items"][0]["item"].update(price=bad))


def test_negative_item_price_is_rejected():
    reject(lambda d: d["line_items"][0]["item"].update(price=-1))


def test_text_lengths():
    ok = "x" * MAX_TEXT
    data = ucp()
    data["line_items"][0]["item"].update(id=ok, title=ok)
    Checkout.from_ucp(data)
    reject(lambda d: d["line_items"][0]["item"].update(title="x" * (MAX_TEXT + 1)))
    reject(lambda d: d["line_items"][0]["item"].update(id="x" * (MAX_TEXT + 1)))
    reject(lambda d: d["line_items"][0]["item"].update(title=""))
    reject(lambda d: d["line_items"][0]["item"].update(id=""))
    reject(lambda d: d.update(id=""))


def test_unknown_total_type_is_rejected():
    reject(lambda d: d["totals"].insert(1, {"type": "handling", "display_text": "H", "amount": 5}))


# ---- non-each quantity units ----


@pytest.mark.parametrize(
    "unit",
    [
        {"unit": "KGM", "scale": 2, "display_text": "kg"},
        {"unit": "LBR", "display_text": "lb"},
        {"unit": "HUR", "scale": 0, "display_text": "hour"},
        {"unit": "C62", "scale": 2, "display_text": "pieces"},
        {"unit": "each", "display_text": "each"},
        {"unit": "c62", "display_text": "each"},
    ],
)
def test_non_each_quantity_unit_is_rejected_not_priced(unit):
    data = ucp()
    data["line_items"][0]["item"]["quantity_unit"] = unit
    with pytest.raises(ValidationError, match="non-each quantity_unit"):
        Checkout.from_ucp(data)


def test_explicit_each_is_accepted_and_changes_nothing_in_the_terms():
    plain = checkout()
    data = ucp()
    data["line_items"][0]["item"]["quantity_unit"] = {
        "unit": "C62",
        "scale": 0,
        "display_text": "each",
        "increment": 2,
    }
    with_unit = Checkout.from_ucp(data)
    assert with_unit.line_items[0].item.quantity_unit == EachQuantityUnit(
        unit="C62", scale=0, display_text="each", increment=2
    )
    assert with_unit.terms() == plain.terms()
    assert with_unit.terms_hash() == plain.terms_hash()
    assert with_unit.canonical_bytes() != plain.canonical_bytes()
    data["line_items"][0]["item"]["quantity_unit"] = {"unit": "C62", "display_text": "each"}
    assert Checkout.from_ucp(data).terms_hash() == plain.terms_hash()


def test_quantity_unit_scale_zero_must_really_be_an_int():
    data = ucp()
    data["line_items"][0]["item"]["quantity_unit"] = {
        "unit": "C62",
        "scale": False,
        "display_text": "each",
    }
    with pytest.raises((ValidationError, ValueError)):
        Checkout.from_ucp(data)


# ---- extra fields, strictness, immutability ----


def test_unknown_members_are_rejected_at_every_nested_level():
    reject(lambda d: d["line_items"][0].update(parent_id="x"), "parent_id")
    reject(
        lambda d: d["line_items"][0]["item"].update(image_url="https://example.com/x.png"),
        "image_url",
    )
    reject(lambda d: d["line_items"][0]["item"].update(unit_price={"amount": 1}), "unit_price")
    reject(lambda d: d["line_items"][0].update(sku="x"), "sku")
    reject(lambda d: d["totals"][0].update(lines=[{"display_text": "a", "amount": 1}]), "lines")
    reject(lambda d: d["totals"][0].update(note="x"), "note")
    data = ucp()
    data["line_items"][0]["item"]["quantity_unit"] = {
        "unit": "C62",
        "display_text": "e",
        "extra": 1,
    }
    with pytest.raises(ValidationError, match="extra"):
        Checkout.from_ucp(data)


def test_extra_fields_are_rejected_when_constructing_directly():
    c = checkout()
    with pytest.raises(ValidationError, match="Extra inputs"):
        Checkout(**{**c.__dict__, "buyer": "x"})
    with pytest.raises(ValidationError, match="Extra inputs"):
        Item(id="a", title="A", price=usd(1), sku="s")
    with pytest.raises(ValidationError, match="Extra inputs"):
        Total(type="tax", amount=usd(1), memo="m")
    with pytest.raises(ValidationError, match="Extra inputs"):
        LineItem(**{**c.line_items[0].__dict__, "note": "n"})
    with pytest.raises(ValidationError, match="Extra inputs"):
        EachQuantityUnit(unit="C62", display_text="e", memo="m")


def test_models_are_strict_about_types():
    with pytest.raises(ValidationError):
        Item(id="a", title="A", price=2500)  # type: ignore[arg-type]
    with pytest.raises(ValidationError):
        Total(type="tax", amount=250)  # type: ignore[arg-type]
    with pytest.raises(ValidationError):
        Item(id=1, title="A", price=usd(1))  # type: ignore[arg-type]
    with pytest.raises(ValidationError):
        LineItem(id="l", item=checkout().line_items[0].item, quantity="2", totals=())  # type: ignore[arg-type]


def test_models_are_frozen():
    c = checkout()
    with pytest.raises(ValidationError):
        c.id = "other"  # type: ignore[misc]
    with pytest.raises(ValidationError):
        c.line_items[0].quantity = 9  # type: ignore[misc]
    hash(c)


@pytest.mark.parametrize(
    "bad",
    [None, [], "x", 5, {"id": "c"}],
)
def test_wrong_shapes_raise_ucp_shape_error(bad):
    with pytest.raises((UcpShapeError, ValidationError)):
        Checkout.from_ucp(bad)  # type: ignore[arg-type]


def test_shape_errors_name_the_problem():
    for key in ("id", "currency", "line_items", "totals"):
        data = ucp()
        del data[key]
        with pytest.raises(UcpShapeError, match=key):
            Checkout.from_ucp(data)
    data = ucp()
    data["line_items"] = {"a": 1}
    with pytest.raises(UcpShapeError, match="array"):
        Checkout.from_ucp(data)
    data = ucp()
    data["line_items"][0] = "x"
    with pytest.raises(UcpShapeError, match="object"):
        Checkout.from_ucp(data)
    data = ucp()
    data["currency"] = 840
    with pytest.raises(UcpShapeError, match="currency"):
        Checkout.from_ucp(data)
    data = ucp()
    del data["line_items"][0]["item"]["price"]
    with pytest.raises(UcpShapeError, match="price"):
        Checkout.from_ucp(data)


def test_overflowing_amounts_are_rejected():
    big = Item(id="a", title="A", price=usd(MAX_MINOR))
    with pytest.raises(ValueError):
        Checkout.from_lines("c", "USD", [("l", big, 2)])
    two = [("l1", big, 1), ("l2", Item(id="b", title="B", price=usd(1)), 1)]
    with pytest.raises(ValueError):
        Checkout.from_lines("c", "USD", two)


# ---- terms and hashing ----


def test_terms_are_the_ucp_form_without_display_text_or_units():
    terms = checkout().terms()
    assert "display_text" not in repr(terms)
    assert "quantity_unit" not in repr(terms)
    assert terms["totals"][1] == {"type": "fulfillment", "amount": 400}
    assert list(terms) == ["id", "currency", "line_items", "totals"]


def test_terms_hash_is_domain_separated_sha256_of_the_jcs_terms():
    c = checkout()
    expected = domain_hash("cs.terms.v1", canonicalize(c.terms()))
    assert c.terms_hash() == expected
    assert len(c.terms_hash()) == 32
    assert c.terms_hash() != hashlib.sha256(c.terms_bytes()).digest()


def test_display_text_changes_canonical_bytes_but_not_the_terms_hash():
    a = checkout()
    data = ucp()
    data["totals"][1]["display_text"] = "Delivery"
    b = Checkout.from_ucp(data)
    assert a.terms_hash() == b.terms_hash()
    assert a.canonical_bytes() != b.canonical_bytes()


def test_totals_order_is_bound():
    data = ucp()
    data["totals"][1], data["totals"][2] = data["totals"][2], data["totals"][1]
    assert Checkout.from_ucp(data).terms_hash() != checkout().terms_hash()


def test_line_item_order_is_bound():
    data = ucp()
    data["line_items"].reverse()
    assert Checkout.from_ucp(data).terms_hash() != checkout().terms_hash()


def test_equal_checkouts_have_equal_hashes_regardless_of_construction_path():
    assert (
        checkout().terms_hash()
        == Checkout.from_ucp(copy.deepcopy(checkout().to_ucp())).terms_hash()
    )


# ---- bounds checked in isolation (the totals are made consistent so only the bound can fail) ----


def zero_line(quantity: int) -> LineItem:
    free = Item(id="free", title="Free sample", price=usd(0))
    return LineItem(
        id="l",
        item=free,
        quantity=quantity,
        totals=(Total(type="subtotal", amount=usd(0)), Total(type="total", amount=usd(0))),
    )


def test_quantity_bounds_hold_even_when_the_money_is_consistent():
    assert zero_line(1).quantity == 1
    assert zero_line(MAX_MINOR).quantity == MAX_MINOR
    for bad in (0, -1, MAX_MINOR + 1):
        with pytest.raises(ValidationError):
            zero_line(bad)


def test_a_checkout_needs_at_least_one_line_even_when_the_totals_are_consistent():
    zeros = (Total(type="subtotal", amount=usd(0)), Total(type="total", amount=usd(0)))
    with pytest.raises(ValidationError, match="at least 1"):
        Checkout(id="c", currency="USD", line_items=(), totals=zeros)
    Checkout(id="c", currency="USD", line_items=(zero_line(1),), totals=zeros)


def test_a_negative_item_price_is_rejected_by_the_item_itself():
    with pytest.raises(ValidationError, match="price must not be negative"):
        Item(id="a", title="A", price=usd(-1))
    Item(id="a", title="A", price=usd(0))
