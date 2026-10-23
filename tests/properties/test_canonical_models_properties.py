"""Properties of the canonical checkout: construction, round trips and hash binding."""

from __future__ import annotations

import copy
from collections.abc import Callable

import pytest
from hypothesis import assume, given
from hypothesis import strategies as st
from pydantic import ValidationError

from countersign.canonical.models import (
    Checkout,
    EachQuantityUnit,
    Item,
    LineItem,
    Total,
)
from countersign.canonical.money import Money, MoneyError

CURRENCIES = ["USD", "EUR", "JPY", "GBP", "HUF"]
text = st.text(min_size=1, max_size=20)


@st.composite
def checkouts(draw, *, positive_prices: bool = False):
    currency = draw(st.sampled_from(CURRENCIES))
    n = draw(st.integers(min_value=1, max_value=4))
    ids = draw(st.lists(text, min_size=n, max_size=n, unique=True))
    lines = []
    for i, line_id in enumerate(ids):
        price = draw(st.integers(min_value=1 if positive_prices else 0, max_value=100_000))
        item = Item(id=draw(text), title=draw(text), price=Money(currency, price))
        lines.append((line_id, item, draw(st.integers(min_value=1, max_value=20))))
    subtotal = sum(i.price.minor * q for _, i, q in lines)
    adjustments = []
    for kind in draw(st.lists(st.sampled_from(["fulfillment", "tax", "fee"]), max_size=3)):
        adjustments.append(
            Total(
                type=kind, amount=Money(currency, draw(st.integers(min_value=0, max_value=5_000)))
            )
        )
    if draw(st.booleans()) and subtotal > 1:
        cut = draw(st.integers(min_value=1, max_value=subtotal))
        adjustments.append(Total(type="discount", amount=Money(currency, -cut)))
    return Checkout.from_lines(draw(text), currency, lines, adjustments)


def other_currency(c: Checkout) -> str:
    return "EUR" if c.currency != "EUR" else "USD"


def bump(m: Money) -> Money:
    return Money(m.currency, m.minor + 1)


def replace_line(c: Checkout, index: int, **update) -> Checkout:
    lines = list(c.line_items)
    lines[index] = lines[index].model_copy(update=update)
    return c.model_copy(update={"line_items": tuple(lines)})


def replace_item(c: Checkout, **update) -> Checkout:
    line = c.line_items[0]
    return replace_line(c, 0, item=line.item.model_copy(update=update))


def replace_total(c: Checkout, index: int, **update) -> Checkout:
    totals = list(c.totals)
    totals[index] = totals[index].model_copy(update=update)
    return c.model_copy(update={"totals": tuple(totals)})


def replace_line_total(c: Checkout, **update) -> Checkout:
    line = c.line_items[0]
    entries = list(line.totals)
    entries[0] = entries[0].model_copy(update=update)
    return replace_line(c, 0, totals=tuple(entries))


# Amounts carry no currency of their own in the terms: the validator forces every amount to use the
# checkout currency, so only the checkout `currency` member is bound. Every change below touches a
# field that is part of the terms; none is validated, on purpose,
# because the property is about the hash, not about whether the result is a legal checkout.
BOUND_CHANGES: dict[str, Callable[[Checkout], Checkout]] = {
    "checkout id": lambda c: c.model_copy(update={"id": c.id + "x"}),
    "currency": lambda c: c.model_copy(update={"currency": other_currency(c)}),
    "line id": lambda c: replace_line(c, 0, id=c.line_items[0].id + "x"),
    "item id": lambda c: replace_item(c, id=c.line_items[0].item.id + "x"),
    "item title": lambda c: replace_item(c, title=c.line_items[0].item.title + "x"),
    "item price": lambda c: replace_item(c, price=bump(c.line_items[0].item.price)),
    "quantity": lambda c: replace_line(c, 0, quantity=c.line_items[0].quantity + 1),
    "line total amount": lambda c: replace_line_total(
        c, amount=bump(c.line_items[0].totals[0].amount)
    ),
    "line total type": lambda c: replace_line_total(c, type="fee"),
    "order total amount": lambda c: replace_total(c, 0, amount=bump(c.totals[0].amount)),
    "order total type": lambda c: replace_total(c, 0, type="fee"),
    "final total amount": lambda c: replace_total(c, -1, amount=bump(c.totals[-1].amount)),
    "totals order": lambda c: c.model_copy(
        update={"totals": (c.totals[1], c.totals[0], *c.totals[2:])}
    ),
    "drop a total": lambda c: c.model_copy(update={"totals": c.totals[:-1]}),
    "extra total": lambda c: c.model_copy(update={"totals": (*c.totals, c.totals[0])}),
    "drop a line": lambda c: c.model_copy(
        update={"line_items": c.line_items[1:] or c.line_items * 2}
    ),
    "duplicate a line": lambda c: c.model_copy(
        update={"line_items": (*c.line_items, c.line_items[0])}
    ),
}


@given(checkouts(), st.sampled_from(sorted(BOUND_CHANGES)))
def test_any_change_to_a_bound_field_changes_the_hash_and_the_bytes(c, change):
    changed = BOUND_CHANGES[change](c)
    assert changed.terms_hash() != c.terms_hash(), change
    assert changed.terms_bytes() != c.terms_bytes(), change
    assert changed.canonical_bytes() != c.canonical_bytes(), change


@given(checkouts().filter(lambda c: len(c.line_items) >= 2))
def test_reordering_line_items_changes_the_hash(c):
    reordered = c.model_copy(update={"line_items": tuple(reversed(c.line_items))})
    assert reordered.terms_hash() != c.terms_hash()


@given(checkouts(), st.text(min_size=1, max_size=10))
def test_display_text_is_not_a_term_but_is_in_the_canonical_bytes(c, label):
    changed = replace_total(c, 0, display_text=label)
    assume(c.totals[0].display_text != label)
    assert changed.terms_hash() == c.terms_hash()
    assert changed.canonical_bytes() != c.canonical_bytes()


@given(checkouts())
def test_an_explicit_each_unit_is_not_a_term(c):
    unit = EachQuantityUnit(unit="C62", scale=0, display_text="each")
    changed = replace_item(c, quantity_unit=unit)
    assert changed.terms_hash() == c.terms_hash()
    assert changed.canonical_bytes() != c.canonical_bytes()


@given(checkouts())
def test_ucp_round_trip_preserves_everything(c):
    again = Checkout.from_ucp(c.to_ucp())
    assert again == c
    assert again.terms_hash() == c.terms_hash()
    assert again.canonical_bytes() == c.canonical_bytes()


@given(checkouts())
def test_built_checkouts_satisfy_the_arithmetic_independently(c):
    line_subtotals = [li.item.price.minor * li.quantity for li in c.line_items]
    assert [li.totals[0].amount.minor for li in c.line_items] == line_subtotals
    assert c.totals[0].amount.minor == sum(line_subtotals)
    assert c.totals[-1].amount.minor == sum(t.amount.minor for t in c.totals[:-1])
    assert c.totals[-1].amount.minor >= 0


@given(checkouts(positive_prices=True), st.data())
def test_no_single_amount_can_be_tampered_with_and_still_validate(c, data):
    """Change one amount by one minor unit in the UCP form, fix nothing else: it must fail."""
    raw = c.to_ucp()
    paths: list[tuple] = []
    for i, line in enumerate(raw["line_items"]):
        paths.append(("line_items", i, "item", "price"))
        paths.append(("line_items", i, "quantity"))
        paths += [("line_items", i, "totals", j, "amount") for j in range(len(line["totals"]))]
    paths += [("totals", j, "amount") for j in range(len(raw["totals"]))]
    path = data.draw(st.sampled_from(paths))
    delta = data.draw(st.sampled_from([1, -1]))

    tampered = copy.deepcopy(raw)
    node = tampered
    for step in path[:-1]:
        node = node[step]
    node[path[-1]] += delta
    with pytest.raises((ValidationError, MoneyError, ValueError)):
        Checkout.from_ucp(tampered)


@given(checkouts(), st.data())
def test_replacing_any_total_type_with_another_never_validates_silently(c, data):
    raw = c.to_ucp()
    index = data.draw(st.integers(min_value=0, max_value=len(raw["totals"]) - 1))
    other = data.draw(st.sampled_from(["subtotal", "total", "fulfillment", "tax", "fee"]))
    assume(raw["totals"][index]["type"] != other)
    raw["totals"][index]["type"] = other
    try:
        changed = Checkout.from_ucp(raw)
    except (ValidationError, MoneyError, ValueError):
        return
    # If it validates, it must be because the retyped entry was interchangeable, and then the
    # hash must still tell the two apart.
    assert changed.terms_hash() != c.terms_hash()


@given(checkouts())
def test_line_item_totals_are_a_pure_function_of_price_and_quantity(c):
    for line in c.line_items:
        rebuilt = LineItem(
            id=line.id,
            item=line.item,
            quantity=line.quantity,
            totals=(
                Total(type="subtotal", amount=line.item.price * line.quantity),
                Total(type="total", amount=line.item.price * line.quantity),
            ),
        )
        assert rebuilt == line
