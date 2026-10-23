"""Any selection of catalog items becomes a consistent canonical checkout."""

from __future__ import annotations

from hypothesis import given
from hypothesis import strategies as st

from countersign.canonical.models import Checkout
from countersign.catalog import load_catalog

CATALOG = load_catalog()


@given(
    st.lists(
        st.tuples(st.sampled_from(CATALOG.items), st.integers(min_value=1, max_value=9)),
        min_size=1,
        max_size=8,
    )
)
def test_any_selection_builds_a_consistent_checkout(selection):
    lines = [(f"l{n}", entry.to_item(), qty) for n, (entry, qty) in enumerate(selection)]
    checkout = Checkout.from_lines("chk", "USD", lines)
    assert checkout.totals[-1].amount.minor == sum(e.price.minor * q for e, q in selection)
    assert Checkout.from_ucp(checkout.to_ucp()).terms_hash() == checkout.terms_hash()


@given(st.sampled_from(CATALOG.items), st.integers(min_value=1, max_value=9))
def test_changing_a_catalog_price_changes_the_checkout_hash(entry, qty):
    base = Checkout.from_lines("chk", "USD", [("l", entry.to_item(), qty)])
    item = entry.to_item()
    bumped = item.model_copy(update={"price": type(item.price)("USD", item.price.minor + 1)})
    other = Checkout.from_lines("chk", "USD", [("l", bumped, qty)])
    assert other.terms_hash() != base.terms_hash()
