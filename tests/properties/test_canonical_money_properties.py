"""Properties of Money across every supported currency."""

from __future__ import annotations

import re

from hypothesis import given
from hypothesis import strategies as st

from countersign.canonical.money import (
    MAX_MINOR,
    PAYPAL_CURRENCIES,
    InexactAmountError,
    Money,
    MoneyError,
    format_decimal,
    iso_exponent,
    parse_decimal,
    paypal_exponent,
)

currencies = st.sampled_from(sorted(PAYPAL_CURRENCIES))
minors = st.integers(min_value=-MAX_MINOR, max_value=MAX_MINOR)
small = st.integers(min_value=-(10**9), max_value=10**9)


def scale(currency: str) -> int:
    return 10 ** (iso_exponent(currency) - paypal_exponent(currency))


@given(currencies, minors)
def test_paypal_round_trip_is_exact_or_refused_never_rounded(currency, minor):
    money = Money(currency, minor)
    if minor % scale(currency):
        try:
            money.to_paypal()
        except InexactAmountError:
            return
        raise AssertionError("an inexact amount was formatted")
    text = money.to_paypal()
    assert Money.from_paypal(text, currency, allow_negative=True) == money


@given(currencies, minors)
def test_paypal_text_has_exactly_the_exponent_decimal_places(currency, minor):
    minor -= minor % scale(currency)
    text = Money(currency, minor).to_paypal()
    exponent = paypal_exponent(currency)
    pattern = r"-?(0|[1-9][0-9]*)" + (rf"\.[0-9]{{{exponent}}}" if exponent else "")
    assert re.fullmatch(pattern, text)
    assert len(text) <= 32


@given(currencies, st.integers(min_value=0, max_value=MAX_MINOR))
def test_ucp_round_trip(currency, minor):
    assert Money.from_ucp(minor, currency).to_ucp() == minor


@given(minors, st.integers(min_value=0, max_value=6))
def test_core_format_parse_round_trip_at_every_exponent(minor, exponent):
    text = format_decimal(minor, exponent)
    assert parse_decimal(text, exponent, allow_negative=True) == minor
    if exponent:
        assert len(text.split(".")[1]) == exponent
    else:
        assert "." not in text


@given(
    currencies,
    st.integers(min_value=0, max_value=10**9),
    st.integers(min_value=1, max_value=4),
    st.data(),
)
def test_excess_precision_is_always_inexact(currency, whole, extra, data):
    exponent = paypal_exponent(currency)
    digits = data.draw(
        st.text(alphabet="0123456789", min_size=exponent + extra, max_size=exponent + extra)
    )
    text = f"{whole}.{digits}"
    try:
        Money.from_paypal(text, currency)
    except InexactAmountError:
        return
    raise AssertionError(f"{text} was accepted for {currency}")


@given(currencies, st.lists(small, max_size=30), st.randoms(use_true_random=False))
def test_sums_are_exact_and_order_independent(currency, amounts, rng):
    items = [Money(currency, a) for a in amounts]
    total = Money.sum(items, currency)
    assert total.minor == sum(amounts)  # Python ints are exact
    shuffled = list(items)
    rng.shuffle(shuffled)
    assert Money.sum(shuffled, currency) == total


@given(currencies, small, small, small)
def test_addition_laws(currency, a, b, c):
    x, y, z = Money(currency, a), Money(currency, b), Money(currency, c)
    assert x + y == y + x
    assert (x + y) + z == x + (y + z)
    assert x + Money.zero(currency) == x
    assert (x + y) - y == x
    assert x + (-x) == Money.zero(currency)


@given(currencies, small, small)
def test_ordering_matches_integer_ordering(currency, a, b):
    x, y = Money(currency, a), Money(currency, b)
    assert (x < y) == (a < b)
    assert (x <= y) == (a <= b)
    assert (x == y) == (a == b)


@given(currencies, small, st.integers(min_value=0, max_value=1000))
def test_multiplication_is_repeated_addition(currency, a, n):
    x = Money(currency, a)
    assert x * n == Money.sum([x] * n, currency)


@given(currencies, st.text(alphabet="0123456789 +-.,eE_$\n\t １", max_size=12))
def test_text_either_fails_with_a_money_error_or_is_a_canonical_decimal(currency, text):
    try:
        money = Money.from_paypal(text, currency, allow_negative=True)
    except MoneyError:
        return
    # Accepted text is plain ASCII digits with at most one dot and an optional leading minus,
    # and re-formatting reproduces the same value.
    assert re.fullmatch(r"-?(0|[1-9][0-9]*)(\.[0-9]+)?", text)
    assert text == text.strip()
    again = Money.from_paypal(money.to_paypal(), currency, allow_negative=True)
    assert again == money
