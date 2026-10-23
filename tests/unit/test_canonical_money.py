"""Money: exact conversion, strict decimal grammar, no floats in the public surface."""

from __future__ import annotations

import ast
import inspect
import typing
from decimal import Decimal
from pathlib import Path

import pytest

import countersign.canonical.money as money_module
from countersign.canonical.money import (
    ISO_EXPONENTS,
    MAX_MINOR,
    PAYPAL_CURRENCIES,
    PAYPAL_ZERO_DECIMAL,
    AmountOutOfRangeError,
    CurrencyMismatchError,
    InexactAmountError,
    InvalidAmountError,
    Money,
    MoneyError,
    UnsupportedCurrencyError,
    check_currency,
    format_decimal,
    iso_exponent,
    parse_decimal,
    paypal_exponent,
)

PAYPAL_LIST = [
    "AUD",
    "BRL",
    "CAD",
    "CNY",
    "CZK",
    "DKK",
    "EUR",
    "HKD",
    "HUF",
    "ILS",
    "JPY",
    "MYR",
    "MXN",
    "TWD",
    "NZD",
    "NOK",
    "PHP",
    "PLN",
    "GBP",
    "RUB",
    "SGD",
    "SEK",
    "CHF",
    "THB",
    "USD",
]


# ---- tables ----


def test_supported_set_is_paypals_list():
    assert PAYPAL_CURRENCIES == frozenset(PAYPAL_LIST)
    assert len(PAYPAL_CURRENCIES) == 25


def test_iso_exponents_known_values():
    assert iso_exponent("USD") == 2
    assert iso_exponent("JPY") == 0
    assert iso_exponent("KRW") == 0
    assert iso_exponent("KWD") == 3
    assert iso_exponent("BHD") == 3
    assert iso_exponent("CLF") == 4
    # ISO 4217 gives HUF and TWD two decimals even though PayPal accepts whole numbers only.
    assert iso_exponent("HUF") == 2
    assert iso_exponent("TWD") == 2


def test_metals_and_test_codes_have_no_exponent():
    for code in ("XAU", "XAG", "XXX", "XDR"):
        with pytest.raises(UnsupportedCurrencyError):
            iso_exponent(code)


def test_every_supported_currency_has_an_iso_entry_and_paypal_exponent_never_exceeds_it():
    for code in PAYPAL_CURRENCIES:
        assert code in ISO_EXPONENTS
        assert 0 <= paypal_exponent(code) <= iso_exponent(code) <= 2


def test_paypal_zero_decimal_currencies():
    assert PAYPAL_ZERO_DECIMAL == {"HUF", "JPY", "TWD"}
    for code in PAYPAL_ZERO_DECIMAL:
        assert paypal_exponent(code) == 0
    for code in PAYPAL_CURRENCIES - PAYPAL_ZERO_DECIMAL:
        assert paypal_exponent(code) == 2


@pytest.mark.parametrize(
    "bad", ["KWD", "BHD", "XAU", "usd", "US", "USDX", " USD", "", "U$D", "USD "]
)
def test_unsupported_or_malformed_currency_is_rejected(bad):
    with pytest.raises(UnsupportedCurrencyError):
        check_currency(bad)
    with pytest.raises(UnsupportedCurrencyError):
        Money(bad, 1)


@pytest.mark.parametrize("bad", [None, 840, b"USD", ["USD"]])
def test_non_string_currency_is_rejected(bad):
    with pytest.raises(UnsupportedCurrencyError):
        check_currency(bad)  # type: ignore[arg-type]


# ---- PayPal decimal strings ----


@pytest.mark.parametrize(
    "text, currency, minor",
    [
        ("74.00", "USD", 7400),
        ("74", "USD", 7400),
        ("74.5", "USD", 7450),
        ("0", "USD", 0),
        ("0.00", "USD", 0),
        ("0.01", "USD", 1),
        ("1000", "JPY", 1000),
        ("0", "JPY", 0),
        ("10", "HUF", 1000),  # ISO minor units: 10.00 forint
        ("10", "TWD", 1000),
        ("9007199254740991", "JPY", MAX_MINOR),
        ("90071992547409.91", "USD", MAX_MINOR),
    ],
)
def test_from_paypal_exact(text, currency, minor):
    assert Money.from_paypal(text, currency) == Money(currency, minor)


@pytest.mark.parametrize(
    "money, text",
    [
        (Money("USD", 7400), "74.00"),
        (Money("USD", 5), "0.05"),
        (Money("USD", 0), "0.00"),
        (Money("USD", 100), "1.00"),
        (Money("JPY", 1000), "1000"),
        (Money("JPY", 0), "0"),
        (Money("HUF", 1000), "10"),
        (Money("TWD", 0), "0"),
        (Money("USD", -150), "-1.50"),
    ],
)
def test_to_paypal_uses_exactly_the_currency_exponent(money, text):
    assert money.to_paypal() == text


@pytest.mark.parametrize("currency", ["HUF", "TWD"])
@pytest.mark.parametrize("minor", [1, 50, 99, 1050, 101])
def test_hundredths_of_a_zero_decimal_currency_cannot_go_to_paypal(currency, minor):
    with pytest.raises(InexactAmountError):
        Money(currency, minor).to_paypal()


@pytest.mark.parametrize(
    "text",
    [
        "+1.00",  # leading plus
        "1e2",
        "1E2",
        "1.0e2",
        "1,000.00",  # thousands separator
        "1 000.00",
        "1_000",
        " 1.00",  # whitespace
        "1.00 ",
        "1.00\n",
        "\t1",
        " 1",
        "",
        "-",
        ".5",  # no leading digit
        "5.",  # no trailing digits
        "007",  # leading zeros
        "00.50",
        "--1",
        "1.2.3",
        "1..0",
        "１２",  # fullwidth digits
        "١٢",  # Arabic-Indic digits
        "NaN",
        "Infinity",
        "-Infinity",
        "0x10",
        "1/2",
        "(1.00)",
        "$1.00",
        "1.00 USD",
        "null",
        "١٢٣",
    ],
)
def test_malformed_decimal_text_is_rejected(text):
    with pytest.raises(InvalidAmountError):
        Money.from_paypal(text, "USD")


@pytest.mark.parametrize("text", ["1.001", "1.500", "1.000", "0.001", "74.999", "1.00000000"])
def test_excess_precision_is_inexact_even_when_the_extra_digits_are_zero(text):
    with pytest.raises(InexactAmountError):
        Money.from_paypal(text, "USD")


@pytest.mark.parametrize("text", ["1.0", "1.00", "10.5", "0.0"])
@pytest.mark.parametrize("currency", ["JPY", "HUF", "TWD"])
def test_any_decimal_point_is_rejected_for_zero_decimal_currencies(text, currency):
    with pytest.raises(InexactAmountError):
        Money.from_paypal(text, currency)


@pytest.mark.parametrize("bad", [74.0, 74, True, False, None, Decimal("1.00"), b"1.00", ["1"]])
def test_non_string_amount_text_is_rejected(bad):
    with pytest.raises(InvalidAmountError):
        Money.from_paypal(bad, "USD")  # type: ignore[arg-type]


def test_text_length_limit():
    with pytest.raises(InvalidAmountError):
        Money.from_paypal("1" * 33, "JPY")
    with pytest.raises(AmountOutOfRangeError):
        Money.from_paypal("1" * 32, "JPY")


def test_out_of_range_text_is_rejected():
    with pytest.raises(AmountOutOfRangeError):
        Money.from_paypal("9007199254740992", "JPY")
    with pytest.raises(AmountOutOfRangeError):
        Money.from_paypal("90071992547409.92", "USD")


def test_negative_amounts_need_an_explicit_opt_in():
    with pytest.raises(InvalidAmountError):
        Money.from_paypal("-1.00", "USD")
    assert Money.from_paypal("-1.00", "USD", allow_negative=True) == Money("USD", -100)
    assert Money.from_paypal("-5", "JPY", allow_negative=True) == Money("JPY", -5)


@pytest.mark.parametrize("text", ["-0", "-0.00", "-0.0"])
def test_negative_zero_is_never_accepted(text):
    for allow in (False, True):
        with pytest.raises(InvalidAmountError):
            Money.from_paypal(text, "USD", allow_negative=allow)


# ---- the generic decimal core, including exponent 3 ----


def test_three_decimal_currency_path_through_the_core_functions():
    kwd = iso_exponent("KWD")
    assert kwd == 3
    assert parse_decimal("1.234", kwd) == 1234
    assert parse_decimal("1", kwd) == 1000
    assert parse_decimal("0.005", kwd) == 5
    assert format_decimal(1234, kwd) == "1.234"
    assert format_decimal(5, kwd) == "0.005"
    assert format_decimal(0, kwd) == "0.000"
    assert format_decimal(-5, kwd) == "-0.005"
    with pytest.raises(InexactAmountError):
        parse_decimal("1.2345", kwd)


def test_core_functions_for_zero_and_two_decimals():
    assert parse_decimal("5", 0) == 5
    with pytest.raises(InexactAmountError):
        parse_decimal("5.0", 0)
    assert format_decimal(5, 0) == "5"
    assert format_decimal(7, 2) == "0.07"
    assert format_decimal(100, 2) == "1.00"
    assert format_decimal(-7, 2) == "-0.07"


@pytest.mark.parametrize("exponent", [-1, 7, 100])
def test_bad_exponent_is_rejected(exponent):
    with pytest.raises(InvalidAmountError):
        parse_decimal("1", exponent)
    with pytest.raises(InvalidAmountError):
        format_decimal(1, exponent)


def test_kwd_money_is_refused_because_paypal_does_not_list_it():
    with pytest.raises(UnsupportedCurrencyError):
        Money.from_paypal("1.234", "KWD")


# ---- UCP integers ----


def test_from_ucp_takes_integers_of_minor_units():
    assert Money.from_ucp(7400, "USD") == Money("USD", 7400)
    assert Money.from_ucp(1000, "JPY").to_ucp() == 1000
    assert Money.from_ucp(0, "USD") == Money.zero("USD")
    assert Money.from_ucp(MAX_MINOR, "USD").to_ucp() == MAX_MINOR


@pytest.mark.parametrize("bad", [1.0, 74.5, True, False, "100", None, Decimal(100), b"1", [1]])
def test_from_ucp_rejects_everything_but_int(bad):
    with pytest.raises(InvalidAmountError):
        Money.from_ucp(bad, "USD")  # type: ignore[arg-type]


def test_from_ucp_rejects_negative_and_out_of_range():
    with pytest.raises(InvalidAmountError):
        Money.from_ucp(-1, "USD")
    with pytest.raises(AmountOutOfRangeError):
        Money.from_ucp(MAX_MINOR + 1, "USD")


def test_to_ucp_rejects_negative():
    with pytest.raises(InvalidAmountError):
        Money("USD", -1).to_ucp()


def test_constructor_rejects_non_int_minor_units():
    for bad in (1.5, True, "1", None, Decimal(1)):
        with pytest.raises(InvalidAmountError):
            Money("USD", bad)  # type: ignore[arg-type]


def test_int_subclasses_are_not_accepted():
    class Loud(int):
        pass

    with pytest.raises(InvalidAmountError):
        Money("USD", Loud(1))


# ---- arithmetic ----


def test_sums_are_exact():
    tenth = Money.from_paypal("0.10", "USD")
    fifth = Money.from_paypal("0.20", "USD")
    assert tenth + fifth == Money.from_paypal("0.30", "USD")  # not true of 0.1 + 0.2 in binary
    assert Money.sum([tenth] * 10, "USD") == Money.from_paypal("1.00", "USD")
    assert Money.sum([], "EUR") == Money.zero("EUR")
    assert (tenth + fifth - fifth) == tenth


def test_multiplication_by_whole_quantities_only():
    unit = Money.from_paypal("25.00", "USD")
    assert unit * 2 == Money.from_paypal("50.00", "USD")
    assert 3 * unit == Money.from_paypal("75.00", "USD")
    for bad in (1.5, True, "2", None):
        with pytest.raises(InvalidAmountError):
            unit * bad  # type: ignore[operator]


def test_mixed_currencies_never_combine_or_compare():
    usd, eur = Money("USD", 1), Money("EUR", 1)
    assert usd != eur
    for op in (
        lambda: usd + eur,
        lambda: usd - eur,
        lambda: usd < eur,
        lambda: usd <= eur,
        lambda: usd > eur,
        lambda: usd >= eur,
    ):
        with pytest.raises(CurrencyMismatchError):
            op()
    with pytest.raises(CurrencyMismatchError):
        Money.sum([usd, eur], "USD")


def test_overflow_in_arithmetic_is_an_error_not_a_wrap():
    top = Money("USD", MAX_MINOR)
    with pytest.raises(AmountOutOfRangeError):
        top + Money("USD", 1)
    with pytest.raises(AmountOutOfRangeError):
        top * 2
    with pytest.raises(AmountOutOfRangeError):
        -top - Money("USD", 1)


def test_negation_and_ordering():
    a, b = Money("USD", 100), Money("USD", 250)
    assert -a == Money("USD", -100)
    assert a < b and a <= b and b > a and b >= a and not (a > b)
    assert a - b == Money("USD", -150)
    assert hash(a) == hash(Money("USD", 100))


def test_comparison_with_other_types_is_a_type_error():
    with pytest.raises(TypeError):
        _ = Money("USD", 1) < 5  # type: ignore[operator]
    with pytest.raises(TypeError):
        Money("USD", 1) + 5  # type: ignore[operator]


def test_money_is_immutable():
    m = Money("USD", 1)
    with pytest.raises((AttributeError, TypeError)):
        m.minor = 2  # type: ignore[misc]


def test_every_error_has_a_distinct_code():
    classes = [
        UnsupportedCurrencyError,
        InvalidAmountError,
        InexactAmountError,
        AmountOutOfRangeError,
        CurrencyMismatchError,
    ]
    assert len({c.code for c in classes}) == 5
    assert all(issubclass(c, MoneyError) for c in classes)


# ---- no floats anywhere ----

SOURCE = Path(inspect.getfile(money_module)).read_text()


def float_nodes(source: str) -> list[str]:
    found = []
    for node in ast.walk(ast.parse(source)):
        if isinstance(node, ast.Name) and node.id in {"float", "Decimal", "Fraction"}:
            found.append(f"name {node.id}")
        elif isinstance(node, ast.Constant) and isinstance(node.value, float):
            found.append(f"constant {node.value}")
        elif isinstance(node, ast.BinOp) and isinstance(node.op, ast.Div):
            found.append("true division")
        elif isinstance(node, (ast.Import, ast.ImportFrom)):
            names = [a.name for a in node.names] + [getattr(node, "module", None) or ""]
            if any(n in {"decimal", "fractions", "math", "statistics"} for n in names):
                found.append("numeric module import")
    return found


def test_the_module_source_contains_no_float_decimal_or_true_division():
    assert float_nodes(SOURCE) == []


def test_the_float_scan_has_teeth():
    assert float_nodes("x = 1.5")
    assert float_nodes("def f(a: float): ...")
    assert float_nodes("y = a / b")
    assert float_nodes("from decimal import Decimal")


def annotation_mentions_float(annotation: object) -> bool:
    text = repr(annotation)
    return any(word in text for word in ("float", "Decimal", "Fraction"))


def public_callables():
    for name, obj in vars(money_module).items():
        if name.startswith("_") or getattr(obj, "__module__", None) != money_module.__name__:
            continue
        if inspect.isfunction(obj):
            yield name, obj
        elif inspect.isclass(obj):
            yield name, obj
            for member_name, member in vars(obj).items():
                if member_name.startswith("__") and member_name not in {
                    "__init__",
                    "__add__",
                    "__sub__",
                    "__mul__",
                    "__neg__",
                    "__lt__",
                    "__le__",
                    "__gt__",
                    "__ge__",
                }:
                    continue
                target = (
                    member.__func__ if isinstance(member, (classmethod, staticmethod)) else member
                )
                if inspect.isfunction(target):
                    yield f"{name}.{member_name}", target


def test_no_public_signature_mentions_float():
    checked = 0
    for name, obj in public_callables():
        hints = typing.get_type_hints(obj)
        for arg, annotation in hints.items():
            assert not annotation_mentions_float(annotation), f"{name} {arg}: {annotation}"
        checked += 1
    assert checked > 20


def test_the_signature_check_has_teeth():
    def bad(amount: float) -> float: ...

    assert any(annotation_mentions_float(a) for a in typing.get_type_hints(bad).values())
