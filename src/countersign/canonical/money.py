"""Money: integer minor units, exact conversion, no floats anywhere (INV-9).

Security reasoning. An amount that changes by one unit between what the customer signed, what
Countersign sent to PayPal and what PayPal authorized is exactly the attack the capture gate exists
to catch, so the conversion code itself must never be a source of drift. Therefore:

- A `Money` holds an `int` count of ISO 4217 minor units, the unit UCP and AP2 use. There is no
  float, `Decimal` or rounding step in this module; a conversion that is not exact raises.
- PayPal decimal strings are parsed as text with a fixed grammar and never pass through the JSON
  loader's float path. Anything outside the grammar is rejected rather than interpreted: floats,
  `bool`, exponent notation, a leading plus, thousands separators, whitespace, a leading dot, a
  trailing dot, leading zeros, negative zero and non-ASCII digits.
- Two exponents are kept per currency because they differ. UCP amounts are in ISO 4217 minor units.
  PayPal says HUF, JPY and TWD "do not support decimals" and errors on a decimal amount, while
  ISO 4217 gives HUF and TWD two decimals. A HUF amount of 1050 minor units is 10.50 HUF, which
  PayPal cannot carry, so `to_paypal` raises instead of rounding.
- Amounts are limited to +/-(2^53 - 1) minor units so they survive JSON (INV-8) unchanged.
- The supported currencies are the ones on PayPal's REST currency page (docs/ENV.md section 8).
  KWD and the other three-decimal currencies are in the ISO table but not supported, so a `Money` in
  one is refused; the exponent-3 code path is still exercised through `parse_decimal` and
  `format_decimal`.

Parsing accepts fewer fractional digits than the exponent (`5` and `5.5` for USD) because the value
is exact, and rejects more (`5.001`, `1.500`), even when the extra digits are zeros.
"""

from __future__ import annotations

import re
from collections.abc import Iterable, Mapping
from dataclasses import dataclass
from types import MappingProxyType

MAX_MINOR = 2**53 - 1
MAX_TEXT_LENGTH = 32  # the maxLength of PayPal's money `value`

# ISO 4217 minor-unit exponents, from the maintenance agency's current list (list one, published
# 2026-09-17). Currencies with no minor unit (metals, XXX and similar) are left out.
_ISO_EXPONENT_GROUPS: Mapping[int, str] = {
    0: ("BIF CLP DJF GNF ISK JPY KMF KRW PYG RWF UGX UYI VND VUV XAF XOF XPF "),
    2: (
        "AED AFN ALL AMD AOA ARS AUD AWG AZN BAM BBD BDT BMD BND BOB BOV BRL BSD BTN BWP BYN "
        "BZD CAD CDF CHE CHF CHW CNY COP COU CRC CUP CVE CZK DKK DOP DZD EGP ERN ETB EUR FJD "
        "FKP GBP GEL GHS GIP GMD GTQ GYD HKD HNL HTG HUF IDR ILS INR IRR JMD KES KGS KHR KPW "
        "KYD KZT LAK LBP LKR LRD LSL MAD MDL MGA MKD MMK MNT MOP MRU MUR MVR MWK MXN MXV MYR "
        "MZN NAD NGN NIO NOK NPR NZD PAB PEN PGK PHP PKR PLN QAR RON RSD RUB SAR SBD SCR SDG "
        "SEK SGD SHP SLE SOS SRD SSP STN SVC SYP SZL THB TJS TMT TOP TRY TTD TWD TZS UAH USD "
        "USN UYU UZS VED VES WST XAD XCD XCG YER ZAR ZMW ZWG "
    ),
    3: ("BHD IQD JOD KWD LYD OMR TND "),
    4: ("CLF UYW "),
}

ISO_EXPONENTS: Mapping[str, int] = MappingProxyType(
    {code: exp for exp, codes in _ISO_EXPONENT_GROUPS.items() for code in codes.split()}
)

# Currencies on PayPal's REST currency page (docs/ENV.md section 8). BRL, CNY and MYR are in-country
# only and RUB carries no note; those are account matters and do not change parsing.
PAYPAL_CURRENCIES: frozenset[str] = frozenset(
    [
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
)

# PayPal: "This currency does not support decimals" (HUF, JPY, TWD). JPY is already 0 in ISO 4217.
PAYPAL_ZERO_DECIMAL: frozenset[str] = frozenset({"HUF", "JPY", "TWD"})

_CODE = re.compile(r"[A-Z]{3}")
_DECIMAL = re.compile(r"(-?)(0|[1-9][0-9]*)(?:\.([0-9]+))?", re.ASCII)


class MoneyError(ValueError):
    """Base class. `code` is a stable machine-readable reason."""

    code = "money_invalid"


class UnsupportedCurrencyError(MoneyError):
    code = "money_unsupported_currency"


class InvalidAmountError(MoneyError):
    code = "money_invalid_amount"


class InexactAmountError(MoneyError):
    code = "money_inexact"


class AmountOutOfRangeError(MoneyError):
    code = "money_out_of_range"


class CurrencyMismatchError(MoneyError):
    code = "money_currency_mismatch"


def iso_exponent(code: str) -> int:
    """ISO 4217 minor-unit exponent: the unit UCP and AP2 amounts are expressed in."""
    try:
        return ISO_EXPONENTS[code]
    except (KeyError, TypeError):
        raise UnsupportedCurrencyError("currency has no ISO 4217 minor unit") from None


def paypal_exponent(code: str) -> int:
    """Decimal places PayPal accepts for a supported currency."""
    check_currency(code)
    return 0 if code in PAYPAL_ZERO_DECIMAL else iso_exponent(code)


def check_currency(code: str) -> str:
    if type(code) is not str or not _CODE.fullmatch(code):
        raise UnsupportedCurrencyError("currency must be three uppercase ASCII letters")
    if code not in PAYPAL_CURRENCIES or code not in ISO_EXPONENTS:
        raise UnsupportedCurrencyError(f"currency {code} is not supported")
    return code


def _check_int(value: object, what: str) -> int:
    if type(value) is not int:  # rejects bool, float, str, Decimal and int subclasses
        raise InvalidAmountError(f"{what} must be an int, not {type(value).__name__}")
    if abs(value) > MAX_MINOR:
        raise AmountOutOfRangeError(f"{what} is outside +/-(2^53 - 1) minor units")
    return value


def parse_decimal(text: str, exponent: int, *, allow_negative: bool = False) -> int:
    """Parse a decimal string into minor units at `exponent` decimal places, exactly."""
    if type(text) is not str:
        raise InvalidAmountError(f"amount text must be a str, not {type(text).__name__}")
    if not 0 <= exponent <= 6:
        raise InvalidAmountError("exponent must be between 0 and 6")
    if len(text) > MAX_TEXT_LENGTH:
        raise InvalidAmountError("amount text is too long")
    match = _DECIMAL.fullmatch(text)
    if match is None:
        raise InvalidAmountError("amount text is not a plain decimal")
    sign, whole, fraction = match.groups()
    fraction = fraction or ""
    if len(fraction) > exponent:
        raise InexactAmountError(f"amount has more than {exponent} decimal places")
    minor = int(whole + fraction.ljust(exponent, "0"))
    if sign:
        if minor == 0:
            raise InvalidAmountError("negative zero is not allowed")
        if not allow_negative:
            raise InvalidAmountError("negative amounts are not allowed here")
        minor = -minor
    return _check_int(minor, "amount")


def format_decimal(minor: int, exponent: int) -> str:
    """Format minor units as a decimal string with exactly `exponent` decimal places."""
    _check_int(minor, "amount")
    if not 0 <= exponent <= 6:
        raise InvalidAmountError("exponent must be between 0 and 6")
    sign = "-" if minor < 0 else ""
    digits = str(abs(minor)).rjust(exponent + 1, "0")
    if exponent == 0:
        return sign + digits
    return f"{sign}{digits[:-exponent]}.{digits[-exponent:]}"


@dataclass(frozen=True, slots=True)
class Money:
    """An amount of a supported currency in ISO 4217 minor units."""

    currency: str
    minor: int

    def __post_init__(self) -> None:
        check_currency(self.currency)
        _check_int(self.minor, "amount")

    @classmethod
    def zero(cls, currency: str) -> Money:
        return cls(currency, 0)

    @classmethod
    def from_ucp(cls, amount: int, currency: str) -> Money:
        """A UCP amount: a JSON integer of minor units, minimum 0."""
        value = _check_int(amount, "UCP amount")
        if value < 0:
            raise InvalidAmountError("UCP amounts are not negative")
        return cls(currency, value)

    @classmethod
    def from_paypal(cls, text: str, currency: str, *, allow_negative: bool = False) -> Money:
        """A PayPal decimal string, e.g. "74.00" for USD or "1000" for JPY."""
        check_currency(currency)
        paypal_minor = parse_decimal(text, paypal_exponent(currency), allow_negative=allow_negative)
        scale = 10 ** (iso_exponent(currency) - paypal_exponent(currency))
        return cls(currency, _check_int(paypal_minor * scale, "amount"))

    def to_ucp(self) -> int:
        if self.minor < 0:
            raise InvalidAmountError("UCP amounts are not negative")
        return self.minor

    def to_paypal(self) -> str:
        """The PayPal decimal string with exactly the currency's number of decimal places."""
        scale = 10 ** (iso_exponent(self.currency) - paypal_exponent(self.currency))
        paypal_minor, remainder = divmod(self.minor, scale)
        if remainder:
            raise InexactAmountError(f"{self.currency} amounts must be whole units for PayPal")
        return format_decimal(paypal_minor, paypal_exponent(self.currency))

    def _same(self, other: Money) -> None:
        if not isinstance(other, Money):
            raise TypeError("expected Money")
        if other.currency != self.currency:
            raise CurrencyMismatchError(f"{self.currency} and {other.currency} cannot be combined")

    def __add__(self, other: Money) -> Money:
        self._same(other)
        return Money(self.currency, self.minor + other.minor)

    def __sub__(self, other: Money) -> Money:
        self._same(other)
        return Money(self.currency, self.minor - other.minor)

    def __neg__(self) -> Money:
        return Money(self.currency, -self.minor)

    def __mul__(self, quantity: int) -> Money:
        """Multiply by a whole-number quantity (a line item count)."""
        return Money(self.currency, self.minor * _check_int(quantity, "quantity"))

    __rmul__ = __mul__

    def __lt__(self, other: Money) -> bool:
        self._same(other)
        return self.minor < other.minor

    def __le__(self, other: Money) -> bool:
        self._same(other)
        return self.minor <= other.minor

    def __gt__(self, other: Money) -> bool:
        self._same(other)
        return self.minor > other.minor

    def __ge__(self, other: Money) -> bool:
        self._same(other)
        return self.minor >= other.minor

    @classmethod
    def sum(cls, items: Iterable[Money], currency: str) -> Money:
        """Exact sum; an empty iterable gives zero in `currency`."""
        total = cls.zero(currency)
        for item in items:
            total = total + item
        return total
