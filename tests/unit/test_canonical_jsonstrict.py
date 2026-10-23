"""Strict JSON loader: every rule in the module docstring has a rejecting test and an accepting one."""

from __future__ import annotations

import pytest

from countersign.canonical.jsonstrict import (
    DuplicateKeyError,
    ExcessPrecisionError,
    InputTooLargeError,
    InvalidEncodingError,
    JsonSyntaxError,
    LoneSurrogateError,
    NestingTooDeepError,
    NonFiniteNumberError,
    StrictJsonError,
    UnsafeIntegerError,
    loads_strict,
)


def test_parses_ordinary_documents():
    doc = b'{"a": [1, 2.5, "x", null, true, false], "b": {"c": "d"}}'
    assert loads_strict(doc) == {"a": [1, 2.5, "x", None, True, False], "b": {"c": "d"}}
    assert loads_strict(b"[]") == []
    assert loads_strict(b'"text"') == "text"
    assert loads_strict(b"7") == 7


@pytest.mark.parametrize(
    "doc",
    [
        b'{"a": 1, "a": 2}',
        b'{"a": 1, "b": 2, "a": 1}',
        b'{"x": {"a": 1, "a": 1}}',
        b'[{"a": 1, "a": 2}]',
        b'{"a": 1, "\\u0061": 2}',  # equal after unescaping
        b'{"\\u00e9": 1, "\xc3\xa9": 2}',
    ],
)
def test_duplicate_keys_are_rejected(doc):
    with pytest.raises(DuplicateKeyError):
        loads_strict(doc)


def test_keys_that_only_look_alike_are_not_duplicates():
    # No Unicode normalization is applied: JCS sorts raw code units, so these are distinct.
    assert len(loads_strict('{"é": 1, "é": 2}'.encode())) == 2
    assert len(loads_strict(b'{"a": 1, "A": 2}')) == 2


@pytest.mark.parametrize("doc", [b"NaN", b"Infinity", b"-Infinity", b'{"a": NaN}', b"[Infinity]"])
def test_non_finite_constants_are_rejected(doc):
    with pytest.raises(NonFiniteNumberError):
        loads_strict(doc)


def test_overflowing_number_is_rejected_as_non_finite():
    with pytest.raises(NonFiniteNumberError):
        loads_strict(b"1e999")
    with pytest.raises(NonFiniteNumberError):
        loads_strict(b"-1e999")


@pytest.mark.parametrize(
    "doc",
    [b"\xff", b'"\xff"', b'"\xc3"', b'"\xc0\xaf"', b'"\xed\xa0\x80"', b'{"a": "\x80"}'],
)
def test_non_utf8_input_is_rejected(doc):
    with pytest.raises(InvalidEncodingError):
        loads_strict(doc)


def test_byte_order_mark_is_rejected():
    with pytest.raises(InvalidEncodingError):
        loads_strict(b"\xef\xbb\xbf{}")


def test_str_input_is_a_type_error():
    with pytest.raises(TypeError):
        loads_strict("{}")  # type: ignore[arg-type]


@pytest.mark.parametrize(
    "doc",
    [
        b'"\\ud800"',
        b'["\\udc00"]',
        b'{"\\ud800": 1}',
        b'{"a": ["x", {"b": "\\udbff"}]}',
        b'"\\ud800x"',
    ],
)
def test_lone_surrogate_escapes_are_rejected(doc):
    with pytest.raises(LoneSurrogateError):
        loads_strict(doc)


def test_valid_surrogate_pair_escape_is_accepted():
    assert loads_strict(b'"\\ud83d\\ude00"') == "\U0001f600"
    assert loads_strict('"\U0001f600"'.encode()) == "\U0001f600"


def test_integers_at_the_safe_limit():
    assert loads_strict(b"9007199254740991") == 2**53 - 1
    assert loads_strict(b"-9007199254740991") == -(2**53 - 1)
    for doc in (b"9007199254740992", b"-9007199254740992", b"[1, 18446744073709551616]"):
        with pytest.raises(UnsafeIntegerError):
            loads_strict(doc)


@pytest.mark.parametrize(
    "doc", [b"9007199254740992.0", b"1E30", b"1e20", b"-1e16", b"1e300", b"[9007199254740993.0]"]
)
def test_floats_beyond_the_safe_range_are_rejected(doc):
    with pytest.raises((UnsafeIntegerError, ExcessPrecisionError)):
        loads_strict(doc)


def test_float_at_the_safe_limit_is_accepted():
    assert loads_strict(b"9007199254740991.0") == 2.0**53 - 1


def test_integer_with_absurd_digit_count_is_rejected_not_crashed():
    with pytest.raises(UnsafeIntegerError):
        loads_strict(b"9" * 6000)


@pytest.mark.parametrize(
    "doc",
    [
        b"0.1000000000000000055",  # rounds to 0.1
        b"333333333.33333329",  # the RFC 8785 sample number: 17 digits that binary64 cannot keep
        b"1.0000000000000001",
        b"0.30000000000000004999",
        b"1e-400",  # underflows to zero, value lost
        b"4503599627370496.5",  # spacing at 2^52 is 1, so the .5 is lost
    ],
)
def test_excess_decimal_precision_is_rejected(doc):
    with pytest.raises(ExcessPrecisionError):
        loads_strict(doc)


@pytest.mark.parametrize(
    "doc, expected",
    [
        (b"1.5", 1.5),
        (b"1.50", 1.5),
        (b"15e-1", 1.5),
        (b"0.1", 0.1),
        (b"0.30000000000000004", 0.1 + 0.2),
        (b"1E15", 1e15),
        (b"5e-324", 5e-324),
        (b"2e-3", 0.002),
        (b"-0.0", -0.0),
        (b"4.50", 4.5),
        (b"0.000000000000000000000000001", 1e-27),
    ],
)
def test_exact_number_spellings_are_accepted(doc, expected):
    assert loads_strict(doc) == expected


@pytest.mark.parametrize(
    "doc",
    [
        b"",
        b"   ",
        b"{",
        b'{"a": 1,}',
        b"[1,]",
        b"{'a': 1}",
        b'{"a": 1} x',
        b"01",
        b"+1",
        b".5",
        b"tru",
    ],
)
def test_syntax_errors_are_typed(doc):
    with pytest.raises(JsonSyntaxError):
        loads_strict(doc)


def test_control_characters_in_strings_are_rejected():
    with pytest.raises(JsonSyntaxError):
        loads_strict(b'"a\nb"')


def test_excessive_nesting_fails_closed():
    with pytest.raises(NestingTooDeepError):
        loads_strict(b"[" * 200_000 + b"]" * 200_000, max_bytes=None)


def test_size_limit():
    with pytest.raises(InputTooLargeError):
        loads_strict(b"[" + b"1," * 600_000 + b"1]")
    assert loads_strict(b"[1, 1]", max_bytes=6) == [1, 1]
    with pytest.raises(InputTooLargeError):
        loads_strict(b"[1, 1]", max_bytes=5)


def test_every_error_is_a_strict_json_error_with_a_distinct_code():
    codes = {
        cls.code
        for cls in (
            InputTooLargeError,
            InvalidEncodingError,
            JsonSyntaxError,
            DuplicateKeyError,
            NonFiniteNumberError,
            UnsafeIntegerError,
            ExcessPrecisionError,
            LoneSurrogateError,
            NestingTooDeepError,
        )
    }
    assert len(codes) == 9
    assert all(issubclass(c, StrictJsonError) for c in (DuplicateKeyError, JsonSyntaxError))


def test_error_messages_do_not_echo_long_input():
    key = "k" * 5000
    with pytest.raises(DuplicateKeyError) as info:
        loads_strict(f'{{"{key}": 1, "{key}": 2}}'.encode())
    assert len(str(info.value)) < 100
