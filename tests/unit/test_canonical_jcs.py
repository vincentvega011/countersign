"""JCS wrapper: RFC 8785 vectors read from the vendored RFC text, plus rejection cases."""

from __future__ import annotations

import json
import re
import struct
from pathlib import Path

import pytest

from countersign.canonical import JcsError, canonicalize, loads_strict
from countersign.canonical.jsonstrict import ExcessPrecisionError, UnsafeIntegerError

RFC = (Path(__file__).resolve().parents[2] / "spec/vendor/rfc8785/rfc8785.txt").read_text()

# RFC 8785 section 3.2.2 sample input, verbatim.
RFC_SAMPLE = (
    '{"numbers": [333333333.33333329, 1E30, 4.50, 2e-3, 0.000000000000000000000000001],'
    ' "string": "\\u20ac$\\u000F\\u000aA\'\\u0042\\u0022\\u005c\\\\\\"\\/",'
    ' "literals": [null, true, false]}'
)


def rfc_expected_sample_bytes() -> bytes:
    block = RFC[RFC.index("Applied to the sample in Section 3.2.3") :]
    block = block[block.index("7b 22") : block.index("This data is intended")]
    return bytes.fromhex("".join(block.split()))


def number_table() -> list[tuple[str, str]]:
    start = RFC.rindex("Appendix B.  Number Serialization Samples")
    section = RFC[start : RFC.index("Appendix C.", start)]
    return re.findall(r"\| ([0-9a-f]{16}) \| (\S*) *\|", section)


def test_number_table_has_the_expected_rows():
    assert len(number_table()) == 26  # guards against a parse change that checks nothing


@pytest.mark.parametrize("bits, expected", number_table())
def test_rfc8785_appendix_b_number_serialization(bits, expected):
    value = struct.unpack(">d", bytes.fromhex(bits))[0]
    if expected == "":  # NaN and Infinity have no JSON form
        with pytest.raises(JcsError):
            canonicalize(value)
    else:
        assert canonicalize(value).decode() == expected


def test_rfc8785_worked_example_byte_for_byte():
    expected = rfc_expected_sample_bytes()
    assert canonicalize(json.loads(RFC_SAMPLE)) == expected
    assert canonicalize(json.loads(RFC_SAMPLE)).startswith(b'{"literals":[null,true,false]')


def test_strict_loader_rejects_the_rfc_sample_numbers_by_design():
    # 333333333.33333329 has 17 significant digits that binary64 cannot hold, and 1E30 is beyond
    # the safe range. The strict loader refuses each; the JCS layer itself accepts both (above).
    with pytest.raises(ExcessPrecisionError):
        loads_strict(RFC_SAMPLE.replace("1E30", "1E15").encode())
    with pytest.raises(UnsafeIntegerError):
        loads_strict(RFC_SAMPLE.replace("333333333.33333329", "333333333.3333333").encode())


def test_strict_loader_then_jcs_matches_the_json_module_on_the_rfc_sample():
    text = RFC_SAMPLE.replace("333333333.33333329", "333333333.3333333").replace("1E30", "1E15")
    assert canonicalize(loads_strict(text.encode())) == canonicalize(json.loads(text))


def test_rfc8785_property_sorting_uses_utf16_code_units():
    data = json.loads(
        '{"\\u20ac": "Euro Sign", "\\r": "Carriage Return",'
        ' "\\ufb33": "Hebrew Letter Dalet With Dagesh", "1": "One",'
        ' "\\ud83d\\ude00": "Emoji: Grinning Face", "\\u0080": "Control",'
        ' "\\u00f6": "Latin Small Letter O With Diaeresis"}'
    )
    assert list(json.loads(canonicalize(data)).values()) == [
        "Carriage Return",
        "One",
        "Control",
        "Latin Small Letter O With Diaeresis",
        "Euro Sign",
        "Emoji: Grinning Face",
        "Hebrew Letter Dalet With Dagesh",
    ]


def test_basic_forms():
    assert canonicalize({"b": 1, "a": [True, None, "x"]}) == b'{"a":[true,null,"x"],"b":1}'
    assert canonicalize(1.0) == b"1"
    assert canonicalize(-0.0) == b"0"
    assert canonicalize("é") == '"é"'.encode()
    assert canonicalize([]) == b"[]"
    assert canonicalize({}) == b"{}"


def test_integer_bounds():
    assert canonicalize(2**53 - 1) == b"9007199254740991"
    for bad in (2**53, -(2**53)):
        with pytest.raises(JcsError):
            canonicalize(bad)


@pytest.mark.parametrize(
    "bad",
    [
        float("nan"),
        float("inf"),
        float("-inf"),
        "\ud800",  # lone surrogate as a value
        {"\ud800": 1},  # lone surrogate as a key (the library raises a different exception type)
        {1: "int key"},
        b"bytes",
        {"s": {1, 2}},
        object(),
    ],
)
def test_values_without_a_canonical_form_raise_jcs_error(bad):
    with pytest.raises(JcsError):
        canonicalize(bad)


def test_deep_nesting_raises_jcs_error():
    value: list = []
    for _ in range(50_000):
        value = [value]
    with pytest.raises(JcsError):
        canonicalize(value)


def test_jcs_error_is_a_value_error_with_a_code():
    with pytest.raises(ValueError) as info:
        canonicalize(float("nan"))
    assert info.value.code == "jcs_invalid"  # type: ignore[attr-defined]
