"""Spike: check the rfc8785 package against the RFC 8785 test vectors.

The vectors are read from the vendored RFC text in spec/vendor/rfc8785/rfc8785.txt:
the number serialization table (Appendix B), the worked example (sections 3.2.2 to 3.2.4)
and the property sorting data (section 3.2.3).

Run: uv run python scripts/spikes/jcs_vectors.py
"""

import json
import re
import struct
from pathlib import Path

import rfc8785

RFC = Path(__file__).resolve().parents[2] / "spec/vendor/rfc8785/rfc8785.txt"
TEXT = RFC.read_text()


def check_number_table() -> int:
    start = TEXT.rindex("Appendix B.  Number Serialization Samples")
    section = TEXT[start : TEXT.index("Appendix C.", start)]
    checked = 0
    for hex_bits, expected in re.findall(r"\| ([0-9a-f]{16}) \| (\S*) *\|", section):
        value = struct.unpack(">d", bytes.fromhex(hex_bits))[0]
        if expected == "":
            # NaN and Infinity must be rejected.
            try:
                rfc8785.dumps(value)
            except rfc8785.FloatDomainError:
                checked += 1
                continue
            raise AssertionError(f"{hex_bits} should be rejected")
        got = rfc8785.dumps(value).decode()
        assert got == expected, (hex_bits, got, expected)
        checked += 1
    # The table has 26 rows. Guard against a parsing change that silently checks nothing.
    assert checked == 26, checked
    return checked


def check_worked_example() -> None:
    # Section 3.2.2 input, parsed with a JSON parser, then canonicalized.
    sample = json.loads(
        '{"numbers": [333333333.33333329, 1E30, 4.50, 2e-3, 0.000000000000000000000000001],'
        ' "string": "\\u20ac$\\u000F\\u000aA\'\\u0042\\u0022\\u005c\\\\\\"\\/",'
        ' "literals": [null, true, false]}'
    )
    block = TEXT[TEXT.index("Applied to the sample in Section 3.2.3") :]
    block = block[block.index("7b 22") : block.index("This data is intended")]
    expected = bytes.fromhex("".join(block.split()))
    assert rfc8785.dumps(sample) == expected


def check_sorting() -> None:
    data = json.loads(
        '{"\\u20ac": "Euro Sign", "\\r": "Carriage Return",'
        ' "\\ufb33": "Hebrew Letter Dalet With Dagesh", "1": "One",'
        ' "\\ud83d\\ude00": "Emoji: Grinning Face", "\\u0080": "Control",'
        ' "\\u00f6": "Latin Small Letter O With Diaeresis"}'
    )
    ordered = list(json.loads(rfc8785.dumps(data)).values())
    assert ordered == [
        "Carriage Return",
        "One",
        "Control",
        "Latin Small Letter O With Diaeresis",
        "Euro Sign",
        "Emoji: Grinning Face",
        "Hebrew Letter Dalet With Dagesh",
    ], ordered


def check_rejections() -> None:
    # Integers outside +/-(2**53 - 1) are rejected, which matches the UCP integer cap.
    for bad_int in (2**53, -(2**53), 2**53 + 1):
        try:
            rfc8785.dumps(bad_int)
        except rfc8785.IntegerDomainError:
            pass
        else:
            raise AssertionError(bad_int)
    assert rfc8785.dumps(2**53 - 1) == b"9007199254740991"
    # Lone surrogates must be rejected. As a value the package raises CanonicalizationError,
    # as an object key it raises UnicodeEncodeError, so a wrapper must catch both.
    for bad in ("\ud800", {"\ud800": 1}):
        try:
            rfc8785.dumps(bad)
        except (rfc8785.CanonicalizationError, UnicodeEncodeError):
            pass
        else:
            raise AssertionError(bad)


if __name__ == "__main__":
    count = check_number_table()
    print(f"OK number serialization table: {count} rows (NaN and Infinity rejected)")
    check_worked_example()
    print("OK RFC 8785 section 3.2.2 to 3.2.4 worked example, byte for byte")
    check_sorting()
    print("OK property sorting by UTF-16 code units")
    check_rejections()
    print("OK unsafe integers and lone surrogates rejected")
    print(f"rfc8785 {rfc8785.__version__}: all vectors verified")
