"""Strict JSON loader. Every inbound JSON document passes through here first (INV-8).

Security reasoning. Signatures and hashes are computed over canonical bytes, so a parser that
accepts several readings of one document lets an attacker present one reading to the verifier and
another to the code that acts on it. Python's own parser is lenient in exactly the places that
matter, so this loader closes them and fails closed with a typed error:

- Duplicate object keys. The standard parser keeps the last value silently; another parser may
  keep the first. Keys are compared after unescaping, so "a" and "\\u0061" collide.
- NaN, Infinity and -Infinity, which are not JSON and have no canonical form.
- Input that is not UTF-8, or that starts with a byte order mark, and lone surrogates produced by
  escapes such as "\\ud800" (they cannot be encoded and canonicalization would fail later).
- Numbers of magnitude above 2^53 - 1, whether written as integers or as floats (1e20). This is
  the I-JSON and RFC 8785 safe range and matches the UCP integer cap. A float that large
  canonicalizes to integer digits that this loader would then refuse, and a larger integer can
  silently lose low digits in a float-based consumer.
- Excess decimal precision. A number written with a fraction or an exponent is accepted only if
  its decimal value is exactly the shortest decimal that identifies the binary64 value it parses
  to. Anything else (for example 0.1000000000000000055 or 333333333.33333329) would be rounded
  by the parse, so two different texts would mean the same number. Trailing zeros and exponent
  spelling are not precision (1.50, 15e-1 and 1.5 are accepted and canonicalize alike).
- Nesting deep enough to exhaust the stack, and input above a size limit.

Money never travels as a JSON float (INV-9); amounts are integers or decimal strings.
"""

from __future__ import annotations

import json
import math
import re
from decimal import Decimal, InvalidOperation
from typing import Any

MAX_SAFE_INTEGER = 2**53 - 1
DEFAULT_MAX_BYTES = 1_048_576

type JsonValue = None | bool | int | float | str | list[JsonValue] | dict[str, JsonValue]

_SURROGATE = re.compile("[\ud800-\udfff]")


class StrictJsonError(ValueError):
    """Base class. `code` is a stable machine-readable reason."""

    code = "json_invalid"


class InputTooLargeError(StrictJsonError):
    code = "json_too_large"


class InvalidEncodingError(StrictJsonError):
    code = "json_encoding"


class JsonSyntaxError(StrictJsonError):
    code = "json_syntax"


class DuplicateKeyError(StrictJsonError):
    code = "json_duplicate_key"


class NonFiniteNumberError(StrictJsonError):
    code = "json_non_finite"


class UnsafeIntegerError(StrictJsonError):
    code = "json_unsafe_integer"


class ExcessPrecisionError(StrictJsonError):
    code = "json_excess_precision"


class LoneSurrogateError(StrictJsonError):
    code = "json_lone_surrogate"


class NestingTooDeepError(StrictJsonError):
    code = "json_too_deep"


def _short(text: str) -> str:
    return repr(text if len(text) <= 40 else text[:40] + "...")


def _object_pairs(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in pairs:
        if key in result:
            raise DuplicateKeyError(f"duplicate object key {_short(key)}")
        result[key] = value
    return result


def _constant(name: str) -> Any:
    raise NonFiniteNumberError(f"{name} is not valid JSON")


def _integer(token: str) -> int:
    try:
        value = int(token)
    except ValueError:  # more digits than the interpreter will convert
        raise UnsafeIntegerError("integer has too many digits") from None
    if abs(value) > MAX_SAFE_INTEGER:
        raise UnsafeIntegerError("integer is outside +/-(2^53 - 1)")
    return value


def _decimal(token: str) -> float:
    value = float(token)
    if not math.isfinite(value):
        raise NonFiniteNumberError("number overflows binary64")
    if abs(value) > MAX_SAFE_INTEGER:
        raise UnsafeIntegerError("number is outside +/-(2^53 - 1)")
    try:
        exact = Decimal(token) == Decimal(repr(value))
    except InvalidOperation:
        exact = False
    if not exact:
        raise ExcessPrecisionError(f"number {_short(token)} is not exactly representable")
    return value


def _check_strings(root: Any) -> None:
    """Reject lone surrogates in any key or string value. Iterative, so depth cannot matter."""
    stack = [root]
    while stack:
        node = stack.pop()
        if isinstance(node, str):
            if _SURROGATE.search(node):
                raise LoneSurrogateError("string contains a lone surrogate")
        elif isinstance(node, list):
            stack.extend(node)
        elif isinstance(node, dict):
            for key, value in node.items():
                if _SURROGATE.search(key):
                    raise LoneSurrogateError("object key contains a lone surrogate")
                stack.append(value)


def loads_strict(data: bytes, *, max_bytes: int | None = DEFAULT_MAX_BYTES) -> JsonValue:
    """Parse UTF-8 JSON bytes under the rules in the module docstring."""
    if not isinstance(data, bytes):
        raise TypeError("loads_strict takes bytes; decoding is part of the check")
    if max_bytes is not None and len(data) > max_bytes:
        raise InputTooLargeError(f"input is {len(data)} bytes, limit is {max_bytes}")
    try:
        text = data.decode("utf-8")
    except UnicodeDecodeError as exc:
        raise InvalidEncodingError(f"input is not UTF-8 at byte {exc.start}") from None
    if text.startswith("﻿"):
        raise InvalidEncodingError("input starts with a byte order mark")
    try:
        value = json.loads(
            text,
            object_pairs_hook=_object_pairs,
            parse_constant=_constant,
            parse_int=_integer,
            parse_float=_decimal,
        )
    except StrictJsonError:
        raise
    except json.JSONDecodeError as exc:
        raise JsonSyntaxError(f"{exc.msg} at position {exc.pos}") from None
    except RecursionError:
        raise NestingTooDeepError("document is nested too deeply") from None
    _check_strings(value)
    return value  # type: ignore[no-any-return]
