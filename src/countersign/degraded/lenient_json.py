"""The request body parser of a conventional integration (`ABL_NO_STRICT_JSON`, baseline mode).

Python's own parser: a duplicate key keeps the last value, NaN and Infinity are accepted, and large
or over-precise numbers are rounded. Only the size limit and the encoding are enforced, so it is
what a careful integration that never thought about parser differentials would use. It is injected
into the request routes by the composition root and nowhere else; signed material (mandates,
receipts, the merchant authorization) is still read by the strict loader, because a signature check
is not a place to be lenient even in the baseline.
"""

from __future__ import annotations

import json

from countersign.canonical.jsonstrict import (
    DEFAULT_MAX_BYTES,
    InputTooLargeError,
    InvalidEncodingError,
    JsonSyntaxError,
    JsonValue,
    NestingTooDeepError,
)


def loads_lenient(data: bytes) -> JsonValue:
    if len(data) > DEFAULT_MAX_BYTES:
        raise InputTooLargeError(f"input is {len(data)} bytes, limit is {DEFAULT_MAX_BYTES}")
    try:
        text = data.decode("utf-8")
    except UnicodeDecodeError as exc:
        raise InvalidEncodingError(f"input is not UTF-8 at byte {exc.start}") from None
    try:
        value: JsonValue = json.loads(text)
    except json.JSONDecodeError as exc:
        raise JsonSyntaxError(f"{exc.msg} at position {exc.pos}") from None
    except RecursionError:
        raise NestingTooDeepError("document is nested too deeply") from None
    return value
