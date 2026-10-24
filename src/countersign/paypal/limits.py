"""Limits PayPal enforces, checked by the client before anything is sent.

Confirmed in the sandbox (docs/PROTOCOL.md section 4.1): `custom_id` up to 255 characters,
`invoice_id` up to 127, `PayPal-Request-Id` up to 108. A longer `custom_id` or `invoice_id` is an
HTTP 400, but a Request-Id of 109 characters is an HTTP 500 `INTERNAL_SERVICE_ERROR`, which looks like
an outage and would be retried, so the client never lets one leave the process. Item `name` and `sku`
are held to 127 characters, the most PayPal returns unchanged (docs/ENV.md section 2.2), so the live
order can be compared exactly with what was sent.

Every check also refuses control characters, so a value cannot smuggle a header or a log line.
"""

from __future__ import annotations

import re

MAX_REQUEST_ID = 108
MAX_CUSTOM_ID = 255
MAX_INVOICE_ID = 127
MAX_ITEM_TEXT = 127

_REQUEST_ID = re.compile(r"[A-Za-z0-9._:-]+")
_PATH_ID = re.compile(r"[A-Za-z0-9_-]{1,64}")


class LimitError(ValueError):
    """A value breaks a limit PayPal enforces. Nothing was sent."""

    code = "paypal_limit"


def _text(value: object, name: str, maximum: int) -> str:
    if type(value) is not str:
        raise LimitError(f"{name} must be a string")
    if not 1 <= len(value) <= maximum:
        raise LimitError(f"{name} must be 1 to {maximum} characters, got {len(value)}")
    if any(ord(c) < 0x20 or ord(c) == 0x7F for c in value):
        raise LimitError(f"{name} must not contain control characters")
    return value


def check_request_id(value: object) -> str:
    text = _text(value, "PayPal-Request-Id", MAX_REQUEST_ID)
    if not _REQUEST_ID.fullmatch(text):
        raise LimitError("PayPal-Request-Id may contain only letters, digits and . _ : -")
    return text


def check_custom_id(value: object) -> str:
    return _text(value, "custom_id", MAX_CUSTOM_ID)


def check_invoice_id(value: object) -> str:
    return _text(value, "invoice_id", MAX_INVOICE_ID)


def check_item_text(value: object, name: str) -> str:
    return _text(value, name, MAX_ITEM_TEXT)


def check_path_id(value: object, name: str) -> str:
    """An identifier that becomes a URL path segment: no slash, dot, query or other surprise."""
    if type(value) is not str or not _PATH_ID.fullmatch(value):
        raise LimitError(f"{name} is not a valid PayPal identifier")
    return value
