"""UCP messages and the two error shapes, built here and nowhere else.

Messages follow `common/types/message_error.json` and `message_warning.json`: an error has `type`,
`code`, `content` and `severity` (and an optional JSONPath `path`); a warning has `type`, `code`
and `content`. A business outcome is returned with HTTP 200 (REST binding, "Business Outcomes");
a protocol failure is HTTP 4xx or 5xx with a body holding `code` and `content`.
"""

from __future__ import annotations

from typing import Any, Literal

from countersign.protocols.ucp.profile import UCP_VERSION

Severity = Literal["recoverable", "requires_buyer_input", "requires_buyer_review", "unrecoverable"]

# Codes. The first group is from the UCP specs; the second is Countersign's own, free-form as the
# schema allows (`error_code.json`: "freeform codes are permitted").
NOT_FOUND = "not_found"
ITEM_UNAVAILABLE = "item_unavailable"
MANDATE_REQUIRED = "mandate_required"
INVALID_PROFILE_URL = "invalid_profile_url"
CHECKOUT_NOT_MODIFIABLE = "checkout_not_modifiable"
CHECKOUT_NOT_CANCELABLE = "checkout_not_cancelable"
CHECKOUT_NOT_READY = "checkout_not_ready"
UPDATE_DURING_COMPLETION = "complete_in_progress"
LINE_ITEM_NOT_FOUND = "line_item_not_found"
QUANTITY_LIMIT = "quantity_limit"
LINE_LIMIT = "line_limit"
QUANTITY_UNIT_MISMATCH = "quantity_unit_mismatch"
FIELD_IGNORED = "field_ignored"
INVALID_REQUEST = "invalid_request"
INTERNAL_ERROR = "internal_error"


class ProtocolError(Exception):
    """A protocol-level failure: an HTTP status and a `{code, content}` body, no checkout."""

    def __init__(self, status: int, code: str, content: str) -> None:
        super().__init__(f"{code}: {content}")
        self.status = status
        self.code = code
        self.content = content

    def body(self) -> dict[str, str]:
        return {"code": self.code, "content": self.content}


def error_message(
    code: str, content: str, severity: Severity, path: str | None = None
) -> dict[str, Any]:
    out: dict[str, Any] = {"type": "error", "code": code, "content": content, "severity": severity}
    if path is not None:
        out["path"] = path
    return out


def warning_message(code: str, content: str, path: str | None = None) -> dict[str, Any]:
    out: dict[str, Any] = {"type": "warning", "code": code, "content": content}
    if path is not None:
        out["path"] = path
    return out


def error_response(messages: list[dict[str, Any]]) -> dict[str, Any]:
    """The body when no resource exists to act on (`common/types/error_response.json`)."""
    if not messages:
        raise ValueError("an error response needs at least one message")
    return {"ucp": {"version": UCP_VERSION, "status": "error"}, "messages": messages}
