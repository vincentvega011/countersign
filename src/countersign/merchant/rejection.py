"""Rejections of a Checkout Mandate: the UCP error code, an internal reason, and the UCP message.

Every verification failure is a `Rejection` carrying three things (docs/PROTOCOL.md Decision 26):

- `ucp_code`: exactly one of the seven codes of the vendored AP2 extension. This is what the agent
  sees in the `messages` array (Decision 10).
- `step`: which verification step failed (`M1` to `M8`), recorded in the decision log.
- `reason`: a finer internal code for the log and tests. It is a fixed string chosen here, never
  text taken from the request, so nothing an attacker sends is echoed into a message or a receipt.

The message `content` is a fixed template per UCP code for the same reason.
"""

from __future__ import annotations

from typing import Any

MANDATE_REQUIRED = "mandate_required"
AGENT_MISSING_KEY = "agent_missing_key"
MANDATE_INVALID_SIGNATURE = "mandate_invalid_signature"
MANDATE_EXPIRED = "mandate_expired"
MANDATE_SCOPE_MISMATCH = "mandate_scope_mismatch"
MERCHANT_AUTHORIZATION_INVALID = "merchant_authorization_invalid"
MERCHANT_AUTHORIZATION_MISSING = "merchant_authorization_missing"

UCP_CODES = frozenset(
    {
        MANDATE_REQUIRED,
        AGENT_MISSING_KEY,
        MANDATE_INVALID_SIGNATURE,
        MANDATE_EXPIRED,
        MANDATE_SCOPE_MISMATCH,
        MERCHANT_AUTHORIZATION_INVALID,
        MERCHANT_AUTHORIZATION_MISSING,
    }
)

STEPS = ("M1", "M2", "M3", "M4", "M5", "M7", "M8")  # M6 is the principal lock (P2.6)

_SEVERITY = {
    MANDATE_REQUIRED: "recoverable",
    AGENT_MISSING_KEY: "unrecoverable",
    MANDATE_INVALID_SIGNATURE: "unrecoverable",
    MANDATE_EXPIRED: "unrecoverable",
    MANDATE_SCOPE_MISMATCH: "recoverable",
    MERCHANT_AUTHORIZATION_INVALID: "recoverable",
    MERCHANT_AUTHORIZATION_MISSING: "recoverable",
}

_CONTENT = {
    MANDATE_REQUIRED: "The checkout requires an AP2 checkout mandate.",
    AGENT_MISSING_KEY: "The mandate does not carry a usable agent key.",
    MANDATE_INVALID_SIGNATURE: "The mandate could not be verified.",
    MANDATE_EXPIRED: "The mandate has expired.",
    MANDATE_SCOPE_MISMATCH: "The mandate does not match this checkout.",
    MERCHANT_AUTHORIZATION_INVALID: "The merchant authorization in the mandate is not valid.",
    MERCHANT_AUTHORIZATION_MISSING: "The mandate does not carry the merchant authorization.",
}


class Rejection(Exception):
    """A failed verification step. Raised inside the verifier, returned to callers as a result."""

    def __init__(self, step: str, reason: str, ucp_code: str, detail: str = "") -> None:
        if ucp_code not in UCP_CODES or step not in STEPS:
            raise ValueError("a rejection needs a known step and a UCP error code")
        super().__init__(f"{step} {reason}")
        self.step = step
        self.reason = reason
        self.ucp_code = ucp_code
        self.detail = detail

    def message(self) -> dict[str, Any]:
        """The UCP `messages` entry (type, code, content, severity)."""
        return {
            "type": "error",
            "code": self.ucp_code,
            "content": _CONTENT[self.ucp_code],
            "severity": _SEVERITY[self.ucp_code],
        }
