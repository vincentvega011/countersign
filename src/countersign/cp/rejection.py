"""Rejections of a Payment Mandate: UCP error code, internal step and reason (Decision 35).

Same vocabulary as the Merchant role (`merchant/rejection.py`): one of the seven UCP codes of the
vendored AP2 extension for the agent, plus a step (`C1` to `C8`) and a fixed internal reason for the
log. Messages use fixed text so nothing from the request is echoed.
"""

from __future__ import annotations

from typing import Any

from countersign.merchant.rejection import (
    AGENT_MISSING_KEY,
    MANDATE_EXPIRED,
    MANDATE_INVALID_SIGNATURE,
    MANDATE_REQUIRED,
    MANDATE_SCOPE_MISMATCH,
)

# A standard UCP error ("Payment processing failed", vendored `shopping/checkout/index.md`, "Standard
# Errors"), not one of the seven AP2 mandate codes. It is used for everything that fails after the
# mandates verified: a PayPal error, an internal error, a log failure (docs/PROTOCOL.md Decision 35).
PAYMENT_FAILED = "payment_failed"

__all__ = [
    "AGENT_MISSING_KEY",
    "MANDATE_EXPIRED",
    "MANDATE_INVALID_SIGNATURE",
    "MANDATE_REQUIRED",
    "MANDATE_SCOPE_MISMATCH",
    "PAYMENT_FAILED",
    "STEPS",
    "CpRejection",
]

# C1 present, C2 chains, C3 transaction_id, C4 payee/amount/currency, C5 constraints,
# C6 reservation, C7 PayPal order and payer approval, C8 pre-authorize check and authorization.
STEPS = ("C1", "C2", "C3", "C4", "C5", "C6", "C7", "C8")

_SEVERITY = {
    MANDATE_REQUIRED: "recoverable",
    AGENT_MISSING_KEY: "unrecoverable",
    MANDATE_INVALID_SIGNATURE: "unrecoverable",
    MANDATE_EXPIRED: "unrecoverable",
    MANDATE_SCOPE_MISMATCH: "recoverable",
    PAYMENT_FAILED: "recoverable",
}
_CONTENT = {
    MANDATE_REQUIRED: "The checkout requires an AP2 payment mandate.",
    AGENT_MISSING_KEY: "The mandate does not carry a usable agent key.",
    MANDATE_INVALID_SIGNATURE: "The payment mandate could not be verified.",
    MANDATE_EXPIRED: "The payment mandate has expired.",
    MANDATE_SCOPE_MISMATCH: "The payment mandate does not match this checkout.",
    PAYMENT_FAILED: "The payment could not be processed.",
}


class CpRejection(Exception):
    def __init__(self, step: str, reason: str, ucp_code: str, detail: str = "") -> None:
        if step not in STEPS or ucp_code not in _CONTENT:
            raise ValueError("a rejection needs a known step and a UCP error code")
        super().__init__(f"{step} {reason}")
        self.step, self.reason, self.ucp_code, self.detail = step, reason, ucp_code, detail

    def message(self) -> dict[str, Any]:
        return {
            "type": "error",
            "code": self.ucp_code,
            "content": _CONTENT[self.ucp_code],
            "severity": _SEVERITY[self.ucp_code],
        }
