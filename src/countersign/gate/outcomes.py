"""What the capture gate returns, and the typed failure of one step.

Four outcomes, and nothing else, so a caller cannot mistake "not captured" for "captured":

- `GatePassed`: every step passed on freshly fetched PayPal state, the capture was made and then
  confirmed `COMPLETED` by a GET, and the ledger and reservations were finalized.
- `GateRejected`: a step failed (or anything unexpected happened), the authorization was voided and
  the void confirmed by a GET, and the reservations were released. A signed rejection receipt.
- `GatePending`: another gate holds the claim on this checkout. Nothing was done by this call.
- `GateUnresolved`: PayPal could not be read or a void or capture could not be confirmed. Money
  may be held, so the budget and the open mandate stay reserved (docs/PROTOCOL.md Decision 40).
  No receipt is issued because neither "captured" nor "rejected" is known.
- `GateNotApplicable`: this checkout has no authorized payment attempt for the gate to act on.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any

from countersign.canonical.money import Money

G_FETCH = "G-FETCH"
G_STATUS = "G-STATUS"
G_REVERSE = "G-REVERSE"
G_TERMS = "G-TERMS"
G_AMOUNT = "G-AMOUNT"
G_MANDATE = "G-MANDATE"
G_BUDGET = "G-BUDGET"
G_LOCK = "G-LOCK"
# Not one of the eight checks: the capture itself and its confirmation, which can also fail.
G_CAPTURE = "G-CAPTURE"

STEP_CODES = (G_FETCH, G_STATUS, G_REVERSE, G_TERMS, G_AMOUNT, G_MANDATE, G_BUDGET, G_LOCK)
ALL_CODES = (*STEP_CODES, G_CAPTURE)


class GateFailure(Exception):
    """One step failed. `reason` is a fixed internal string (it goes to the log and the receipt)."""

    def __init__(self, code: str, reason: str, ucp_code: str | None = None) -> None:
        if code not in ALL_CODES:
            raise ValueError("unknown gate code")
        super().__init__(f"{code} {reason}")
        self.code = code
        self.reason = reason[:80]
        self.ucp_code = ucp_code


@dataclass(frozen=True)
class GatePassed:
    checkout_id: str
    order_id: str
    authorization_id: str
    capture_id: str
    amount: Money
    custom_id: str
    receipt: str


@dataclass(frozen=True)
class GateRejected:
    checkout_id: str
    code: str
    reason: str
    ucp_code: str
    receipt: str
    messages: tuple[dict[str, Any], ...]


@dataclass(frozen=True)
class GatePending:
    checkout_id: str
    state: str


@dataclass(frozen=True)
class GateUnresolved:
    checkout_id: str
    code: str
    reason: str


@dataclass(frozen=True)
class GateNotApplicable:
    checkout_id: str
    state: str


GateOutcome = GatePassed | GateRejected | GatePending | GateUnresolved | GateNotApplicable
