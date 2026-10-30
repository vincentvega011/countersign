"""The capture gate. See docs/architecture.md section 5.9 and docs/PROTOCOL.md Decisions 41 to 46.

The only package allowed to mint a `CaptureApproval` and therefore to capture (INV-4).
"""

from countersign.gate.gate import CaptureGate, ucp_code_for
from countersign.gate.outcomes import (
    ALL_CODES,
    STEP_CODES,
    GateFailure,
    GateNotApplicable,
    GateOutcome,
    GatePassed,
    GatePending,
    GateRejected,
    GateUnresolved,
)
from countersign.gate.policy import DenyAllLockPolicy, LockDecision, LockPolicy, LockQuery
from countersign.gate.revocation import revoke_mandate

__all__ = [
    "ALL_CODES",
    "STEP_CODES",
    "CaptureGate",
    "DenyAllLockPolicy",
    "GateFailure",
    "GateNotApplicable",
    "GateOutcome",
    "GatePassed",
    "GatePending",
    "GateRejected",
    "GateUnresolved",
    "LockDecision",
    "LockPolicy",
    "LockQuery",
    "revoke_mandate",
    "ucp_code_for",
]
