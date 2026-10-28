"""Credential Provider role. See docs/architecture.md section 5.5 and docs/PROTOCOL.md Decisions 34 to 39."""

from countersign.cp.config import CpConfig
from countersign.cp.evidence import custom_id_for, evidence_reference
from countersign.cp.ledger import SpendLedger
from countersign.cp.provider import (
    CpApprovalRequired,
    CpAuthorized,
    CpOutcome,
    CpPending,
    CpRejected,
    CredentialProvider,
    check_terms,
)
from countersign.cp.rejection import CpRejection
from countersign.cp.verify import VerifiedPayment, verify_payment

__all__ = [
    "CpApprovalRequired",
    "CpAuthorized",
    "CpConfig",
    "CpOutcome",
    "CpPending",
    "CpRejected",
    "CpRejection",
    "CredentialProvider",
    "SpendLedger",
    "VerifiedPayment",
    "check_terms",
    "custom_id_for",
    "evidence_reference",
    "verify_payment",
]
