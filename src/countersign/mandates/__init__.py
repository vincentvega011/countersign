"""SD-JWT mandate primitives. See docs/architecture.md section 5.3 and docs/PROTOCOL.md 1.2.3.

Pure verification code: no I/O, no web framework, no imports of protocols, paypal, gate or lock
(enforced by tests/unit/test_mandates_import_guard.py).
"""

from countersign.mandates.chain import (
    KNOWN_VCTS,
    VCT_CHECKOUT,
    VCT_CHECKOUT_OPEN,
    VCT_PAYMENT,
    VCT_PAYMENT_OPEN,
    VerifiedChain,
    VerifiedLink,
    verify_chain,
)
from countersign.mandates.cnf import extract_cnf_key
from countersign.mandates.errors import MandateError
from countersign.mandates.structure import MAX_MANDATE_CHARS, RawLink, split_chain
from countersign.mandates.subject import customer_id_of
from countersign.mandates.timecheck import CLOCK_SKEW_SECONDS, Clock

__all__ = [
    "CLOCK_SKEW_SECONDS",
    "KNOWN_VCTS",
    "MAX_MANDATE_CHARS",
    "VCT_CHECKOUT",
    "VCT_CHECKOUT_OPEN",
    "VCT_PAYMENT",
    "VCT_PAYMENT_OPEN",
    "Clock",
    "MandateError",
    "RawLink",
    "VerifiedChain",
    "VerifiedLink",
    "customer_id_of",
    "extract_cnf_key",
    "split_chain",
    "verify_chain",
]
