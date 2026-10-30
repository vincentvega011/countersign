"""The principal lock. See docs/architecture.md section 5.7 and docs/PROTOCOL.md Decisions 47 to 50.

Imports no protocol adapter and no web framework (tests/unit/test_lock_import_guard.py). The capture
gate does not import this package either: it is wired to it at the composition root.
"""

from countersign.lock.policy import MerchantPolicy, PolicyError
from countersign.lock.principal import Principal, principal_from_chain, principal_from_delegation
from countersign.lock.service import (
    AP2_CAPABILITY,
    LockPort,
    LockRequest,
    LockVerdict,
    PrincipalLock,
)
from countersign.lock.store import LockStore, LockStoreError

__all__ = [
    "AP2_CAPABILITY",
    "LockPort",
    "LockRequest",
    "LockStore",
    "LockStoreError",
    "LockVerdict",
    "MerchantPolicy",
    "PolicyError",
    "Principal",
    "PrincipalLock",
    "principal_from_chain",
    "principal_from_delegation",
]
