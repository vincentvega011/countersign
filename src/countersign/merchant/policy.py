"""The merchant policy hash recorded in every decision log entry.

Until the policy settings exist, the policy is fixed: AP2 protection is required for every agent
(INV-3 as the default). The hash is domain separated and computed from the canonical bytes of the
policy document, so changing the policy changes the hash on every later log entry.
"""

from __future__ import annotations

from typing import Any

from countersign.canonical.hashing import domain_hash
from countersign.canonical.jcs import canonicalize

POLICY_DOMAIN = "cs.policy.v1"

# SHORTCUT: a constant policy; versioned, editable policy settings replace this with the policy
# document the merchant saved.
DEFAULT_POLICY: dict[str, Any] = {"version": 1, "protection": "require_ap2_all_agents"}


def policy_hash(policy: dict[str, Any] | None = None) -> bytes:
    return domain_hash(POLICY_DOMAIN, canonicalize(DEFAULT_POLICY if policy is None else policy))
