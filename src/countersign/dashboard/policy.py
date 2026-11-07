"""The active policy as one read-only snapshot with a hash (docs/PROTOCOL.md Decision 124).

Security reasoning. The snapshot only DESCRIBES what the running code enforces; nothing here (or in the
route that serves it) changes a setting. It is assembled from the real constants the verifier and the gate
use (the constraint handler tables, the gate step codes), the runtime mode and the stored merchant lock
policy, so it cannot drift from the code by hand-editing text. It is serialised with RFC 8785 (the one
canonical library) and hashed with SHA-256; the hash is logged once at start and shown in the Policy
panel. Features that exist only in part are listed as "not enabled" in fixed words: claiming a control
that is not wired would be worse than omitting it (INV-13).
"""

from __future__ import annotations

import hashlib
from typing import Any

from countersign.canonical import canonicalize
from countersign.constraints.checkout import ALLOWED_MERCHANTS, LINE_ITEMS
from countersign.constraints.payment import PAYMENT_HANDLERS
from countersign.gate.outcomes import STEP_CODES
from countersign.runtime import Mode, RuntimeSettings

SNAPSHOT_VERSION = 1

GATE_STEP_TEXT = {
    "G-FETCH": "Fetch the live PayPal order and authorization (never from a cache)",
    "G-STATUS": "The authorization is capturable, unexpired, alone on its order, uncaptured",
    "G-REVERSE": "Re-derive the checkout terms from the live order",
    "G-TERMS": "The live terms equal the signed checkout, with the same invoice id and custom id",
    "G-AMOUNT": "The authorized amount equals the checkout total exactly",
    "G-MANDATE": "Both mandates verify again now, are not revoked, and are still held by this checkout",
    "G-BUDGET": "The budget still holds under the reconciled ledger view",
    "G-LOCK": "The principal lock policy still allows the payment",
    "G-CHECKOUT": "The checkout is still in progress and unexpired when the capture starts",
}

NOT_ENABLED = (
    {
        "id": "unmandated_cap",
        "label": "Cap for purchases without a mandate",
        "status": "not enabled",
    },
    {"id": "velocity_limits", "label": "Velocity limits", "status": "not enabled"},
    {
        "id": "category_policy",
        "label": "Category policy",
        "status": "not enabled",
        "note": "check_category_policy exists but is not wired into the Merchant verifier",
    },
    {
        "id": "editable_policy",
        "label": "Editing and versioning this policy",
        "status": "not enabled",
    },
)


def snapshot(settings: RuntimeSettings, lock_policy: dict[str, Any] | None) -> dict[str, Any]:
    """The policy as plain JSON data. `lock_policy` is the stored merchant lock policy's data."""
    lock = lock_policy or {"version": 0, "mode": "off", "threshold_minor": None, "currency": None}
    return {
        "snapshot_version": SNAPSHOT_VERSION,
        "protection": {
            "mode": "baseline" if settings.mode is Mode.BASELINE else "full",
            "ablations": list(settings.active_ablations),
            "merchant_lock": {
                "version": lock.get("version"),
                "mode": lock.get("mode"),
                "threshold_minor": lock.get("threshold_minor"),
                "currency": lock.get("currency"),
            },
        },
        "constraint_families": {
            "checkout": sorted([LINE_ITEMS, ALLOWED_MERCHANTS]),
            "payment": sorted(PAYMENT_HANDLERS),
        },
        "capture_gate_steps": [
            {"code": code, "check": GATE_STEP_TEXT[code]} for code in STEP_CODES
        ],
        "dashboard": {"read_only": True, "write_endpoints": 0, "login": False},
        "not_enabled": [dict(entry) for entry in NOT_ENABLED],
    }


def canonical_bytes(value: dict[str, Any]) -> bytes:
    return canonicalize(value)


def snapshot_hash(value: dict[str, Any]) -> str:
    """SHA-256 (lowercase hex) of the RFC 8785 bytes of the snapshot."""
    return hashlib.sha256(canonical_bytes(value)).hexdigest()
