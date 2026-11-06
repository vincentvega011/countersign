"""The few evidence bundles the dashboard offers to try in the Evidence view (docs/PROTOCOL.md Decision 120).

Security reasoning. The set is an exact table of names to committed test vectors, built here; nothing
is joined from a request, so no path can be steered (an unknown name is a 404, and the 404 tests cover
traversal shapes). The vectors are synthetic (a test scans them), signed with throwaway keys, and the
public keys needed to pin them are served with them. Each entry says which step the verifier must fail
at, taken from the vectors' own index, so a changed vector that stopped failing there is visible in a test.
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

VECTORS = Path(__file__).resolve().parents[3] / "tests" / "vectors" / "evidence"

# name -> (label, file under VECTORS)
SAMPLES: dict[str, tuple[str, str]] = {
    "valid": ("A recorded bundle that verifies", "valid.json"),
    "amount-raised": (
        "Tampered: the checkout amount was raised", "tampered/checkout_amount_raised.json",
    ),
    "custom-id": (
        "Tampered: the PayPal custom_id was changed", "tampered/paypal_custom_id.json",
    ),
    "payee": (
        "Forged: a payee the customer did not allow", "forged/a_payee_the_customer_did_not_allow.json",
    ),
}  # fmt: skip


def listing() -> list[dict[str, str]]:
    return [{"name": n, "label": label} for n, (label, _) in SAMPLES.items()]


def sample(name: str) -> dict[str, Any] | None:
    entry = SAMPLES.get(name)
    if entry is None:
        return None
    label, relative = entry
    try:
        text = (VECTORS / relative).read_text(encoding="utf-8")
        index = json.loads((VECTORS / "index.json").read_text(encoding="utf-8"))
        pinned = {
            "merchant": json.loads((VECTORS / "merchant.key.json").read_text(encoding="utf-8")),
            "platform": json.loads((VECTORS / "platform.key.json").read_text(encoding="utf-8")),
        }
    except (OSError, ValueError):
        return None
    expected: str | None = None
    for group in ("tampered", "forged"):
        for row in index.get(group, []):
            if row.get("file") == relative:
                expected = row.get("first_failure")
    # The forged vectors are signed with their own throwaway keys, so the shared public keys do not
    # apply to them: they are checked against the keys in the bundle, like any unpinned bundle.
    return {
        "name": name, "label": label, "bundle_text": text,
        "pinned": None if relative.startswith("forged/") else pinned,
        "expected_first_failure": expected,
    }  # fmt: skip
