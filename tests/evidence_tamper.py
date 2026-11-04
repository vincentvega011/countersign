"""Tampered evidence bundles, each with the step that must reject it first.

Used by the verifier tests and by `tests/vectors/evidence/tampered/` (the same cases as files, so the
browser verifier of P3.8 can be checked against them). Every function takes a deep copy of a valid
bundle and returns the tampered one. Only synthetic bundle data goes in: nothing here adds a name,
an email or a token.
"""

from __future__ import annotations

import base64
import copy
import json
from collections.abc import Callable
from typing import Any

from countersign_verify import log as vlog
from countersign_verify.crypto import b64url, jcs

Bundle = dict[str, Any]
ALPHABET = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_"


def flip(text: str, at: int) -> str:
    """The same text with one character replaced by a different one of the same alphabet."""
    at %= len(text)
    old = text[at]
    new = ALPHABET[(ALPHABET.index(old) + 1) % len(ALPHABET)] if old in ALPHABET else "x"
    return text[:at] + new + text[at + 1 :]


def _seg(token: str, index: int) -> Any:
    raw = token.split(".")[index]
    return json.loads(base64.urlsafe_b64decode(raw + "=" * (-len(raw) % 4)))


def _put(token: str, index: int, value: Any) -> str:
    parts = token.split(".")
    parts[index] = b64url(json.dumps(value, separators=(",", ":")).encode())
    return ".".join(parts)


def _relog(b: Bundle, entries: list[dict[str, Any]]) -> None:
    """Make the log section self-consistent for `entries` (what a forger with the code could do)."""
    hashes = [vlog.entry_hash(e) for e in entries]
    for e, h in zip(entries, hashes, strict=True):
        e["entry_hash"] = b64url(h)
    root = vlog.root_of(hashes)
    proofs = []
    for i in range(len(hashes)):
        proofs.append(_proof(hashes, i))
    b["log"] = {"entries": entries, "size": len(entries), "root": b64url(root), "proofs": proofs}


def _proof(hashes: list[bytes], index: int) -> dict[str, Any]:
    def path(lo: int, hi: int, i: int) -> list[bytes]:
        if hi - lo == 1:
            return []
        k = 1
        while k * 2 < hi - lo:
            k *= 2
        if i - lo < k:
            return [*path(lo, lo + k, i), vlog.root_of_subtree(hashes[lo + k : hi])]
        return [*path(lo + k, hi, i), vlog.root_of_subtree(hashes[lo : lo + k])]

    return {
        "v": 1, "index": index, "size": len(hashes),
        "path": [b64url(h) for h in path(0, len(hashes), index)],
    }  # fmt: skip


def checkout_amount_raised(b: Bundle) -> None:
    payload = _seg(b["checkout_jwt"], 1)
    for t in payload["totals"]:
        t["amount"] += 100
    b["checkout_jwt"] = _put(b["checkout_jwt"], 1, payload)


def checkout_jwt_signature(b: Bundle) -> None:
    head, body, sig = b["checkout_jwt"].split(".")
    b["checkout_jwt"] = f"{head}.{body}.{flip(sig, 3)}"


def closed_checkout_key_binding(b: Bundle) -> None:
    chain = b["mandates"]["checkout_closed"]
    head, tail = chain.split("~~")
    b["mandates"]["checkout_closed"] = head + "~~" + flip(tail, 80)


def open_checkout_signature(b: Bundle) -> None:
    chain = b["mandates"]["checkout_open"]
    b["mandates"]["checkout_open"] = flip(chain, chain.index(".", chain.index(".") + 1) + 5)
    b["mandates"]["checkout_closed"] = (
        b["mandates"]["checkout_open"] + "~" + b["mandates"]["checkout_closed"].split("~~", 1)[1]
    )


def platform_key_swapped(b: Bundle) -> None:
    other = copy.deepcopy(b["keys"]["merchant"])
    b["keys"]["platform"] = {k: other[k] for k in ("kty", "crv", "x", "y")}


def checkout_receipt_signature(b: Bundle) -> None:
    b["receipts"]["checkout"] = flip(b["receipts"]["checkout"], -4)


def checkout_receipt_reference(b: Bundle) -> None:
    other = b["receipts"]["payment"]
    b["receipts"]["checkout"] = other  # a genuine merchant receipt, but not for this mandate


def payment_closed_signature(b: Bundle) -> None:
    chain = b["mandates"]["payment_closed"]
    head, tail = chain.split("~~")
    b["mandates"]["payment_closed"] = head + "~~" + flip(tail, 60)


def payment_receipt_capture(b: Bundle) -> None:
    b["capture_id"] = "CAP9"
    b["paypal"]["capture"][-1]["id"] = "CAP9"


def consent_removed(b: Bundle) -> None:
    b["consent"] = {}


def consent_key_swapped(b: Bundle) -> None:
    b["consent"]["device_jwk"] = copy.deepcopy(b["keys"]["merchant"])
    for extra in ("alg", "kid", "use"):
        b["consent"]["device_jwk"].pop(extra, None)


def consent_record_altered(b: Bundle) -> None:
    b["consent"]["record"] = flip(b["consent"]["record"], 40)


def consent_signature_altered(b: Bundle) -> None:
    b["consent"]["signature"] = flip(b["consent"]["signature"], 9)


def paypal_capture_amount(b: Bundle) -> None:
    b["paypal"]["capture"][-1]["amount"]["value"] = "4.50"


def paypal_item_name(b: Bundle) -> None:
    b["paypal"]["order"][-1]["purchase_units"][0]["items"][0]["name"] = "Another Product"


def paypal_invoice(b: Bundle) -> None:
    b["paypal"]["authorization"][-1]["invoice_id"] = "chk_somebodyelse"


def paypal_custom_id(b: Bundle) -> None:
    b["paypal"]["order"][-1]["purchase_units"][0]["custom_id"] = "cs1." + "A" * 43


def paypal_status(b: Bundle) -> None:
    b["paypal"]["capture"][-1]["status"] = "PENDING"


def log_last_entry_dropped(b: Bundle) -> None:
    """The newest entry (gate.captured) cut off without touching size or root: the gate result misses it
    first, and the log section disagrees with its own size too."""
    b["log"]["entries"].pop()
    b["log"]["proofs"].pop()


def log_middle_entry_dropped(b: Bundle) -> None:
    b["log"]["entries"].pop(5)
    b["log"]["proofs"].pop(5)


def log_proof_truncated(b: Bundle) -> None:
    b["log"]["proofs"][3]["path"].pop()


def log_proof_dropped(b: Bundle) -> None:
    b["log"]["proofs"].pop()


def log_payload_altered(b: Bundle) -> None:
    entry = b["log"]["entries"][10]
    entry["payload"] = (
        entry["payload"].replace("pass", "fail", 1)
        if "pass" in entry["payload"]
        else (entry["payload"][:-1] + ',"x":1}')
    )


def log_root_altered(b: Bundle) -> None:
    b["log"]["root"] = flip(b["log"]["root"], 2)


def log_consistently_truncated(b: Bundle) -> None:
    """The gate.captured entry removed and the log made self-consistent again."""
    entries = [e for e in b["log"]["entries"] if e["kind"] != "gate.captured"]
    _relog(b, entries)


def gate_step_missing(b: Bundle) -> None:
    entries = [e for e in b["log"]["entries"] if '"G-BUDGET"' not in e["payload"]]
    _relog(b, entries)


def not_captured(b: Bundle) -> None:
    b["gate"]["state"] = "authorized"


def extra_member(b: Bundle) -> None:
    b["surprise"] = 1


def bundle_checkout_id(b: Bundle) -> None:
    b["checkout_id"] = "chk_other"


# name: (tamper, the step that must fail first)
TAMPERS: dict[str, tuple[Callable[[Bundle], None], str]] = {
    "checkout_amount_raised": (checkout_amount_raised, "checkout_mandate"),
    "checkout_jwt_signature": (checkout_jwt_signature, "checkout_mandate"),
    "closed_checkout_key_binding": (closed_checkout_key_binding, "checkout_mandate"),
    "open_checkout_signature": (open_checkout_signature, "checkout_mandate"),
    "platform_key_swapped": (platform_key_swapped, "trusted_keys"),
    "checkout_receipt_signature": (checkout_receipt_signature, "checkout_receipt"),
    "checkout_receipt_reference": (checkout_receipt_reference, "checkout_receipt"),
    "payment_closed_signature": (payment_closed_signature, "payment_mandate"),
    "payment_receipt_capture": (payment_receipt_capture, "payment_receipt"),
    "consent_removed": (consent_removed, "consent_signature"),
    "consent_key_swapped": (consent_key_swapped, "consent_signature"),
    "consent_record_altered": (consent_record_altered, "consent_signature"),
    "consent_signature_altered": (consent_signature_altered, "consent_signature"),
    "paypal_capture_amount": (paypal_capture_amount, "paypal_objects"),
    "paypal_item_name": (paypal_item_name, "paypal_objects"),
    "paypal_invoice": (paypal_invoice, "paypal_objects"),
    "paypal_status": (paypal_status, "paypal_objects"),
    "paypal_custom_id": (paypal_custom_id, "paypal_custom_id"),
    "log_last_entry_dropped": (log_last_entry_dropped, "gate_result"),
    "log_middle_entry_dropped": (log_middle_entry_dropped, "decision_log"),
    "log_proof_truncated": (log_proof_truncated, "decision_log"),
    "log_proof_dropped": (log_proof_dropped, "decision_log"),
    "log_payload_altered": (log_payload_altered, "decision_log"),
    "log_root_altered": (log_root_altered, "decision_log"),
    "log_consistently_truncated": (log_consistently_truncated, "gate_result"),
    "gate_step_missing": (gate_step_missing, "gate_result"),
    "not_captured": (not_captured, "bundle_structure"),
    "extra_member": (extra_member, "bundle_structure"),
    "bundle_checkout_id": (bundle_checkout_id, "checkout_jwt_hash"),
}

_ = jcs  # imported so a reader sees the canonical form the log section is checked against


def write_vectors(valid: Bundle, directory: Any) -> None:
    """Write the valid bundle's pinned keys, every tampered bundle and `index.json` under `directory`."""
    tampered = directory / "tampered"
    tampered.mkdir(parents=True, exist_ok=True)
    index = []
    for name, (tamper, step) in sorted(TAMPERS.items()):
        bundle = copy.deepcopy(valid)
        tamper(bundle)
        (tampered / f"{name}.json").write_text(json.dumps(bundle, indent=1, sort_keys=True) + "\n")
        index.append({"file": f"tampered/{name}.json", "first_failure": step})
    for key in ("merchant", "platform"):
        (directory / f"{key}.key.json").write_text(
            json.dumps(valid["keys"][key], indent=1, sort_keys=True) + "\n"
        )
    (directory / "index.json").write_text(
        json.dumps(
            {"valid": "valid.json", "pinned": ["merchant.key.json", "platform.key.json"],
             "tampered": index}, indent=1, sort_keys=True,
        ) + "\n"
    )  # fmt: skip
