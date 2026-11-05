"""Mutation sweep of the offline evidence verifier: break one decisive check at a time, run its tests.

Each mutant replaces one exact piece of source in `countersign_verify/` (a comparison turned off, a
signature check made to accept, a binding dropped), runs `tests/unit/test_verify_evidence.py` and records
whether a test failed (killed) or all passed (survived). The file is restored after every mutant, also on
an interrupt. A survivor is either an equivalent mutant (no observable difference, with the reason) or a
gap in the tests, and the table says which.

    uv run python scripts/mutate_verifier.py
"""

from __future__ import annotations

import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
PKG = ROOT / "countersign_verify"

# (id, file, exact old text, new text, what it breaks)
MUTANTS: list[tuple[str, str, str, str, str]] = [
    (
        "M01",
        "crypto.py",
        "    except InvalidSignature:\n        return False",
        "    except InvalidSignature:\n        return True",
        "ES256 accepts a bad signature",
    ),
    (
        "M02",
        "crypto.py",
        "    if len(raw) != 64:\n        return False\n    der",
        "    der",
        "signature length check removed",
    ),
    (
        "M03",
        "crypto.py",
        "    if b64url(raw) != text:",
        "    if False:",
        "non canonical base64url accepted",
    ),
    (
        "M04",
        "crypto.py",
        "    if len(set(keys)) != len(keys):",
        "    if False:",
        "duplicate JSON keys accepted",
    ),
    (
        "M05",
        "crypto.py",
        '    if typ is not None and header.get("typ") != typ:',
        "    if False:",
        "JWS typ not checked",
    ),
    (
        "M06",
        "crypto.py",
        '    if not isinstance(header, dict) or header.get("alg") != "ES256":',
        "    if not isinstance(header, dict):",
        "JWS alg not checked",
    ),
    (
        "M07",
        "sdjwt.py",
        '    if payload.get("sd_hash") != digest(open_serialization):',
        "    if False:",
        "key binding not bound to the open mandate",
    ),
    (
        "M08",
        "sdjwt.py",
        '    if payload.get("aud") != audience:',
        "    if False:",
        "key binding audience not checked",
    ),
    (
        "M09",
        "sdjwt.py",
        "    if not is_int(iat) or not is_int(exp) or iat > exp:",
        "    if False:",
        "closed after open expiry accepted",
    ),
    (
        "M10",
        "sdjwt.py",
        "    if content.get(hash_member) != digest(cj[2]):",
        "    if False:",
        "checkout_hash not tied to the checkout_jwt",
    ),
    (
        "M11",
        "sdjwt.py",
        '    if set(disclosed) != {payload["delegate_payload"][0]["..."], hidden[0]}:',
        "    if False:",
        "unreferenced disclosure accepted (closed)",
    ),
    (
        "M12",
        "steps.py",
        '        if opened != self.mandate("checkout_open"):',
        "        if False:",
        "closed checkout not tied to the bundled open mandate",
    ),
    (
        "M13",
        "steps.py",
        '    if closed.checkout_jwt != b.raw["checkout_jwt"]:',
        "    if False:",
        "bundled checkout_jwt not the disclosed one",
    ),
    (
        "M14",
        "steps.py",
        '    if digest(b.raw["checkout_jwt"]) != closed.content["checkout_hash"]:',
        "    if False:",
        "AP2 step 2 hash comparison",
    ),
    (
        "M15",
        "steps.py",
        '    if claims.get("reference") != digest(mandate_link):',
        "    if False:",
        "AP2 steps 3 and 5 reference comparison",
    ),
    (
        "M16",
        "steps.py",
        '    if not isinstance(claims, dict) or claims.get("status") != "Success":',
        "    if not isinstance(claims, dict):",
        "receipt status not checked",
    ),
    (
        "M17",
        "steps.py",
        '    if pcl.content["transaction_id"] != ccl.content["checkout_hash"]:',
        "    if False:",
        "AP2 step 4 scoping to the checkout",
    ),
    (
        "M18",
        "steps.py",
        '    if not same(pcl.content.get("payment_amount"), {"amount": total, "currency": currency}):',
        "    if False:",
        "payment amount equals checkout total",
    ),
    (
        "M19",
        "steps.py",
        '    if len(allowed) != 1 or not any(same(payee, p) for p in allowed[0].get("allowed", [])):',
        "    if False:",
        "payee must be allowed",
    ),
    (
        "M20",
        "steps.py",
        '    if len(budget) != 1 or not is_int(budget[0].get("max")) or total > budget[0]["max"]:',
        "    if False:",
        "total within the budget",
    ),
    (
        "M21",
        "steps.py",
        "    if not verify_es256(device, text.encode(), signature):",
        "    if False:",
        "device signature check",
    ),
    (
        "M22",
        "steps.py",
        '    if record.get("device_thumbprint") != thumbprint(device):',
        "    if False:",
        "device key matches the record",
    ),
    (
        "M23",
        "steps.py",
        '    if not same(signed.get("checkout"), checkout):',
        "    if False:",
        "signed terms equal the open Checkout Mandate",
    ),
    (
        "M24",
        "steps.py",
        '    if not same(signed.get("payment"), payment):',
        "    if False:",
        "signed terms equal the open Payment Mandate",
    ),
    (
        "M25",
        "steps.py",
        '    if minor(obj.get("amount")) != (total, currency):\n        raise Invalid("paypal_amount"',
        '    if False:\n        raise Invalid("paypal_amount"',
        "PayPal amount equals the signed total",
    ),
    (
        "M26",
        "steps.py",
        '    if capture.get("status") != "COMPLETED" or capture.get("final_capture") is not True:',
        "    if False:",
        "capture completed and final",
    ),
    (
        "M27",
        "steps.py",
        "    if not all(isinstance(f, str) and f == want for f in found):",
        "    if False:",
        "custom_id is the recomputed reference",
    ),
    (
        "M28",
        "steps.py",
        '        if not same(steps.get(code), ["pass"]):',
        "        if False:",
        "every gate step passed once",
    ),
    (
        "M29",
        "steps.py",
        '    if not same(captured.get("reference"), claims.get("reference")):',
        "    if False:",
        "gate.captured agrees with the receipt",
    ),
    (
        "M30",
        "steps.py",
        '        if b64url(computed) != e["entry_hash"]:',
        "        if False:",
        "log entry hash recomputed",
    ),
    (
        "M31",
        "steps.py",
        '    if b64url(root) != log["root"]:',
        "    if False:",
        "log root recomputed",
    ),
    (
        "M32",
        "steps.py",
        '    if not same(log["size"], len(entries)) or len(proofs) != len(entries):',
        "    if False:",
        "log size and proof count",
    ),
    (
        "M33",
        "log.py",
        '    if domain_hash("cs.merkle.root.v1", u64(size) + top) != root:',
        "    if False:",
        "inclusion proof reaches the root",
    ),
    (
        "M34",
        "steps.py",
        '        if thumbprint(b.pinned[name]) != thumbprint(b.raw["keys"].get(name)):',
        "        if False:",
        "pinned keys equal the bundle keys",
    ),
    ("M35", "steps.py", "    if len(payees) != 1:", "    if False:", "payee stable across reads"),
]

# Survivors that are equivalent mutants, with the reason (checked by hand, not assumed).
EQUIVALENT = {
    "M02": "a signature of another length can never verify: a short one splits into a different "
           "(r, s) and an over-long one makes s too large, so the ECDSA check rejects it anyway",
    "M14": "the same comparison already runs twice earlier: `read_closed` requires checkout_hash to "
           "equal the hash of the disclosed checkout_jwt, and the checkout_mandate step requires the "
           "bundled checkout_jwt to be that disclosed one; this line is defence in depth",
}  # fmt: skip


def run_tests() -> bool:
    done = subprocess.run(
        [sys.executable, "-m", "pytest", "tests/unit/test_verify_evidence.py", "-x", "-q",
         "-p", "no:cacheprovider"],
        cwd=ROOT, capture_output=True, text=True, check=False,
    )  # fmt: skip
    return done.returncode == 0


def main() -> int:
    if not run_tests():
        print("the verifier tests fail before any mutation; fix them first", file=sys.stderr)
        return 2
    rows = []
    for ident, name, old, new, what in MUTANTS:
        path = PKG / name
        original = path.read_text()
        if original.count(old) != 1:
            print(
                f"{ident}: the text to mutate occurs {original.count(old)} times", file=sys.stderr
            )
            return 2
        try:
            path.write_text(original.replace(old, new))
            survived = run_tests()
        finally:
            path.write_text(original)
        rows.append((ident, name, what, ("equivalent" if ident in EQUIVALENT else "SURVIVED")
                     if survived else "killed"))  # fmt: skip
        print(rows[-1], flush=True)
    killed = sum(1 for r in rows if r[3] == "killed")
    equivalent = sum(1 for r in rows if r[3] == "equivalent")
    print(
        f"\n{killed} of {len(rows)} mutants killed, {equivalent} equivalent, "
        f"{len(rows) - killed - equivalent} unexplained survivors"
    )
    print("\n| id | file | what it breaks | result |\n|---|---|---|---|")
    for ident, name, what, result in rows:
        print(f"| {ident} | {name} | {what} | {result} |")
    for ident, reason in EQUIVALENT.items():
        print(f"\n{ident} equivalent: {reason}")
    return 0 if all(r[3] != "SURVIVED" for r in rows) else 1


if __name__ == "__main__":
    raise SystemExit(main())
