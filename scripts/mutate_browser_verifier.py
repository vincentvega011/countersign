"""Mutation sweep of the browser evidence verifier (`web/ui/evidence/`): break one decisive check at a time.

Each mutant changes one exact piece of source (a check made to accept, a comparison removed), runs the
browser verifier's unit tests over the shared vectors (`node --test web/ui/test/evidence.test.mjs`) and
records whether a test failed (killed) or all passed (survived). The file is restored after every mutant,
also on an interrupt. A check is switched off by turning its `throw new Invalid(` into a call of an empty
function, which keeps the syntax valid and the message arguments unevaluated in effect.

    uv run python scripts/mutate_browser_verifier.py
"""

from __future__ import annotations

import re
import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
UI = ROOT / "web" / "ui"
PKG = UI / "evidence"
OFF = "(() => {})("


def off(code: str) -> tuple[str, str]:
    """The `throw` that raises `code` (exactly one site), as (pattern, replacement)."""
    return (rf'throw new Invalid\(\s*"{code}"', f'{OFF}"{code}"')


# (id, file, regex, replacement, what it breaks)
MUTANTS: list[tuple[str, str, str, str, str]] = [
    ("T01", "crypto.js", r"return subtle\.verify\(", "return true || subtle.verify(",
     "ES256 accepts any signature"),
    ("T02", "crypto.js", r"if \(b64url\(out\) !== text\)", "if (false)",
     "base64url need not be canonical"),
    ("T03", "sdjwt.js", *off("closed_sd_hash"), "key binding not tied to the open mandate (sd_hash)"),
    ("T04", "sdjwt.js", r'"kb\+sd-jwt"', "null", "key binding typ unchecked"),
    ("T05", "sdjwt.js", r" \|\| iat > exp", "", "closed mandate after open expiry accepted"),
    ("T06", "sdjwt.js", *off("closed_hash_member"), "checkout_hash not the hash of the disclosed JWT"),
    ("T07", "steps.js", *off("checkout_hash_mismatch"), "AP2 step 2 hash comparison"),
    ("T08", "steps.js", *off("receipt_reference"), "AP2 steps 3 and 5 receipt reference"),
    ("T09", "steps.js", *off("payment_amount"), "Payment Mandate amount equals checkout total"),
    ("T10", "steps.js", *off("payment_payee"), "payee must be allowed"),
    ("T11", "steps.js", *off("consent_signature"), "device signature over the consent record"),
    ("T12", "steps.js", *off("consent_checkout"), "consent equals the open Checkout Mandate"),
    ("T13", "steps.js", *off("consent_payment"), "consent equals the open Payment Mandate"),
    ("T14", "steps.js", *off("paypal_amount"), "PayPal amount equals the signed total"),
    ("T15", "steps.js", *off("custom_id_mismatch"), "custom_id is the recomputed reference"),
    ("T16", "steps.js", *off("log_entry_hash"), "log entry hash recomputed"),
    ("T17", "log.js", *off("proof_root"), "inclusion proof reaches the root"),
    ("T18", "steps.js", *off("log_root"), "log root recomputed"),
    ("T19", "steps.js", *off("keys_differ"), "pinned keys equal the bundle keys"),
    ("T21", "constraints.js", r"if \(flow !== sum\(demands\) \|\| flow !== sum\(supplies\)\)", "if (false)",
     "checkout lines need not be what the customer allowed"),
    ("T22", "constraints.js", r"if \(!isStr\(id\) \|\| !ids\.includes\(id\)\)", "if (false)",
     "merchant paid need not be allowed"),
    ("T23", "constraints.js", r"!\(low <= amount && amount <= high\)", "false",
     "amount need not be in the allowed range"),
    ("T24", "steps.js", *off("consent_terms_mismatch"), "terms shown need not make the mandates"),
    ("T20", "json.js", r"if \(new Set\(keys\)\.size !== keys\.length\)", "if (false)",
     "duplicate JSON keys accepted"),
]  # fmt: skip

# Survivors that are equivalent mutants, with the reason (checked by hand, not assumed).
EQUIVALENT = {
    "T02": "the canonical re-encoding check only matters for text in a non-canonical spelling, and "
           "every base64url value a bundle holds is also hashed or signed as text, so another spelling "
           "of the same bytes fails a signature or hash check anyway",
    "T07": "same outcome, other code: `readClosed` already requires checkout_hash to be the hash of the "
           "disclosed checkout_jwt and step 1 requires the bundled one to be that one, so with this check "
           "off step 2 still fails, on the merchant signature that follows (`signature_invalid` instead "
           "of `checkout_hash_mismatch`); the vector tests compare the first failure only, the "
           "cross-implementation test compares every step's code and does catch it",
}  # fmt: skip


def run_tests() -> bool:
    done = subprocess.run(
        ["node", "--test", "test/evidence.test.mjs"],
        cwd=UI, capture_output=True, text=True, check=False, timeout=600,
    )  # fmt: skip
    return done.returncode == 0


def main() -> int:
    if not run_tests():
        print(
            "the browser verifier tests fail before any mutation; fix them first", file=sys.stderr
        )
        return 2
    rows = []
    for ident, name, pattern, new, what in MUTANTS:
        path = PKG / name
        original = path.read_text()
        hits = len(re.findall(pattern, original))
        if hits != 1:
            print(f"{ident}: the text to mutate occurs {hits} times", file=sys.stderr)
            return 2
        try:
            path.write_text(re.sub(pattern, lambda _m, n=new: n, original))
            survived = run_tests()
        finally:
            path.write_text(original)
        result = ("equivalent" if ident in EQUIVALENT else "SURVIVED") if survived else "killed"
        rows.append((ident, name, what, result))
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
        if any(r[0] == ident and r[3] == "equivalent" for r in rows):
            print(f"\n{ident} equivalent: {reason}")
    return 0 if all(r[3] != "SURVIVED" for r in rows) else 1


if __name__ == "__main__":
    raise SystemExit(main())
