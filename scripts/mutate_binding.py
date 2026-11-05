"""Mutation check of the checkout customer binding (L55, docs/PROTOCOL.md Decision 111).

Each mutant replaces one exact piece of source (a check turned off, a refusal turned into a pass, the
wiring dropped), then runs the binding tests in `tests/integration/test_purchase_consent.py`, the
coordinator unit test and the `agent_self_approval` attack case in full mode (judged from PayPal state
and the log). Killed means a test failed or the attack case no longer matched its expectation. The file
is restored after every mutant, also on an interrupt.

    uv run python scripts/mutate_binding.py
"""

from __future__ import annotations

import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
SRC = ROOT / "src" / "countersign"

# (id, file, exact old text, new text, what it breaks)
MUTANTS: list[tuple[str, str, str, str, str]] = [
    ("B01", "trusted_surface/purchase.py",
     "            if not ok:\n                raise ts.refusal_for(BINDING_MISMATCH)",
     "            if False:\n                raise ts.refusal_for(BINDING_MISMATCH)",
     "offer opens for a customer the checkout is not bound to"),
    ("B02", "trusted_surface/purchase.py",
     '            if offer.customer_id is None or offer.customer_id != raw["customer_id"]:',
     "            if False:",
     "consent does not check whom the offer was opened for"),
    ("B03", "trusted_surface/purchase.py",
     '            if owner is None or owner.customer_id != raw["customer_id"]:',
     "            if False:",
     "consent does not re-read the checkout's customer"),
    ("B04", "checkout/binding.py",
     "    return current.customer_id == customer_id, current",
     "    return True, current",
     "an existing binding matches every customer"),
    ("B05", "checkout/binding.py",
     "    if principal is None or not principal.customer_id:\n        return False",
     "    return False",
     "create never binds the delegation's customer"),
    ("B06", "checkout/binding.py",
     "                ok, binding = False, None",
     "                ok, binding = True, None",
     "a chain with no usable customer is admitted at complete"),
    ("B07", "completion.py",
     "        if not self._customer_admitted(checkout.id, named):",
     "        if False:",
     "complete skips the customer check"),
    ("B08", "completion.py",
     ("        except Exception:  # noqa: BLE001 - INV-10: a check that cannot run refuses\n"
      "            return False"),
     ("        except Exception:  # noqa: BLE001 - INV-10: a check that cannot run refuses\n"
      "            return True"),
     "an error in the complete check admits"),
    ("B09", "composition.py",
     "merchant, merchant_store, cp, stage, lock, evidence, binding=binding",
     "merchant, merchant_store, cp, stage, lock, evidence, binding=None",
     "the composition root does not wire the complete check"),
]  # fmt: skip

EQUIVALENT = {
    "B03": "an offer is created only for the customer the checkout is bound to, under the customer "
           "and checkout locks, and the binding never changes (insert only); so when the offer's "
           "customer equals the consenting customer (B02's check) the binding does too. Defence in "
           "depth against a row written by something other than create_offer",
}  # fmt: skip

TESTS = [
    sys.executable, "-m", "pytest", "-x", "-q", "-p", "no:cacheprovider",
    "tests/unit/test_completion_customer_check.py",
    "tests/integration/test_purchase_consent.py",
]  # fmt: skip
ATTACK = [sys.executable, "-m", "eval.run", "--suite", "attacks", "--mode", "full",
          "--case", "agent_self_approval", "--no-write"]  # fmt: skip


def passes() -> bool:
    for command in (TESTS, ATTACK):
        done = subprocess.run(command, cwd=ROOT, capture_output=True, text=True, check=False)
        if done.returncode != 0:
            return False
    return True


def main() -> int:
    if not passes():
        print("the binding tests fail before any mutation; fix them first", file=sys.stderr)
        return 2
    rows = []
    for ident, name, old, new, what in MUTANTS:
        path = SRC / name
        original = path.read_text()
        if original.count(old) != 1:
            print(
                f"{ident}: the text to mutate occurs {original.count(old)} times", file=sys.stderr
            )
            return 2
        try:
            path.write_text(original.replace(old, new))
            survived = passes()
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
        print(f"\n{ident} equivalent: {reason}")
    return 0 if all(r[3] != "SURVIVED" for r in rows) else 1


if __name__ == "__main__":
    raise SystemExit(main())
