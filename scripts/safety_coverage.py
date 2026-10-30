"""Fail if an invariant package is imported by no test or test support module.

`make test-safety` runs the tests of the modules that decide about money, identity and evidence. This
check guards the list itself: a package added to `PACKAGES` without a test importing it, or a test file
that stops importing it, fails here instead of leaving the gate quietly empty. `evidence` and `mpp`
are empty until P3 and are listed so that the day they gain code they must also gain a test.
"""

from __future__ import annotations

import ast
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
PACKAGES = (
    "merchant", "cp", "gate", "lock", "constraints", "canonical", "ledger", "mandates", "webhooks",
    "protocols", "paypal", "degraded", "checkout", "evidence", "mpp",
)  # fmt: skip


def imported(path: Path) -> set[str]:
    tree = ast.parse(path.read_text(encoding="utf-8"))
    found: set[str] = set()
    for node in ast.walk(tree):
        names = []
        if isinstance(node, ast.ImportFrom) and node.module:
            names = [node.module]
        elif isinstance(node, ast.Import):
            names = [a.name for a in node.names]
        for name in names:
            parts = name.split(".")
            if parts[0] == "countersign" and len(parts) > 1:
                found.add(parts[1])
    return found


def main() -> int:
    covered: dict[str, int] = {p: 0 for p in PACKAGES}
    for path in (ROOT / "tests").rglob("*.py"):
        for package in imported(path) & set(PACKAGES):
            covered[package] += 1
    empty = {
        p
        for p in ("evidence", "mpp")
        if not any((ROOT / "src" / "countersign" / p).glob("[!_]*.py"))
    }
    missing = [p for p, n in covered.items() if n == 0 and p not in empty]
    for package, count in covered.items():
        print(
            f"safety: {package:12} {count:3} files"
            + (" (empty package)" if package in empty else "")
        )
    if missing:
        print(f"safety: no test imports {missing}", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
