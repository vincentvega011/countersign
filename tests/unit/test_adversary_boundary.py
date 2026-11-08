"""The adversary is a separate process that speaks HTTP only (Decision 130).

Every import in `agents/adversary` is the standard library, `httpx` or the package itself. Nothing from
`countersign` (so no PayPal client, no database, no key loader) and nothing from `eval` or `tests`.
No environment variable is read, so no credential can reach it.
"""

from __future__ import annotations

import ast
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
AGENT = ROOT / "agents" / "adversary"
THIRD_PARTY = {"httpx"}
SECRET_WORDS = ("PAYPAL", "DATABASE", "SECRET", "environ", "getenv")


def imports(path: Path) -> list[str]:
    found: list[str] = []
    for node in ast.walk(ast.parse(path.read_text(encoding="utf-8"))):
        if isinstance(node, ast.ImportFrom) and node.module and node.level == 0:
            found.append(node.module)
        elif isinstance(node, ast.Import):
            found.extend(alias.name for alias in node.names)
    return found


def test_the_adversary_imports_only_what_a_separate_process_may() -> None:
    files = sorted(AGENT.glob("*.py"))
    assert len(files) >= 5
    for path in files:
        for name in imports(path):
            top = name.split(".")[0]
            assert top in sys.stdlib_module_names or top in THIRD_PARTY or top == "agents", (
                f"{path.name} imports {name}"
            )
            assert not name.startswith(("agents.shopper", "countersign", "eval", "tests"))


def test_the_adversary_reads_no_environment_and_names_no_credential() -> None:
    for path in sorted(AGENT.glob("*.py")):
        text = path.read_text(encoding="utf-8")
        for word in SECRET_WORDS:
            assert word not in text, f"{path.name} mentions {word}"


def test_the_boundary_check_would_catch_a_violation(tmp_path: Path) -> None:
    bad = tmp_path / "bad.py"
    bad.write_text("from countersign.paypal.client import PayPalClient\n")
    assert "countersign.paypal.client" in imports(bad)
