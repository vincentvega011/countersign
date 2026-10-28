"""constraints/ is pure evaluation: it must not import merchant/, protocols/, paypal/, gate/, lock/
or a web framework. The Merchant role and the Credential Provider call it, never the reverse, and
it satisfies the Merchant's evaluator interface structurally. AST based, like the other guards.
"""

from __future__ import annotations

import ast
from pathlib import Path

SRC = Path(__file__).resolve().parents[2] / "src" / "countersign" / "constraints"
FORBIDDEN = (
    "countersign.merchant",
    "countersign.cp",
    "countersign.protocols",
    "countersign.paypal",
    "countersign.gate",
    "countersign.lock",
    "countersign.mpp",
    "countersign.api",
    "countersign.llm",
    "fastapi",
    "starlette",
    "flask",
    "django",
    "httpx",
    "requests",
    "aiohttp",
    "uvicorn",
    "sqlalchemy",
)


def _imported(tree: ast.AST) -> list[tuple[str, int]]:
    found: list[tuple[str, int]] = []
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            found += [(alias.name, node.lineno) for alias in node.names]
        elif isinstance(node, ast.ImportFrom):
            base = node.module or ""
            found.append((base, node.lineno))
            found += [(f"{base}.{alias.name}", node.lineno) for alias in node.names]
        elif (
            isinstance(node, ast.Constant)
            and isinstance(node.value, str)
            and node.value.startswith(FORBIDDEN)
        ):
            found.append((node.value, node.lineno))
    return found


def test_constraints_has_its_modules() -> None:
    names = {p.name for p in SRC.glob("*.py")}
    assert {"engine.py", "checkout.py", "payment.py", "budget.py", "policy.py", "flow.py"} <= names


def test_constraints_does_not_import_merchant_protocols_paypal_gate_lock_or_a_web_framework() -> (
    None
):
    for path in SRC.glob("*.py"):
        for name, line in _imported(ast.parse(path.read_text())):
            assert not name.startswith(FORBIDDEN), f"{path.name}:{line} imports {name}"


def test_the_guard_detects_a_forbidden_import() -> None:
    tree = ast.parse(
        "def f():\n    from countersign.merchant.verify import x\n    import fastapi\n"
    )
    names = [n for n, _ in _imported(tree)]
    assert any(n.startswith("countersign.merchant") for n in names) and "fastapi" in names


def test_the_engine_has_no_clock_or_network_of_its_own() -> None:
    """INV-1: time arrives as an argument. No `time`, `datetime.now`, sockets or randomness."""
    for path in SRC.glob("*.py"):
        text = path.read_text()
        for needle in ("datetime.now(", "time.time(", "import socket", "import random", "urllib"):
            assert needle not in text, f"{path.name} uses {needle}"
