"""merchant/ verifies mandates and signs receipts; it must not reach a protocol adapter, PayPal or a
web framework (INV-1 deterministic code, INV-5 protection independent of protocols). AST based, like
the mandates guard: every import statement (also function-local) and string imports.
"""

from __future__ import annotations

import ast
from pathlib import Path

SRC = Path(__file__).resolve().parents[2] / "src" / "countersign" / "merchant"
FORBIDDEN = (
    "countersign.protocols",
    "countersign.paypal",
    "countersign.api",
    "countersign.gate",
    "countersign.lock",
    "countersign.mpp",
    "countersign.llm",
    "fastapi",
    "starlette",
    "flask",
    "django",
    "httpx",
    "requests",
    "aiohttp",
    "uvicorn",
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


def test_merchant_has_the_verification_modules() -> None:
    names = {p.name for p in SRC.glob("*.py")}
    assert {
        "verify.py",
        "receipts.py",
        "reservations.py",
        "constraints.py",
        "rejection.py",
    } <= names


def test_merchant_does_not_import_protocols_paypal_or_a_web_framework() -> None:
    for path in SRC.glob("*.py"):
        for name, line in _imported(ast.parse(path.read_text())):
            assert not name.startswith(FORBIDDEN), f"{path.name}:{line} imports {name}"


def test_the_guard_detects_a_forbidden_import() -> None:
    tree = ast.parse("def f():\n    from countersign.protocols.ucp import x\n    import fastapi\n")
    names = [n for n, _ in _imported(tree)]
    assert any(n.startswith("countersign.protocols") for n in names) and "fastapi" in names


def test_verification_modules_use_only_the_mandates_primitives_for_chains() -> None:
    """No second SD-JWT implementation in merchant/: no joserfc JWS parsing of mandates there."""
    text = (SRC / "verify.py").read_text()
    assert "from countersign.mandates import" in text
    assert "deserialize_compact" not in text and "import jws" not in text
