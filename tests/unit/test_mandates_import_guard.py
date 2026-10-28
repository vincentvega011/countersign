"""mandates/ is pure verification code: it must not reach protocols, paypal, gate, lock or a web
framework (INV-5 keeps policy independent of protocol adapters; INV-1 keeps this deterministic).
AST based: every import statement, including function-local ones, and `importlib` string imports.
"""

from __future__ import annotations

import ast
from pathlib import Path

SRC = Path(__file__).resolve().parents[2] / "src" / "countersign" / "mandates"
FORBIDDEN = (
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
            and node.value.startswith(FORBIDDEN)  # import_module("countersign.gate")
        ):
            found.append((node.value, node.lineno))
    return found


def test_mandates_has_source_files() -> None:
    assert len(list(SRC.glob("*.py"))) >= 8


def test_mandates_does_not_import_protocols_paypal_gate_lock_or_a_web_framework() -> None:
    for path in SRC.glob("*.py"):
        for name, line in _imported(ast.parse(path.read_text())):
            assert not name.startswith(FORBIDDEN), f"{path.name}:{line} imports {name}"


def test_the_guard_detects_a_forbidden_import() -> None:
    tree = ast.parse("def f():\n    from countersign.gate import x\n    import fastapi\n")
    names = [n for n, _ in _imported(tree)]
    assert any(n.startswith("countersign.gate") for n in names)
    assert "fastapi" in names
