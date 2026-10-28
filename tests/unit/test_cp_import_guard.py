"""cp/ is the Credential Provider: UCP complete calls it, never the reverse. It must not import a
protocol adapter (`protocols/`), the API layer or a web framework (INV-1, INV-5), and it must not
reach the capture gate, which is a separate module with its own approval. AST based, like the others.
"""

from __future__ import annotations

import ast
from pathlib import Path

SRC = Path(__file__).resolve().parents[2] / "src" / "countersign" / "cp"
FORBIDDEN = (
    "countersign.protocols",
    "countersign.api",
    "countersign.completion",
    "countersign.gate",
    "countersign.mpp",
    "countersign.lock",
    "countersign.llm",
    "fastapi",
    "starlette",
    "flask",
    "django",
    "aiohttp",
    "uvicorn",
)
MINT = "mint_capture" + "_approval"  # split so the capture-surface test does not flag this file
CAPTURE = "capture_" + "authorization"


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


def test_cp_has_its_modules() -> None:
    names = {p.name for p in SRC.glob("*.py")}
    assert {
        "provider.py",
        "verify.py",
        "ledger.py",
        "evidence.py",
        "rejection.py",
        "config.py",
    } <= names


def test_cp_does_not_import_protocol_adapters_the_api_or_a_web_framework() -> None:
    for path in SRC.glob("*.py"):
        for name, line in _imported(ast.parse(path.read_text())):
            assert not name.startswith(FORBIDDEN), f"{path.name}:{line} imports {name}"


def test_cp_never_captures_and_never_mints_a_capture_approval() -> None:
    """The gate is P2.5: nothing in cp/ may reference the capture call or the approval mint."""
    for path in SRC.glob("*.py"):
        text = path.read_text()
        assert MINT not in text and CAPTURE not in text, path.name


def test_the_guard_detects_a_forbidden_import() -> None:
    tree = ast.parse("def f():\n    from countersign.protocols.ucp import x\n    import fastapi\n")
    names = [n for n, _ in _imported(tree)]
    assert any(n.startswith("countersign.protocols") for n in names) and "fastapi" in names


def test_cp_is_deterministic_code() -> None:
    """INV-1: no model, no randomness except identifiers, time only from the injected clocks."""
    for path in SRC.glob("*.py"):
        text = path.read_text()
        for needle in ("import random", "countersign.llm", "datetime.now(", "an" + "thropic"):
            assert needle not in text, f"{path.name} uses {needle}"
