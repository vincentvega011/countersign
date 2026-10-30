"""gate/ is deterministic code that decides about money (INV-1, INV-4, INV-5).

AST based, like the other guards. It must not import a protocol adapter, the lock, the API, a web
framework, or any model or agent code; it must not read from a cache, a global, or a memoized PayPal
result; and the capture and the approval mint may appear nowhere outside it.
"""

from __future__ import annotations

import ast
from pathlib import Path

import pytest

SRC = Path(__file__).resolve().parents[2] / "src" / "countersign"
GATE = SRC / "gate"
FORBIDDEN = (
    "countersign.protocols",
    "countersign.lock",
    "countersign.api",
    "countersign.completion",
    "countersign.llm",
    "agents",
    "fastapi",
    "starlette",
    "flask",
    "django",
    "aiohttp",
    "uvicorn",
    "openai",
)
# `__all__` and the two read-only message tables of gate.py (UCP error text and severity).
READ_ONLY_TABLES = {"__all__", "_CONTENT", "_SEVERITY"}
CACHES = ("lru_cache", "cache", "cached_property", "memoize", "memoized", "TTLCache", "LRUCache")


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


def test_gate_has_its_modules() -> None:
    names = {p.name for p in GATE.glob("*.py")}
    assert {"gate.py", "steps.py", "store.py", "policy.py", "outcomes.py"} <= names


def test_gate_imports_no_adapter_lock_framework_or_model_code() -> None:
    for path in GATE.glob("*.py"):
        for name, line in _imported(ast.parse(path.read_text())):
            assert not name.startswith(FORBIDDEN), f"{path.name}:{line} imports {name}"


def test_the_guard_detects_a_forbidden_import() -> None:
    tree = ast.parse("from countersign.lock import x\nimport fastapi\nimport countersign.llm\n")
    names = [n for n, _ in _imported(tree)]
    assert "countersign.lock" in names and "fastapi" in names and "countersign.llm" in names


def test_gate_reads_from_no_cache_global_or_memoized_paypal_result() -> None:
    for path in GATE.glob("*.py"):
        tree = ast.parse(path.read_text())
        for node in ast.walk(tree):
            if isinstance(node, ast.Global | ast.Nonlocal):
                pytest.fail(f"{path.name}:{node.lineno} uses global state")
            names = []
            if isinstance(node, ast.FunctionDef | ast.AsyncFunctionDef):
                names = [ast.unparse(d) for d in node.decorator_list]
            elif isinstance(node, ast.Attribute):
                names = [node.attr]
            elif isinstance(node, ast.Name):
                names = [node.id]
            for name in names:
                assert not any(c in name for c in CACHES), f"{path.name}:{node.lineno} {name}"
        # Module level: constants only, no mutable container that could hold a fetched object.
        for node in tree.body:
            if isinstance(node, ast.Assign | ast.AnnAssign) and node.value is not None:
                targets = node.targets if isinstance(node, ast.Assign) else [node.target]
                declared = {getattr(t, "id", "") for t in targets}
                if declared <= READ_ONLY_TABLES:
                    continue
                bad = isinstance(node.value, ast.Dict | ast.List | ast.Set | ast.ListComp)
                assert not bad, (
                    f"{path.name}:{node.lineno} holds a mutable container at module level"
                )


def test_gate_instances_keep_no_paypal_object_between_calls() -> None:
    """The gate class assigns only configuration in `__init__`; fetched state is local to a call."""
    tree = ast.parse((GATE / "gate.py").read_text())
    cls = next(n for n in tree.body if isinstance(n, ast.ClassDef) and n.name == "CaptureGate")
    for fn in cls.body:
        if not isinstance(fn, ast.FunctionDef) or fn.name == "__init__":
            continue
        for node in ast.walk(fn):
            if isinstance(node, ast.Assign):
                for target in node.targets:
                    assert not (
                        isinstance(target, ast.Attribute)
                        and isinstance(target.value, ast.Name)
                        and target.value.id == "self"
                    ), f"{fn.name}:{node.lineno} stores state on the gate instance"


def test_only_the_gate_may_reference_the_capture_or_the_mint() -> None:
    mint, capture = "mint_capture" + "_approval", "capture_" + "authorization"
    for path in SRC.rglob("*.py"):
        rel = path.relative_to(SRC).as_posix()
        text = path.read_text()
        if rel.startswith(("gate/", "mpp/", "degraded/")) or rel in (
            "paypal/approval.py",
            "paypal/client.py",
        ):
            continue
        assert mint not in text and capture not in text, rel
