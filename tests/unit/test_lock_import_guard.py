"""lock/, constraints/ and the policy path must not import a protocol adapter (INV-5), and the gate
must not import lock/. Also no web framework and no model code in the lock (INV-1). AST based."""

from __future__ import annotations

import ast
from pathlib import Path

SRC = Path(__file__).resolve().parents[2] / "src" / "countersign"
PROTOCOLS = ("countersign.protocols", "countersign.api")
FRAMEWORKS = ("fastapi", "starlette", "flask", "django", "aiohttp", "uvicorn")
MODELS = ("countersign.llm", "agents", "openai")
# The policy path: everything that decides whether AP2 is required, however it is spelled.
POLICY_PATH = [
    *sorted((SRC / "lock").glob("*.py")),
    *sorted((SRC / "constraints").glob("*.py")),
    SRC / "merchant" / "policy.py",
    SRC / "gate" / "policy.py",
]


def imported(path: Path) -> list[tuple[str, int]]:
    found: list[tuple[str, int]] = []
    for node in ast.walk(ast.parse(path.read_text())):
        if isinstance(node, ast.Import):
            found += [(a.name, node.lineno) for a in node.names]
        elif isinstance(node, ast.ImportFrom):
            base = node.module or ""
            found.append((base, node.lineno))
            found += [(f"{base}.{a.name}", node.lineno) for a in node.names]
        elif (
            isinstance(node, ast.Constant)
            and isinstance(node.value, str)
            and node.value.startswith((*PROTOCOLS, *FRAMEWORKS))
        ):
            found.append((node.value, node.lineno))
    return found


def test_the_policy_path_is_not_empty() -> None:
    assert len(POLICY_PATH) >= 12 and all(p.exists() for p in POLICY_PATH)


def test_the_policy_path_imports_no_protocol_adapter_framework_or_model_code() -> None:
    for path in POLICY_PATH:
        for name, line in imported(path):
            assert not name.startswith((*PROTOCOLS, *FRAMEWORKS, *MODELS)), (
                f"{path.relative_to(SRC)}:{line} imports {name}"
            )


def test_the_gate_does_not_import_the_lock() -> None:
    for path in sorted((SRC / "gate").glob("*.py")):
        for name, line in imported(path):
            assert not name.startswith("countersign.lock"), f"{path.name}:{line} imports {name}"


def test_nothing_under_lock_reaches_the_network_a_clock_or_randomness() -> None:
    for path in sorted((SRC / "lock").glob("*.py")):
        text = path.read_text()
        for needle in ("import httpx", "import requests", "import random", "datetime.now(", "uuid"):
            assert needle not in text, f"{path.name} uses {needle}"


def test_the_guard_detects_a_forbidden_import(tmp_path: Path) -> None:
    sample = tmp_path / "bad.py"
    sample.write_text("from countersign.protocols.ucp import service\nimport fastapi\n")
    names = [n for n, _ in imported(sample)]
    assert any(n.startswith("countersign.protocols") for n in names) and "fastapi" in names


def test_the_provisional_lock_adapter_is_gone() -> None:
    assert not (SRC / "provisional_lock.py").exists()
    for path in SRC.rglob("*.py"):
        text = path.read_text()
        assert "provisional_lock" not in text and "ProvisionalLock" not in text, path.name
