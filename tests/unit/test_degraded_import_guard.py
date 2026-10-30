"""The weakened implementations are reachable only from the composition root (docs/PROTOCOL.md Decision 59).

Structural, over the syntax trees: no module outside `countersign/degraded/` and `composition.py`
imports `countersign.degraded`, and `composition.py` imports it only inside a function, so importing
the application in `full` mode does not even load it.
"""

from __future__ import annotations

import ast
from pathlib import Path

SRC = Path(__file__).resolve().parents[2] / "src" / "countersign"


def _imports(tree: ast.AST) -> list[tuple[str, int]]:
    found = []
    for node in ast.walk(tree):
        if isinstance(node, ast.ImportFrom) and node.module:
            found.append((node.module, node.lineno))
        elif isinstance(node, ast.Import):
            found.extend((a.name, node.lineno) for a in node.names)
    return [(m, n) for m, n in found if m.split(".")[:2] == ["countersign", "degraded"]]


def test_only_the_composition_root_imports_the_degraded_package() -> None:
    offenders = []
    for path in SRC.rglob("*.py"):
        rel = path.relative_to(SRC).as_posix()
        if rel.startswith("degraded/") or rel == "composition.py":
            continue
        for module, line in _imports(ast.parse(path.read_text())):
            offenders.append(f"{rel}:{line} imports {module}")
    assert not offenders, offenders


def test_the_composition_root_imports_it_lazily_and_only_in_the_modes_that_use_it() -> None:
    tree = ast.parse((SRC / "composition.py").read_text())
    top_level = [n for n in tree.body if isinstance(n, ast.Import | ast.ImportFrom) and _imports(n)]
    assert top_level == [], "composition.py must import countersign.degraded inside functions"
    assert _imports(tree), "the composition root is expected to use the degraded package"


def test_the_invariant_modules_know_nothing_about_modes() -> None:
    """Mode logic stays at the root: no invariant module reads the mode or the baseline."""
    names = ("Mode.BASELINE", "CS_MODE", "RuntimeSettings", "countersign.degraded")
    for package in (
        "merchant",
        "cp",
        "gate",
        "lock",
        "constraints",
        "canonical",
        "ledger",
        "evidence",
    ):
        for path in (SRC / package).rglob("*.py"):
            text = path.read_text()
            for name in names:
                assert name not in text, f"{path.relative_to(SRC)} mentions {name}"
