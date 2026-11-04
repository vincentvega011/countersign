"""The shopping agent is a separate process that speaks HTTP only (Decision 98).

Statically: every import in `agents/shopper` is the standard library, a listed third-party package, the
agent's own package, or `countersign.llm`. Nothing of the server's authorization or storage code
(gate, lock, constraints, trusted_surface, openmandates, cp, paypal, tables, ...) is imported, directly
or through any chain: `countersign.llm` itself reaches none of them (tests/unit/test_llm_boundary.py).
"""

from __future__ import annotations

import ast
import sys
from pathlib import Path

from tests.unit.test_llm_boundary import build_graph, reachable

ROOT = Path(__file__).resolve().parents[2]
AGENT = ROOT / "agents" / "shopper"
THIRD_PARTY = {"httpx", "rfc8785", "cryptography"}
ALLOWED_COUNTERSIGN = ("countersign.llm",)


def imports(path: Path) -> list[str]:
    found: list[str] = []
    for node in ast.walk(ast.parse(path.read_text(encoding="utf-8"))):
        if isinstance(node, ast.ImportFrom) and node.module and node.level == 0:
            found.append(node.module)
        elif isinstance(node, ast.Import):
            found.extend(alias.name for alias in node.names)
    return found


def test_the_agent_imports_only_what_a_separate_process_may() -> None:
    files = sorted(AGENT.glob("*.py"))
    assert files
    for path in files:
        for name in imports(path):
            top = name.split(".")[0]
            if top in sys.stdlib_module_names or top in THIRD_PARTY or top == "agents":
                continue
            assert top == "countersign" and any(
                name == ok or name.startswith(ok + ".") for ok in ALLOWED_COUNTERSIGN
            ), f"{path.name} imports {name}"


def test_nothing_server_side_is_reachable_through_the_allowed_import() -> None:
    graph = build_graph()
    reach = reachable(graph, "countersign.llm") | {"countersign.llm"}
    forbidden = (
        "gate", "lock", "constraints", "trusted_surface", "openmandates", "cp", "paypal", "mpp",
        "tables", "merchant", "mandates", "checkout", "ledger", "canonical", "api", "evidence",
    )  # fmt: skip
    hit = [m for m in reach if m.split(".")[1:2] and m.split(".")[1] in forbidden]
    assert not hit, hit


def test_the_boundary_check_would_catch_a_violation(tmp_path: Path) -> None:
    bad = tmp_path / "bad.py"
    bad.write_text("from countersign.gate import CaptureGate\nimport os\n")
    assert "countersign.gate" in imports(bad)
