"""The authorization boundary: no model code decides anything (INV-1, Decision 95).

Statically, from the import graph of `src/countersign`: no module of an authorization package imports
`countersign.llm`, directly or through any chain of countersign modules, and the `llm` package imports no
authorization module either (directly or through a chain). There is no exception today; adding one needs a
numbered decision and an entry in `ALLOWED`.
"""

from __future__ import annotations

import ast
from pathlib import Path

SRC = Path(__file__).resolve().parents[2] / "src"
AUTHORIZATION = (
    "gate", "constraints", "mandates", "lock", "trusted_surface", "openmandates", "checkout",
    "paypal", "canonical", "evidence", "merchant", "cp", "mpp", "ledger",
)  # fmt: skip
ALLOWED: set[tuple[str, str]] = set()  # (importing module prefix, imported module prefix)


def module_name(path: Path, root: Path = SRC) -> str:
    parts = list(path.relative_to(root).with_suffix("").parts)
    if parts[-1] == "__init__":
        parts.pop()
    return ".".join(parts)


def build_graph(root: Path = SRC) -> dict[str, set[str]]:
    modules = {module_name(p, root): p for p in (root / "countersign").rglob("*.py")}
    graph: dict[str, set[str]] = {}
    for name, path in modules.items():
        edges: set[str] = set()
        for node in ast.walk(ast.parse(path.read_text(encoding="utf-8"))):
            targets: list[str] = []
            if isinstance(node, ast.ImportFrom) and node.module and node.level == 0:
                targets.append(node.module)
                targets.extend(f"{node.module}.{alias.name}" for alias in node.names)
            elif isinstance(node, ast.Import):
                targets.extend(alias.name for alias in node.names)
            edges.update(t for t in targets if t in modules)
        graph[name] = edges
    return graph


def reachable(graph: dict[str, set[str]], start: str) -> set[str]:
    seen: set[str] = set()
    stack = [start]
    while stack:
        for nxt in graph.get(stack.pop(), ()):
            if nxt not in seen:
                seen.add(nxt)
                stack.append(nxt)
    return seen


def in_package(module: str, package: str) -> bool:
    return module == f"countersign.{package}" or module.startswith(f"countersign.{package}.")


def violations(graph: dict[str, set[str]]) -> list[str]:
    found: list[str] = []
    for module in sorted(graph):
        reach = reachable(graph, module)
        if any(in_package(module, p) for p in AUTHORIZATION):
            hit = sorted(m for m in reach if in_package(m, "llm"))
            if hit and not any(module.startswith(a) and hit[0].startswith(b) for a, b in ALLOWED):
                found.append(f"{module} reaches {hit[0]}")
        if in_package(module, "llm"):
            hit = sorted(m for m in reach if any(in_package(m, p) for p in AUTHORIZATION))
            if hit and not any(module.startswith(a) and hit[0].startswith(b) for a, b in ALLOWED):
                found.append(f"{module} reaches {hit[0]}")
    return found


def test_no_authorization_module_reaches_the_model_gateway_and_the_gateway_reaches_none() -> None:
    graph = build_graph()
    assert any(in_package(m, "llm") for m in graph), "the gateway package was not found"
    assert any(in_package(m, "gate") for m in graph), "the authorization packages were not found"
    assert violations(graph) == []


def test_the_guard_sees_a_direct_and_a_transitive_import(tmp_path: Path) -> None:
    """A synthetic tree: the check fails for a direct import, a chain, and the gateway importing a gate."""
    pkg = tmp_path / "countersign"
    for sub in ("gate", "llm", "helpers"):
        (pkg / sub).mkdir(parents=True)
        (pkg / sub / "__init__.py").write_text("")
    (pkg / "__init__.py").write_text("")
    (pkg / "llm" / "gateway.py").write_text("x = 1\n")
    (pkg / "helpers" / "mid.py").write_text("from countersign.llm import gateway\n")
    (pkg / "gate" / "direct.py").write_text("import countersign.llm.gateway\n")
    (pkg / "gate" / "chain.py").write_text("from countersign.helpers import mid\n")
    (pkg / "llm" / "bad.py").write_text("from countersign.gate import direct\n")
    found = violations(build_graph(tmp_path))
    assert "countersign.gate.direct reaches countersign.llm.gateway" in found
    assert any(f.startswith("countersign.gate.chain reaches") for f in found)
    assert any(f.startswith("countersign.llm.bad reaches countersign.gate") for f in found)


# ----------------------------------------------------------------------------------- the assistant
# Ask Countersign (Decisions 125 to 129) plans with the model and answers with fixed templates. It may use
# the gateway, but it must not reach any authorization module, the database layer, the dashboard or API
# code, or anything that talks to PayPal, and no authorization module may reach it.
ASSISTANT_FORBIDDEN = (
    *AUTHORIZATION, "dashboard", "api", "protocols", "degraded", "completion", "composition",
    "webhooks", "runtime", "tables", "main",
)  # fmt: skip


def assistant_violations(graph: dict[str, set[str]]) -> list[str]:
    found: list[str] = []
    for module in sorted(graph):
        reach = reachable(graph, module)
        if in_package(module, "assistant"):
            hit = sorted(m for m in reach if any(in_package(m, p) for p in ASSISTANT_FORBIDDEN))
            if hit:
                found.append(f"{module} reaches {hit[0]}")
        elif any(in_package(module, p) for p in AUTHORIZATION):
            hit = sorted(m for m in reach if in_package(m, "assistant"))
            if hit:
                found.append(f"{module} reaches {hit[0]}")
    return found


def test_the_assistant_reaches_no_authorization_module_and_none_reaches_it() -> None:
    graph = build_graph()
    assert any(in_package(m, "assistant") for m in graph), "the assistant package was not found"
    assert assistant_violations(graph) == []
    # It does use the gateway: the planner is the only model call.
    assert any(in_package(m, "llm") for m in reachable(graph, "countersign.assistant.planner"))


def test_the_assistant_guard_sees_direct_and_transitive_imports(tmp_path: Path) -> None:
    pkg = tmp_path / "countersign"
    for sub in ("assistant", "gate", "helpers"):
        (pkg / sub).mkdir(parents=True)
        (pkg / sub / "__init__.py").write_text("")
    (pkg / "__init__.py").write_text("")
    (pkg / "gate" / "g.py").write_text("x = 1\n")
    (pkg / "helpers" / "mid.py").write_text("from countersign.gate import g\n")
    (pkg / "assistant" / "direct.py").write_text("from countersign.gate import g\n")
    (pkg / "assistant" / "chain.py").write_text("from countersign.helpers import mid\n")
    (pkg / "gate" / "back.py").write_text("from countersign.assistant import direct\n")
    found = assistant_violations(build_graph(tmp_path))
    assert any(f.startswith("countersign.assistant.direct reaches countersign.gate") for f in found)
    assert any(f.startswith("countersign.assistant.chain reaches countersign.gate") for f in found)
    assert any(f.startswith("countersign.gate.back reaches countersign.assistant") for f in found)
