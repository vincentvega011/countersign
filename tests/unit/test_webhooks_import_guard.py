"""The webhook code reads PayPal and writes bookkeeping; it must have no way to move money (INV-4, INV-7).

AST based. It may import `paypal`, `ledger`, the gate's store (the existing add-only ledger code),
the tables and the decision log; not a protocol adapter, the API layer, a web framework or model code.
And it never mentions a money moving client method or the capture approval.
"""

from __future__ import annotations

import ast
from pathlib import Path

SRC = Path(__file__).resolve().parents[2] / "src" / "countersign"
WEBHOOKS = SRC / "webhooks"
ALLOWED = (
    "countersign.canonical",
    "countersign.gate.store",
    "countersign.ledger",
    "countersign.merchant.decision_log",
    "countersign.merchant.policy",
    "countersign.paypal",
    "countersign.tables",
    "countersign.webhooks",
)
FORBIDDEN = (
    "countersign.protocols", "countersign.api", "countersign.llm", "agents", "fastapi", "starlette",
    "flask", "django", "aiohttp", "uvicorn", "openai",
)  # fmt: skip
MONEY_MOVING = (
    "capture_authorization", "void_authorization", "authorize_order", "refund_capture",
    "create_order", "mint_capture_approval", "CaptureApproval",
)  # fmt: skip


def imports(path: Path) -> list[tuple[str, int]]:
    found: list[tuple[str, int]] = []
    for node in ast.walk(ast.parse(path.read_text())):
        if isinstance(node, ast.Import):
            found += [(a.name, node.lineno) for a in node.names]
        elif isinstance(node, ast.ImportFrom):
            base = node.module or ""
            found.append((base, node.lineno))
            found += [(f"{base}.{a.name}", node.lineno) for a in node.names]
    return found


def test_webhooks_import_only_what_they_may() -> None:
    files = sorted(WEBHOOKS.glob("*.py"))
    assert {p.name for p in files} >= {"service.py", "events.py", "reconcile.py"}
    for path in files:
        for name, line in imports(path):
            assert not name.startswith(FORBIDDEN), f"{path.name}:{line} imports {name}"
            if name.startswith("countersign."):
                assert name.startswith(ALLOWED), f"{path.name}:{line} imports {name}"


def test_webhooks_and_their_route_never_reach_a_money_moving_call() -> None:
    for path in [*WEBHOOKS.glob("*.py"), SRC / "api" / "webhook_routes.py"]:
        text = path.read_text()
        for needle in MONEY_MOVING:
            assert needle not in text, f"{path.name} mentions {needle}"


def test_nothing_inner_imports_the_webhooks() -> None:
    for package in ("gate", "cp", "merchant", "lock", "constraints", "canonical", "ledger"):
        for path in sorted((SRC / package).rglob("*.py")):
            for name, line in imports(path):
                assert not name.startswith("countersign.webhooks"), f"{path}:{line}"
