"""Protocol adapters sit at the edge (INV-5): the policy, verification and money modules must not import
one, and the ACP adapter may import only the canonical model, the shared checkout storage, the catalog,
the log and the shared lock entry point. AST based, like the other guards."""

from __future__ import annotations

import ast
from pathlib import Path

SRC = Path(__file__).resolve().parents[2] / "src" / "countersign"
ACP = SRC / "protocols" / "acp"
INNER = (
    "lock", "constraints", "gate", "cp", "merchant", "mpp", "mandates", "canonical", "ledger",
    "checkout", "evidence", "paypal",
)  # fmt: skip
ALLOWED_INTERNAL = (
    "countersign.canonical",
    "countersign.catalog",
    "countersign.checkout",
    "countersign.ledger",
    "countersign.lock",
    "countersign.protocols.acp",
)
FORBIDDEN_FRAMEWORKS = ("fastapi", "starlette", "flask", "django", "aiohttp", "uvicorn")


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


def test_no_inner_module_imports_a_protocol_adapter() -> None:
    for package in INNER:
        for path in sorted((SRC / package).rglob("*.py")):
            for name, line in imports(path):
                assert not name.startswith("countersign.protocols"), (
                    f"{path.relative_to(SRC)}:{line} imports {name}"
                )


def test_the_acp_adapter_imports_only_what_it_may() -> None:
    files = sorted(ACP.glob("*.py"))
    assert {p.name for p in files} >= {"service.py", "requests.py", "responses.py", "errors.py"}
    for path in files:
        for name, line in imports(path):
            if name.startswith("countersign."):
                assert name.startswith(ALLOWED_INTERNAL), f"{path.name}:{line} imports {name}"
            assert not name.startswith(FORBIDDEN_FRAMEWORKS), f"{path.name}:{line} imports {name}"


def test_the_acp_adapter_holds_no_lock_logic_of_its_own() -> None:
    text = "\n".join(p.read_text() for p in ACP.glob("*.py"))
    for needle in ("lock_state", "requires_ap2", "MerchantPolicy", "lock_events", "is_locked",
                   "record_lock", "customer_id_of"):  # fmt: skip
        assert needle not in text, needle


def test_acp_and_ucp_agree_on_the_capability_that_means_ap2() -> None:
    from countersign.lock import AP2_CAPABILITY
    from countersign.protocols.ucp.profile import AP2_CAPABILITY as UCP

    assert AP2_CAPABILITY == UCP


def test_acp_money_is_never_a_float() -> None:
    for path in ACP.glob("*.py"):
        text = path.read_text()
        assert "float(" not in text and "Decimal(" not in text, path.name
