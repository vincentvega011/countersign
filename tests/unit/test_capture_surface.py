"""The library has no ungated capture (INV-4): who may mint a capture approval or capture.

Structural check over the source tree. Library code under `src/` may build a `CaptureApproval` only
from `countersign/gate/`, and may call `capture_authorization` only from `countersign/gate/` or
`countersign/mpp/`. The recording and test helpers outside `src/` that mint or capture are listed by
name, so a new one has to be added here on purpose.
"""

from __future__ import annotations

import ast
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
SRC = ROOT / "src" / "countersign"
MINT = "mint_capture_approval"
CAPTURE = "capture_authorization"

LIBRARY_MINTERS = ("gate/",)
LIBRARY_CAPTURERS = ("gate/", "mpp/")
# Outside the package: the recording harness and tests that stand in for the gate.
OUTSIDE_MINTERS = {
    "tests/ungated_capture_cycle.py",
    "tests/unit/test_capture_approval.py",
    "tests/unit/test_paypal_client.py",
}
OUTSIDE_CAPTURERS = {
    "tests/ungated_capture_cycle.py",
    "tests/unit/test_paypal_client.py",
    "tests/unit/test_paypal_strict_json.py",
}


def _py_files(base: Path) -> list[Path]:
    skip = {".venv", "node_modules", ".git", "__pycache__"}
    return [p for p in base.rglob("*.py") if not skip & set(p.relative_to(ROOT).parts)]


def _uses(path: Path, name: str) -> tuple[bool, bool]:
    """(imports or references `name`, calls an attribute or function called `name`)."""
    tree = ast.parse(path.read_text(encoding="utf-8"))
    referenced = called = False
    for node in ast.walk(tree):
        if (
            isinstance(node, ast.ImportFrom)
            and any(a.name == name for a in node.names)
            or isinstance(node, ast.Attribute)
            and node.attr == name
            or isinstance(node, ast.Name)
            and node.id == name
        ):
            referenced = True
        if isinstance(node, ast.Call):
            func = node.func
            if (isinstance(func, ast.Attribute) and func.attr == name) or (
                isinstance(func, ast.Name) and func.id == name
            ):
                called = True
    return referenced, called


def _rel(path: Path, base: Path) -> str:
    return path.relative_to(base).as_posix()


def test_the_ungated_cycle_is_not_in_the_package() -> None:
    assert not (SRC / "paypal" / "cycle.py").exists()
    assert (ROOT / "tests" / "ungated_capture_cycle.py").exists()


def test_only_the_gate_mints_a_capture_approval_in_the_library() -> None:
    offenders = []
    for path in _py_files(SRC):
        rel = _rel(path, SRC)
        referenced, _ = _uses(path, MINT)
        if referenced and rel != "paypal/approval.py" and not rel.startswith(LIBRARY_MINTERS):
            offenders.append(rel)
    assert not offenders, f"these library files must not mint a capture approval: {offenders}"


def test_only_the_gate_and_mpp_capture_in_the_library() -> None:
    offenders = []
    for path in _py_files(SRC):
        rel = _rel(path, SRC)
        _, called = _uses(path, CAPTURE)
        if called and not rel.startswith(LIBRARY_CAPTURERS):
            offenders.append(rel)
    assert not offenders, f"these library files must not capture: {offenders}"


def test_the_library_never_imports_tests_or_scripts() -> None:
    offenders = []
    for path in _py_files(SRC):
        tree = ast.parse(path.read_text(encoding="utf-8"))
        for node in ast.walk(tree):
            names = []
            if isinstance(node, ast.Import):
                names = [a.name for a in node.names]
            elif isinstance(node, ast.ImportFrom) and node.module:
                names = [node.module]
            if any(n.split(".")[0] in {"tests", "scripts"} for n in names):
                offenders.append(_rel(path, SRC))
    assert not offenders


def test_outside_the_package_only_the_listed_helpers_mint_or_capture() -> None:
    mint_users, capture_users = set(), set()
    for path in _py_files(ROOT):
        if SRC in path.parents:
            continue
        rel = _rel(path, ROOT)
        if rel == "tests/unit/test_capture_surface.py":
            continue
        referenced, _ = _uses(path, MINT)
        _, called = _uses(path, CAPTURE)
        if referenced:
            mint_users.add(rel)
        if called:
            capture_users.add(rel)
    assert mint_users <= OUTSIDE_MINTERS, mint_users - OUTSIDE_MINTERS
    assert capture_users <= OUTSIDE_CAPTURERS, capture_users - OUTSIDE_CAPTURERS


def test_the_check_would_catch_a_violation(tmp_path: Path) -> None:
    sample = tmp_path / "bad.py"
    sample.write_text(
        "from countersign.paypal.approval import mint_capture_approval\n"
        "def f(client, a):\n    return client.capture_authorization(a)\n"
    )
    assert _uses(sample, MINT) == (True, False)
    assert _uses(sample, CAPTURE) == (True, True)
