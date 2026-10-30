"""The library has no ungated capture (INV-4): who may mint a capture approval or capture.

Structural check over the source tree, in two parts. A static part reads the syntax trees and flags any
reference at all (a call, an alias such as `f = client.capture_authorization`, an import under another
name, a `getattr` string, a star import) rather than only direct calls. A runtime part imports every
library module and inspects its attributes, so a re-export or a class attribute that holds the capture
or the mint is found even when the source hides it. Library code under `src/` may build a `CaptureApproval` only
from `countersign/gate/`, and may call `capture_authorization` only from `countersign/gate/` or
`countersign/mpp/`. The recording and test helpers outside `src/` that mint or capture are listed by
name, so a new one has to be added here on purpose.
"""

from __future__ import annotations

import ast
import importlib
import inspect
import pkgutil
import types
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
SRC = ROOT / "src" / "countersign"
MINT = "mint_capture_approval"
CAPTURE = "capture_authorization"

LIBRARY_MINTERS = ("gate/",)
LIBRARY_CAPTURERS = ("gate/", "mpp/")
# Outside the package: the recording harness and tests that stand in for the gate.
OUTSIDE_MINTERS = {
    "tests/unit/test_webhooks_import_guard.py",  # lists the names the webhook code must never use
    "tests/ungated_capture_cycle.py",
    "tests/unit/test_capture_approval.py",
    "tests/unit/test_paypal_client.py",
}
OUTSIDE_CAPTURERS = {
    "tests/unit/test_webhooks_import_guard.py",  # lists the method names the webhook code must never use
    "tests/integration/test_gate_flow.py",  # checks that the client refuses a capture without a gate approval
    "tests/ungated_capture_cycle.py",
    "tests/unit/test_paypal_client.py",
    "tests/unit/test_paypal_strict_json.py",
}


def _py_files(base: Path) -> list[Path]:
    skip = {".venv", "node_modules", ".git", "__pycache__"}
    return [p for p in base.rglob("*.py") if not skip & set(p.relative_to(ROOT).parts)]


def _uses(path: Path, name: str) -> tuple[bool, bool]:
    """(references `name` in any way, calls something called `name`).

    A reference is an import of the name (also under `as` another name), an attribute access, a bare
    name, a string constant equal to the name (for `getattr`), or a star import from a module under
    `countersign.paypal`, which defines it.
    """
    tree = ast.parse(path.read_text(encoding="utf-8"))
    referenced = called = False
    for node in ast.walk(tree):
        if isinstance(node, ast.ImportFrom):
            star = any(a.name == "*" for a in node.names) and (node.module or "").startswith(
                "countersign.paypal"
            )
            if star or any(a.name == name for a in node.names):
                referenced = True
        elif isinstance(node, ast.Attribute):
            referenced = referenced or node.attr == name
        elif isinstance(node, ast.Name):
            referenced = referenced or node.id == name
        elif isinstance(node, ast.Constant):
            referenced = referenced or node.value == name
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
        referenced, _ = _uses(path, CAPTURE)
        if referenced and not rel.startswith(LIBRARY_CAPTURERS):
            offenders.append(rel)
    assert not offenders, f"these library files must not reference the capture: {offenders}"


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
        used, _ = _uses(path, CAPTURE)
        if referenced:
            mint_users.add(rel)
        if used:
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


SEAL = "_SEAL"


def test_nothing_but_the_approval_module_touches_the_seal_or_builds_an_approval() -> None:
    offenders = []
    for path in _py_files(ROOT):
        rel = _rel(path, ROOT)
        if rel in {"src/countersign/paypal/approval.py", "tests/unit/test_capture_surface.py"}:
            continue
        if rel == "tests/unit/test_capture_approval.py":
            continue  # it tests the sealed constructor itself
        sealed, _ = _uses(path, SEAL)
        _, built = _uses(path, "CaptureApproval")
        if sealed or built:
            offenders.append(rel)
    assert not offenders, (
        f"only paypal/approval.py may use the seal or build an approval: {offenders}"
    )


def test_the_check_catches_aliases_strings_and_star_imports(tmp_path: Path) -> None:
    cases = {
        "alias": "def f(client):\n    g = client.capture_authorization\n    return g\n",
        "rename": "from x import capture_authorization as c\n",
        "string": "def f(c):\n    return getattr(c, 'capture_authorization')\n",
        "star": "from countersign.paypal.client import *\n",
        "star_approval": "from countersign.paypal.approval import *\n",
    }
    for name, source in cases.items():
        sample = tmp_path / f"{name}.py"
        sample.write_text(source)
        assert _uses(sample, CAPTURE)[0], name
    rename = tmp_path / "rename_mint.py"
    rename.write_text("from countersign.paypal.approval import mint_capture_approval as m\n")
    assert _uses(rename, MINT)[0]
    builder = tmp_path / "builder.py"
    builder.write_text("def f(a):\n    return CaptureApproval(object(), **a)\n")
    assert _uses(builder, "CaptureApproval")[1]


# ---------------------------------------------------------------- runtime: module attributes


def _library_modules() -> list[types.ModuleType]:
    import countersign

    modules = []
    for info in pkgutil.walk_packages(countersign.__path__, "countersign."):
        modules.append(importlib.import_module(info.name))
    return modules


def _allowed_module(name: str) -> bool:
    allowed = ("countersign.gate", "countersign.mpp")
    return name == "countersign.paypal.approval" or name.startswith(allowed)


def test_no_library_module_holds_the_mint_the_seal_or_the_capture_function() -> None:
    from countersign.paypal import approval as approval_module
    from countersign.paypal.client import PayPalClient

    capture = PayPalClient.capture_authorization
    holders = []
    for module in _library_modules():
        if _allowed_module(module.__name__) or module.__name__ == "countersign.paypal.client":
            continue
        for attr, value in vars(module).items():
            if (
                value is approval_module.mint_capture_approval
                or value is approval_module._SEAL
                or value is capture
                or (attr == "mint_capture_approval" or attr == "capture_authorization")
            ):
                holders.append(f"{module.__name__}.{attr}")
    assert not holders, f"re-exports found: {holders}"


def test_the_package_init_files_do_not_re_export_the_approval_or_capture() -> None:
    import countersign.paypal as paypal_package

    for name in ("mint_capture_approval", "capture_authorization", "_SEAL"):
        assert not hasattr(paypal_package, name), name


def test_no_class_outside_the_client_carries_a_capture_method_or_the_mint() -> None:
    from countersign.paypal.approval import mint_capture_approval
    from countersign.paypal.client import PayPalClient

    capture = PayPalClient.capture_authorization
    carriers = []
    for module in _library_modules():
        if _allowed_module(module.__name__):
            continue
        for attr, value in vars(module).items():
            if not inspect.isclass(value) or value.__module__ != module.__name__:
                continue
            if value is PayPalClient:
                continue  # the one definition
            for member, held in vars(value).items():
                if held is capture or held is mint_capture_approval or member == CAPTURE:
                    carriers.append(f"{module.__name__}.{attr}.{member}")
    assert not carriers, carriers
    assert [
        c for c in PayPalClient.__subclasses__() if _lib(c) and not _allowed_module(c.__module__)
    ] == []


def _lib(cls: type) -> bool:
    return cls.__module__.startswith("countersign.")


def test_the_capture_and_the_mint_are_defined_in_exactly_one_place() -> None:
    from countersign.paypal.approval import mint_capture_approval
    from countersign.paypal.client import PayPalClient

    assert mint_capture_approval.__module__ == "countersign.paypal.approval"
    assert PayPalClient.capture_authorization.__module__ == "countersign.paypal.client"
    assert PayPalClient.capture_authorization.__qualname__ == "PayPalClient.capture_authorization"
