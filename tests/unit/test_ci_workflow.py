"""The CI workflow installs the Node packages the Python tests need, before pytest runs."""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

import yaml

ROOT = Path(__file__).resolve().parents[2]


def _python_steps() -> list[dict[str, Any]]:
    workflow = yaml.safe_load((ROOT / ".github/workflows/ci.yml").read_text())
    steps = workflow["jobs"]["python"]["steps"]
    assert isinstance(steps, list)
    return steps


def _index(steps: list[dict[str, Any]], needle: str) -> int:
    for i, step in enumerate(steps):
        if needle in str(step.get("run", "")) or needle in str(step.get("uses", "")):
            return i
    raise AssertionError(f"no step mentions {needle!r}")


def test_the_python_job_installs_node_dependencies_before_pytest() -> None:
    steps = _python_steps()
    pnpm = _index(steps, "pnpm/action-setup")
    node = _index(steps, "actions/setup-node")
    install = _index(steps, "pnpm install")
    pytest_step = _index(steps, "uv run pytest")
    assert pnpm < install and node < install < pytest_step
    assert steps[install]["run"].strip() == "pnpm install --frozen-lockfile"
    assert str(steps[node]["with"]["node-version"]) == "22"


def test_the_lockfile_pins_the_packages_the_script_imports() -> None:
    manifest = json.loads((ROOT / "package.json").read_text())
    lock = (ROOT / "pnpm-lock.yaml").read_text()
    for package in ("jose", "canonicalize"):
        version = manifest["devDependencies"][package]
        assert version[0].isdigit(), "pinned exactly, not a range"
        assert f"  {package}@{version}:" in lock
        assert f"specifier: {version}" in lock
    script = (ROOT / "scripts/interop_verify.mjs").read_text()
    assert 'from "jose"' in script and 'from "canonicalize"' in script


def test_make_setup_installs_the_node_packages_from_the_lockfile() -> None:
    makefile = (ROOT / "Makefile").read_text()
    assert "setup: node-deps" in makefile
    assert "node-deps:\n\tpnpm install --frozen-lockfile" in makefile
