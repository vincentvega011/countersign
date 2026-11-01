"""Run the Node tests of the shared UI helpers (amount formatting, fingerprints, status map)."""

from __future__ import annotations

import shutil
import subprocess
from pathlib import Path

UI = Path(__file__).resolve().parents[2] / "web" / "ui"


def test_the_ui_helper_tests_pass() -> None:
    node = shutil.which("node")
    assert node is not None, "Node 22 is required (the interop verifier needs it too)"
    done = subprocess.run(
        [node, "--test", "test/format.test.mjs"],
        check=False,
        cwd=UI,
        capture_output=True,
        text=True,
    )
    assert done.returncode == 0, done.stdout + done.stderr
