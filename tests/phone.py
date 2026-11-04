"""The customer's phone for end-to-end tests and recorders: a headless browser, not a Python stand-in.

`web/approve/test/phone_consent.mjs` enrols a WebCrypto device key in a fresh browser context, opens the
agent's approval link and taps Approve, so the consent record the service verifies was signed by the
page itself. Chromium must be installed (`pnpm --filter @countersign/approve exec playwright install
chromium`); a missing browser fails the run, it is not skipped.
"""

from __future__ import annotations

import shutil
import subprocess
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]


def phone_consent(approve_url: str, timeout_s: float = 90.0) -> None:
    node = shutil.which("node")
    assert node, "node is required for the browser step"
    done = subprocess.run(
        [node, "test/phone_consent.mjs", approve_url],
        cwd=ROOT / "web" / "approve",
        capture_output=True,
        text=True,
        timeout=timeout_s,
        check=False,
    )
    if done.returncode != 0:
        raise RuntimeError(f"the phone step failed:\n{done.stdout}\n{done.stderr}")
