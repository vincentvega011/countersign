"""Verify every stored evidence bundle with both verifiers, the service keys pinned.

The Python CLI (`countersign_verify`) and the browser verifier (`web/ui/evidence`, run in Node) are
independent implementations of the same twelve steps. A bundle counts as verified only when both pass
every step. The pinned keys come from the world that produced the bundle, never from the bundle.
"""

from __future__ import annotations

import json
import shutil
import subprocess
import sys
import tempfile
from pathlib import Path
from typing import Any

from eval.harness import BundleJob

ROOT = Path(__file__).resolve().parents[1]
STEPS = 12


def _python(path: Path, merchant: Path, platform: Path) -> bool:
    done = subprocess.run(
        [sys.executable, "-m", "countersign_verify", str(path), "--merchant-key", str(merchant),
         "--platform-key", str(platform)],
        capture_output=True, text=True, cwd=ROOT, check=False, timeout=120,
    )  # fmt: skip
    return done.returncode == 0 and done.stdout.count("PASS") == STEPS


def verify_jobs(jobs: list[BundleJob]) -> list[dict[str, Any]]:
    """One result per bundle: whether the Python and the browser verifier each passed all steps."""
    if not jobs:
        return []
    node = shutil.which("node")
    if node is None:
        raise RuntimeError("node is required to run the browser verifier")
    results: list[dict[str, Any]] = []
    with tempfile.TemporaryDirectory(prefix="cs-eval-verify-") as tmp:
        root = Path(tmp)
        node_jobs = []
        for n, job in enumerate(jobs):
            bundle, merchant, platform = (root / f"{n}.{k}.json" for k in ("bundle", "m", "p"))
            bundle.write_text(job.text)
            merchant.write_text(json.dumps(job.merchant_jwk))
            platform.write_text(json.dumps(job.platform_jwk))
            node_jobs.append(
                {
                    "path": str(bundle),
                    "pinned": {"merchant": str(merchant), "platform": str(platform)},
                }
            )
            results.append(
                {
                    "capture": job.capture_id,
                    "python": _python(bundle, merchant, platform),
                    "browser": False,
                }
            )
        listing = root / "jobs.json"
        listing.write_text(json.dumps(node_jobs))
        done = subprocess.run(
            [node, "test/verify-runner.mjs", str(listing)], cwd=ROOT / "web" / "ui",
            capture_output=True, text=True, check=False, timeout=600,
        )  # fmt: skip
        if done.returncode == 0:
            for result, steps in zip(results, json.loads(done.stdout), strict=True):
                result["browser"] = len(steps) == STEPS and all(s["ok"] for s in steps)
    return results
