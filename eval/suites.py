"""The non-attack suites: legitimate tasks, and the property and concurrency tests with a fixed seed."""

from __future__ import annotations

import re
import subprocess
import sys
from pathlib import Path
from typing import Any

from eval.harness import scratch_databases
from eval.tasks import build_tasks
from eval.tasks.runner import run_task

ROOT = Path(__file__).resolve().parents[1]
SEED = 0  # Hypothesis `--hypothesis-seed`: the same examples on every run

PYTEST_SUITES: dict[str, tuple[str, ...]] = {
    "properties": (
        "tests/properties",
        "tests/integration/test_lock_property.py",
        "tests/integration/test_gate_property.py",
        "tests/integration/test_cp_budget_property.py",
        "tests/integration/test_webhooks_property.py",
    ),
    "concurrency": (
        "tests/integration/test_gate_concurrency.py",
        "tests/integration/test_cp_concurrency.py",
        "tests/integration/test_ucp_checkout_concurrency.py",
        "tests/integration/test_complete_stress.py",
    ),
}


def task_rows(modes: list[str], only: list[str] | None = None) -> list[dict[str, Any]]:
    rows = []
    with scratch_databases() as dbs:
        for task in build_tasks():
            if only and task.id not in only:
                continue
            for mode in modes:
                done = run_task(task, mode, dbs)
                rows.append(
                    {
                        "task": task.id, "kind": task.kind, "mode": mode,
                        "completed": done.completed, "false_block": done.false_block,
                        "latency_ms": round(done.latency_ms, 1),
                        "captured_minor": done.captured_minor, "expected_minor": done.expected_minor,
                        "unauthorized_captures": done.verdict.unauthorized_captures,
                        "duplicate_paypal_objects": done.verdict.duplicate_objects,
                        "violations": done.verdict.violations, "error": done.error,
                    }
                )  # fmt: skip
    return rows


def _count(pattern: str, text: str) -> int:
    found = re.search(pattern, text)
    return int(found.group(1)) if found else 0


def run_pytest_suite(name: str) -> list[dict[str, Any]]:
    targets = PYTEST_SUITES[name]
    command = [
        sys.executable, "-m", "pytest", *targets, "-q", "-p", "no:cacheprovider",
        f"--hypothesis-seed={SEED}", "--no-header", "-o", "addopts=",
    ]  # fmt: skip
    done = subprocess.run(command, cwd=ROOT, capture_output=True, text=True, check=False)
    tail = "\n".join(done.stdout.strip().splitlines()[-3:])
    return [
        {
            "target": name, "files": list(targets), "seed": SEED, "exit_status": done.returncode,
            "passed": _count(r"(\d+) passed", tail), "failed": _count(r"(\d+) failed", tail),
            "errors": _count(r"(\d+) error", tail),
        }
    ]  # fmt: skip
