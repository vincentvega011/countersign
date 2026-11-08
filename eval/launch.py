"""Launch one scripted attack against a fresh baseline and a fresh full instance, side by side.

Used by the dashboard's "Run attack" button (Decision 131). Each run builds two whole apps over the PayPal
simulator on a scratch database (the evaluation harness), lets the scripted adversary attack both
through their HTTP interface and judges each from PayPal state and the decision log. Run records go to
`eval/reports/attack-runs/<run id>/` (a record file and the attempt logs); nothing else is written, and
no merchant data is read or changed.
"""

from __future__ import annotations

import json
import secrets
import threading
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

from agents.adversary.scripts import SCRIPTS
from eval.adversary.runner import run_goal
from eval.harness import scratch_databases
from eval.run import load_cases

RUNS = Path(__file__).resolve().parent / "reports" / "attack-runs"
MODES = ("baseline", "full")


class Unavailable(RuntimeError):
    """The scratch database could not be created (no administrator connection)."""


class Busy(RuntimeError):
    """A run is already in progress."""


class AttackLauncher:
    def __init__(self, runs_dir: Path = RUNS) -> None:
        self.runs_dir = runs_dir
        self._lock = threading.Lock()
        registry = {c.id: c for c in load_cases()}
        self._cases = {name: registry[name] for name in sorted(SCRIPTS)}

    def launchable(self) -> list[dict[str, str]]:
        return [
            {"id": c.id, "category": c.category, "description": c.description}
            for c in self._cases.values()
        ]

    def run(self, attack_id: str) -> dict[str, Any]:
        if attack_id not in self._cases:
            raise KeyError(attack_id)
        if not self._lock.acquire(blocking=False):
            raise Busy
        try:
            return self._run(attack_id)
        finally:
            self._lock.release()

    def _run(self, attack_id: str) -> dict[str, Any]:
        case = self._cases[attack_id]
        run_id = datetime.now(UTC).strftime("%Y%m%dT%H%M%SZ") + "-" + secrets.token_hex(3)
        folder = self.runs_dir / run_id
        results: dict[str, Any] = {}
        try:
            with scratch_databases() as dbs:
                for mode in MODES:
                    done = run_goal(attack_id, mode, dbs, folder / f"attempts-{mode}.jsonl")
                    v = done.run.verdict
                    expected = case.expected[mode].outcome
                    results[mode] = {
                        "captured_outside_signed": v.outcome == "success",
                        "unauthorized_captures": v.unauthorized_captures,
                        "duplicate_paypal_objects": v.duplicate_objects,
                        "captured_minor": v.captured_minor,
                        "reason_code": done.run.reason,
                        "attempts": done.attempts,
                        "violations": v.violations,
                        "matches_expectation": v.outcome == expected,
                        "error": done.run.error,
                    }
        except Exception as exc:  # a missing admin database is the one expected failure
            if not results:
                raise Unavailable(type(exc).__name__) from None
            raise
        record = {
            "version": 1, "run_id": run_id, "attack": case.id, "category": case.category,
            "description": case.description,
            "started_at": datetime.now(UTC).strftime("%Y-%m-%dT%H:%M:%SZ"),
            "ground_truth": "PayPal simulator state and the hash-chained decision log",
            "results": results,
        }  # fmt: skip
        folder.mkdir(parents=True, exist_ok=True)
        (folder / "record.json").write_text(json.dumps(record, indent=1, sort_keys=True) + "\n")
        return record

    def recent(self, limit: int = 5) -> list[dict[str, Any]]:
        found: list[dict[str, Any]] = []
        for path in sorted(self.runs_dir.glob("*/record.json"), reverse=True)[:limit]:
            try:
                found.append(json.loads(path.read_text()))
            except (OSError, ValueError):
                continue
        return found
