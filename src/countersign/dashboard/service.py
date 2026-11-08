"""What the dashboard routes need: the engine, the labels of this deployment and the stream timing.

Nothing here writes. `status` reports configuration as booleans and labels, never a value: whether a
PayPal sandbox app is configured (not its id), the protection mode, where the UCP profile is.
"""

from __future__ import annotations

import time
from collections.abc import Callable
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from sqlalchemy import Engine

from countersign.dashboard import policy as policy_snapshot
from countersign.dashboard import read
from countersign.runtime import Mode, RuntimeSettings

ROOT = Path(__file__).resolve().parents[3]
EVAL_LATEST = ROOT / "eval" / "reports" / "latest.json"
ATTACK_RUN_ENVS = ("dev", "eval", "demo")


@dataclass
class DashboardService:
    engine: Engine
    runtime: RuntimeSettings
    public_base_url: str
    paypal_configured: bool
    data_source: str
    eval_path: Path = EVAL_LATEST
    lock_policy: Callable[[], dict[str, Any]] | None = None
    assistant: Any = None  # the Ask Countersign service, set by the composition root (Decision 125)
    attack_launcher: Any = (
        None  # `eval.launch.AttackLauncher`, installed only where it may run (Decision 131)
    )
    poll_seconds: float = 1.0
    stream_seconds: float = 300.0  # the browser reconnects; a bounded stream frees its worker
    clock: Callable[[], float] = field(default=time.time)

    def attack_runs_enabled(self) -> bool:
        """The run launcher exists and this deployment is dev, eval or demo (never anything else)."""
        return self.attack_launcher is not None and self.runtime.app_env in ATTACK_RUN_ENVS

    def status(self) -> dict[str, Any]:
        mode = self.runtime.mode.value
        return {
            "version": read.API_VERSION,
            "app_env": self.runtime.app_env,
            "mode": mode,
            "protection": "baseline" if self.runtime.mode is Mode.BASELINE else "full",
            "ablations": list(self.runtime.active_ablations),
            "paypal_sandbox_configured": self.paypal_configured,
            "data_source": self.data_source,
            "ucp_profile_url": self.public_base_url.rstrip("/") + "/.well-known/ucp",
            "read_only": self.runtime.app_env != "dev",
            "login": False,
        }

    def orders(self, ids: list[str] | None) -> dict[str, Any]:
        rows = read.orders(self.engine, ids)
        return {"version": read.API_VERSION, "orders": rows}

    def detail(self, checkout_id: str) -> dict[str, Any] | None:
        found = read.order_detail(self.engine, checkout_id)
        if found is None:
            return None
        return {"version": read.API_VERSION, "checkout_id": checkout_id, **found}

    def summary(self) -> dict[str, Any]:
        return {
            "version": read.API_VERSION,
            "unauthorized_captures": read.unauthorized_captures(self.engine),
        }

    def mandates(self) -> dict[str, Any]:
        return {
            "version": read.API_VERSION,
            "mandates": read.mandates(self.engine, int(self.clock())),
        }

    def events(self) -> dict[str, Any]:
        return {"version": read.API_VERSION, "events": read.protection_events(self.engine)}

    def eval(self) -> dict[str, Any]:
        return {
            "version": read.API_VERSION,
            "eval": read.eval_summary(self.eval_path),
            "results": read.eval_results(self.eval_path),
        }

    def policy(self) -> dict[str, Any]:
        """The read-only policy snapshot and its SHA-256 (Decision 124)."""
        body = policy_snapshot.snapshot(
            self.runtime, self.lock_policy() if self.lock_policy else None
        )
        return {
            "version": read.API_VERSION,
            "snapshot": body,
            "sha256": policy_snapshot.snapshot_hash(body),
            "hash_of": "SHA-256 of the RFC 8785 canonical JSON of snapshot",
        }
