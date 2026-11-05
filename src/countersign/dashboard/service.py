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

from countersign.dashboard import read
from countersign.runtime import Mode, RuntimeSettings

ROOT = Path(__file__).resolve().parents[3]
EVAL_LATEST = ROOT / "eval" / "reports" / "latest.json"


@dataclass
class DashboardService:
    engine: Engine
    runtime: RuntimeSettings
    public_base_url: str
    paypal_configured: bool
    data_source: str
    eval_path: Path = EVAL_LATEST
    poll_seconds: float = 1.0
    stream_seconds: float = 300.0  # the browser reconnects; a bounded stream frees its worker
    clock: Callable[[], float] = field(default=time.time)

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
        return {"version": read.API_VERSION, "eval": read.eval_summary(self.eval_path)}
