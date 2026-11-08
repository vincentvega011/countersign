"""The attempt log: one JSON line per request the adversary makes.

A line holds the attack id, the target mode, a timestamp, the step label, method and path, the shape
of the request body (member names and sizes, never values), the response status, what the adversary
observed (its own reading of the response, not a verdict) and the stable code. Header values, tokens
and bodies are never written, so there is no secret in the log. The verdict comes from the judge
(PayPal state and the decision log), not from this file.
"""

from __future__ import annotations

import json
import time
from collections.abc import Callable
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any


def body_shape(body: Any) -> dict[str, Any]:
    if body is None:
        return {"kind": "none"}
    if isinstance(body, bytes | str):
        return {"kind": "raw", "bytes": len(body)}
    if isinstance(body, dict):
        return {"kind": "object", "members": sorted(str(k) for k in body)[:20]}
    return {"kind": type(body).__name__}


@dataclass
class AttemptLog:
    attack_id: str
    target_mode: str
    path: Path | None = None
    clock: Callable[[], float] = time.time
    entries: list[dict[str, Any]] = field(default_factory=list)

    def record(self, **fields: Any) -> dict[str, Any]:
        entry = {
            "ts": round(self.clock(), 3), "attack": self.attack_id, "target_mode": self.target_mode,
            "n": len(self.entries) + 1, **fields,
        }  # fmt: skip
        self.entries.append(entry)
        if self.path is not None:
            self.path.parent.mkdir(parents=True, exist_ok=True)
            with self.path.open("a", encoding="utf-8") as handle:
                handle.write(json.dumps(entry, sort_keys=True) + "\n")
        return entry
