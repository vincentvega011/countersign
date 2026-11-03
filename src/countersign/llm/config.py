"""Gateway configuration, read from the environment only. The key never appears in a `repr` or a log."""

from __future__ import annotations

import os
from collections.abc import Mapping
from dataclasses import dataclass, field
from pathlib import Path

from countersign.llm.cassette import DEFAULT_DIR
from countersign.llm.errors import LlmConfigError

MODES = ("live", "record", "replay")


@dataclass(frozen=True)
class LlmConfig:
    mode: str = "replay"
    model: str = "unset"
    base_url: str = ""
    api_key: str = field(default="", repr=False)
    provider: str = ""
    demo: bool = False
    max_calls: int = 50
    per_minute: int = 10
    response_format: str = "json_object"
    seed: int | None = None
    cassette_dir: Path = DEFAULT_DIR

    @classmethod
    def from_env(cls, env: Mapping[str, str] | None = None) -> LlmConfig:
        """Replay is the default everywhere; live and record must be asked for with `LLM_MODE`."""
        source = os.environ if env is None else env
        mode = source.get("LLM_MODE") or "replay"
        if mode not in MODES:
            raise LlmConfigError("LLM_MODE is live, record or replay")
        try:
            max_calls = int(source.get("LLM_MAX_CALLS") or 50)
            per_minute = int(source.get("LLM_RATE_PER_MINUTE") or 10)
            seed_text = source.get("LLM_SEED") or ""
            seed = int(seed_text) if seed_text else None
        except ValueError:
            raise LlmConfigError("a numeric LLM setting is not a number") from None
        config = cls(
            mode=mode,
            model=source.get("LLM_MODEL") or "unset",
            base_url=source.get("LLM_BASE_URL") or "",
            api_key=source.get("LLM_API_KEY") or "",
            provider=source.get("LLM_PROVIDER") or "",
            demo=source.get("APP_ENV") == "demo",
            max_calls=max_calls,
            per_minute=per_minute,
            response_format=source.get("LLM_RESPONSE_FORMAT") or "json_object",
            seed=seed,
        )
        config.check()
        return config

    def check(self) -> None:
        if self.max_calls < 1 or self.per_minute < 1:
            raise LlmConfigError("the call budget and the rate limit are at least 1")
        if self.mode in ("live", "record"):
            missing = [
                name
                for name, value in (
                    ("LLM_BASE_URL", self.base_url),
                    ("LLM_MODEL", self.model if self.model != "unset" else ""),
                    ("LLM_API_KEY", self.api_key),
                )
                if not value
            ]
            if missing:
                raise LlmConfigError("live or record mode needs " + ", ".join(missing))
            if not self.base_url.startswith("https://") and not self.base_url.startswith(
                "http://127.0.0.1"
            ):
                raise LlmConfigError("LLM_BASE_URL must be https (or loopback for a local server)")
