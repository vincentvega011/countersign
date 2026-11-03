"""Typed errors of the model gateway. Every failure of a model call is one of these, never a bare exception."""

from __future__ import annotations


class LlmError(Exception):
    """Base class. `code` is stable and safe to log; the message never holds a prompt or a key."""

    code = "llm_error"


class LlmConfigError(LlmError):
    code = "llm_config_invalid"


class LlmTimeoutError(LlmError):
    code = "llm_timeout"


class LlmRateLimitedError(LlmError):
    code = "llm_rate_limited"


class LlmBudgetExceededError(LlmError):
    code = "llm_budget_exceeded"


class LlmProviderError(LlmError):
    code = "llm_provider_error"


class LlmOutputTooLargeError(LlmError):
    code = "llm_output_too_large"


class LlmSchemaError(LlmError):
    """The output did not validate after the one allowed retry. `errors` are path and rule only."""

    code = "llm_schema_invalid"

    def __init__(self, errors: list[str]) -> None:
        super().__init__("; ".join(errors[:5]) or "invalid output")
        self.errors = errors


class LlmReplayMissingError(LlmError):
    """Replay mode found no cassette for the request: fail closed and say how to record one."""

    code = "llm_replay_missing"

    def __init__(self, key: str, task: str) -> None:
        super().__init__(
            f"no recorded model call for task {task!r} (key {key[:16]}). Record it with "
            "LLM_MODE=record and the provider configured: uv run python scripts/record_llm_cassette.py "
            "(smoke requests) or run the code path in record mode."
        )
        self.key = key
        self.task = task
