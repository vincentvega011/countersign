"""The model call as data: a request, its canonical key, and the validated result."""

from __future__ import annotations

import hashlib
import json
from dataclasses import dataclass, field
from typing import Any

from countersign.llm.schema import check_schema

DEFAULT_TIMEOUT_S = 30.0
DEFAULT_MAX_OUTPUT_CHARS = 8000


@dataclass(frozen=True)
class LlmRequest:
    """One structured model call. `schema` describes the JSON object the output must be."""

    task: str
    system: str
    user: str
    schema: dict[str, Any]
    timeout_s: float = DEFAULT_TIMEOUT_S
    max_output_chars: int = DEFAULT_MAX_OUTPUT_CHARS
    temperature: float = 0.0
    seed: int | None = None

    def __post_init__(self) -> None:
        if not self.task or not self.task.replace("_", "").replace("-", "").isalnum():
            raise ValueError("task is a short identifier")
        if self.timeout_s <= 0 or self.max_output_chars <= 0:
            raise ValueError("timeout and output size are positive")
        try:
            check_schema(self.schema)
        except TypeError as error:
            raise ValueError(str(error)) from None

    def messages(self) -> list[dict[str, str]]:
        return [
            {"role": "system", "content": self.system},
            {"role": "user", "content": self.user},
        ]


@dataclass(frozen=True)
class LlmResult:
    data: Any  # validated against the request schema; still untrusted data
    task: str
    model: str
    request_hash: str
    attempts: int  # model replies consumed (1, or 2 after a schema retry)
    source: str  # "live", "record" or "replay"
    prompt_tokens: int | None = None
    completion_tokens: int | None = None
    extra: dict[str, Any] = field(default_factory=dict)


def _canonical(value: Any) -> bytes:
    """Sorted-key compact JSON, UTF-8. A local twin of JCS for plain strings, numbers and booleans.

    The gateway imports none of the authorization modules (docs/PROTOCOL.md Decision 95), so it cannot use
    `countersign.canonical`; the cassette key only needs to be stable, not interoperable.
    """
    return json.dumps(
        value, sort_keys=True, separators=(",", ":"), ensure_ascii=False, allow_nan=False
    ).encode("utf-8")


def request_key(
    task: str,
    model: str,
    messages: list[dict[str, str]],
    schema: dict[str, Any],
    temperature: float,
) -> str:
    """The cassette key: SHA-256 hex of the canonical form of (task, model, messages, schema, temperature)."""
    body = {
        "task": task, "model": model, "messages": messages, "schema": schema,
        "temperature": float(temperature),
    }  # fmt: skip
    return hashlib.sha256(b"cs.llm.request.v1\x00" + _canonical(body)).hexdigest()
