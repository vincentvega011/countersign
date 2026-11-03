"""What a provider adapter looks like. Adapters return text; they never interpret it."""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any, Protocol


class ProviderHttpError(Exception):
    """The endpoint answered with an error status. 429 and 5xx are retried by the gateway."""

    def __init__(self, status: int, retry_after: float | None = None, body: str = "") -> None:
        super().__init__(f"http {status}")
        self.status = status
        self.retry_after = retry_after
        self.body = body[:300]


class ProviderTransportError(Exception):
    """No usable answer (connection, timeout, undecodable body). Retried like a 5xx."""


@dataclass(frozen=True)
class ProviderCall:
    model: str
    messages: list[dict[str, str]]
    schema: dict[str, Any]
    schema_name: str
    temperature: float
    seed: int | None
    timeout_s: float
    max_tokens: int


@dataclass(frozen=True)
class ProviderReply:
    text: str
    prompt_tokens: int | None = None
    completion_tokens: int | None = None


class Provider(Protocol):
    def generate(self, call: ProviderCall) -> ProviderReply: ...
