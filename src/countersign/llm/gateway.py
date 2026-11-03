"""The model gateway: `complete(request)` returns validated, structured, untrusted data.

Model output is data. The gateway parses it as JSON, checks it against the caller's schema, and returns it
or raises a typed error. It executes nothing, calls no tool, and does not act on instructions found in the
text. On a schema failure it retries once with the validator's error (path and rule, never the offending
value) appended, then raises `LlmSchemaError`. It imports no authorization module and none imports it
(`tests/unit/test_llm_boundary.py`, docs/PROTOCOL.md Decision 95): what comes out may only be PROPOSED
values that deterministic code validates again before anything depends on them.

Modes: `live` calls the provider, `record` calls it and writes a scrubbed cassette per reply, `replay`
reads cassettes and fails closed with `LlmReplayMissingError` when one is missing. Live calls pass the
client-side rate limiter and the run's call budget, back off with jitter on 429 and 5xx inside the
request's total deadline, and never log a prompt, an output (outside debug, never in demo) or the key.
"""

from __future__ import annotations

import json
import random
import re
import time
from collections.abc import Callable
from typing import Any

import structlog

from countersign.llm.cassette import CassetteStore, scrub
from countersign.llm.config import LlmConfig
from countersign.llm.errors import (
    LlmError,
    LlmOutputTooLargeError,
    LlmProviderError,
    LlmReplayMissingError,
    LlmSchemaError,
    LlmTimeoutError,
)
from countersign.llm.limits import CallBudget, RateLimiter
from countersign.llm.provider import (
    Provider,
    ProviderCall,
    ProviderHttpError,
    ProviderReply,
    ProviderTransportError,
)
from countersign.llm.request import LlmRequest, LlmResult, request_key
from countersign.llm.schema import validate

log = structlog.get_logger("countersign.llm")

MAX_ATTEMPTS = 4
BACKOFF_BASE_S = 1.0
BACKOFF_CAP_S = 20.0
_FENCE = re.compile(r"^\s*```[a-zA-Z]*\s*(.*?)\s*```\s*$", re.DOTALL)


def _no_constant(name: str) -> Any:
    raise ValueError(f"{name} is not JSON")


def parse_output(text: str) -> Any:
    """Parse model text as one JSON value: strict first, then JSON in a fenced block or the first object.

    NaN, Infinity and duplicate keys are refused. This only finds the JSON; it believes nothing in it.
    """

    def strict(candidate: str) -> Any:
        def pairs(items: list[tuple[str, Any]]) -> dict[str, Any]:
            keys = [k for k, _ in items]
            if len(set(keys)) != len(keys):
                raise ValueError("duplicate key")
            return dict(items)

        return json.loads(candidate, parse_constant=_no_constant, object_pairs_hook=pairs)

    try:
        return strict(text)
    except ValueError:
        pass
    fenced = _FENCE.match(text)
    if fenced:
        try:
            return strict(fenced.group(1))
        except ValueError:
            pass
    start, end = text.find("{"), text.rfind("}")
    if 0 <= start < end:
        try:
            return strict(text[start : end + 1])
        except ValueError:
            pass
    raise ValueError("no JSON object in the output")


class LlmGateway:
    def __init__(
        self,
        config: LlmConfig,
        provider: Provider | None = None,
        *,
        store: CassetteStore | None = None,
        clock: Callable[[], float] = time.monotonic,
        sleep: Callable[[float], None] = time.sleep,
        jitter: Callable[[], float] = random.random,
    ) -> None:
        config.check()
        self._config = config
        self._provider = provider
        self._store = store or CassetteStore(config.cassette_dir)
        self._clock = clock
        self._sleep = sleep
        self._jitter = jitter
        self._limiter = RateLimiter(config.per_minute, clock, sleep)
        self._budget = CallBudget(config.max_calls)
        if config.mode in ("live", "record") and provider is None:
            raise LlmError("live or record mode needs a provider")

    @property
    def config(self) -> LlmConfig:
        return self._config

    @property
    def calls_used(self) -> int:
        return self._budget.used

    # ------------------------------------------------------------------ public

    def complete(self, request: LlmRequest) -> LlmResult:
        messages = request.messages()
        errors: list[str] = []
        total_prompt: int | None = None
        total_completion: int | None = None
        for attempt in (1, 2):
            reply, key = self._reply(request, messages)
            total_prompt = _add(total_prompt, reply.prompt_tokens)
            total_completion = _add(total_completion, reply.completion_tokens)
            if len(reply.text) > request.max_output_chars:
                self._outcome(request, key, "output_too_large")
                raise LlmOutputTooLargeError("the model output exceeds the size limit")
            try:
                data = parse_output(reply.text)
                errors = validate(data, request.schema)
            except ValueError:
                errors = ["$: not parseable as JSON"]
            if not errors:
                self._outcome(request, key, "ok", attempt)
                return LlmResult(
                    data, request.task, self._config.model, key, attempt, self._config.mode,
                    total_prompt, total_completion,
                )  # fmt: skip
            self._outcome(request, key, "schema_invalid", attempt)
            if attempt == 1:
                messages = [
                    *messages,
                    {
                        "role": "user",
                        "content": "Your previous reply did not match the schema ("
                        + "; ".join(errors[:5])
                        + "). Reply again with one JSON object only that matches the schema.",
                    },
                ]
        raise LlmSchemaError(errors)

    # ------------------------------------------------------------------ one reply

    def _reply(
        self, request: LlmRequest, messages: list[dict[str, str]]
    ) -> tuple[ProviderReply, str]:
        key = request_key(
            request.task, self._config.model, messages, request.schema, request.temperature
        )
        if self._config.mode == "replay":
            recorded = self._store.load(key)
            if recorded is None:
                self._outcome(request, key, "replay_missing")
                raise LlmReplayMissingError(key, request.task)
            return recorded.reply, key
        assert self._provider is not None
        started = self._clock()
        reply = self._call_with_backoff(request, messages)
        if self._config.mode == "record":
            self._store.save(
                key, task=request.task, model=self._config.model, messages=messages,
                schema=request.schema, temperature=request.temperature, reply=reply,
                secrets=(self._config.api_key,),
            )  # fmt: skip
        self._latency = self._clock() - started
        return reply, key

    def _call_with_backoff(
        self, request: LlmRequest, messages: list[dict[str, str]]
    ) -> ProviderReply:
        assert self._provider is not None
        deadline = self._clock() + request.timeout_s
        for attempt in range(1, MAX_ATTEMPTS + 1):
            remaining = deadline - self._clock()
            if remaining <= 0:
                raise LlmTimeoutError("the model call ran out of time")
            self._limiter.acquire(deadline)
            self._budget.spend()
            call = ProviderCall(
                model=self._config.model, messages=messages, schema=request.schema,
                schema_name=request.task.replace("-", "_"), temperature=request.temperature,
                seed=request.seed if request.seed is not None else self._config.seed,
                timeout_s=max(remaining, 0.001), max_tokens=max(64, request.max_output_chars // 2),
            )  # fmt: skip
            try:
                return self._provider.generate(call)
            except ProviderHttpError as error:
                if error.status != 429 and error.status < 500:
                    raise LlmProviderError(
                        f"the endpoint refused the request ({error.status})"
                    ) from None
                wait = self._delay(attempt, error.retry_after)
                reason = f"http_{error.status}"
            except ProviderTransportError as error:
                wait = self._delay(attempt, None)
                reason = f"transport_{error}"[:40]
            if attempt == MAX_ATTEMPTS or self._clock() + wait >= deadline:
                if self._clock() + wait >= deadline:
                    raise LlmTimeoutError("the model call ran out of time while backing off")
                raise LlmProviderError(f"the endpoint kept failing ({reason})")
            log.info("llm_backoff", task=request.task, reason=reason, wait_s=round(wait, 3))
            self._sleep(wait)
        raise LlmProviderError("the endpoint kept failing")

    def _delay(self, attempt: int, retry_after: float | None) -> float:
        base = min(BACKOFF_CAP_S, BACKOFF_BASE_S * (2 ** (attempt - 1)))
        wait: float = base * (
            0.5 + 0.5 * float(self._jitter())
        )  # jittered between half and the whole step
        if retry_after is not None and retry_after > 0:
            wait = max(wait, min(retry_after, BACKOFF_CAP_S))
        return wait

    # ------------------------------------------------------------------ logging

    _latency: float = 0.0

    def _outcome(self, request: LlmRequest, key: str, outcome: str, attempt: int = 1) -> None:
        """Task, model, latency, request hash and outcome. Never the key, a header, or (in demo) a prompt."""
        log.info(
            "llm_call", task=request.task, model=self._config.model, mode=self._config.mode,
            request_hash=key[:16], outcome=outcome, attempt=attempt,
            latency_ms=round(self._latency * 1000),
        )  # fmt: skip
        if not self._config.demo:
            log.debug(
                "llm_payload", task=request.task, request_hash=key[:16],
                system=scrub(request.system, (self._config.api_key,)),
                user=scrub(request.user, (self._config.api_key,)),
            )  # fmt: skip


def _add(total: int | None, more: int | None) -> int | None:
    if more is None:
        return total
    return more if total is None else total + more
