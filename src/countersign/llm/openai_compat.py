"""One adapter for any OpenAI-compatible chat completions endpoint.

Configuration comes from the environment only (`LLM_BASE_URL`, `LLM_MODEL`, `LLM_API_KEY`). The key goes
in the `Authorization` header and nowhere else: it is never logged, never put in an error message and not
part of `repr` (docs/PROTOCOL.md Decision 96). The adapter sends `messages`, `temperature`, an optional
`seed` and a `response_format`:

- `json_schema` (strict structured output) where the endpoint supports it,
- `json_object` (JSON mode), where the schema is also written into the system message,
- `text`, with the schema in the system message and JSON-in-text parsing downstream.

An endpoint that refuses the `response_format` with a 400 or 422 makes the adapter step down one level
(`json_schema` to `json_object` to `text`) and try again. The reply text is returned untouched; parsing and
validation are the gateway's job. The adapter executes nothing it receives.
"""

from __future__ import annotations

import json
from typing import Any

import httpx

from countersign.llm.provider import (
    ProviderCall,
    ProviderHttpError,
    ProviderReply,
    ProviderTransportError,
)

FORMATS = ("json_schema", "json_object", "text")


class OpenAICompatProvider:
    def __init__(
        self,
        base_url: str,
        api_key: str,
        *,
        response_format: str = "json_object",
        transport: httpx.BaseTransport | None = None,
    ) -> None:
        if response_format not in FORMATS:
            raise ValueError("response_format is json_schema, json_object or text")
        self._url = base_url.rstrip("/") + "/chat/completions"
        self._key = api_key
        self._format = response_format
        self._client = httpx.Client(transport=transport)

    def __repr__(self) -> str:  # the key is never part of a representation
        return f"OpenAICompatProvider(url={self._url!r}, format={self._format!r})"

    def generate(self, call: ProviderCall) -> ProviderReply:
        while True:
            try:
                return self._once(call, self._format)
            except ProviderHttpError as error:
                lower = FORMATS.index(self._format) + 1
                if error.status in (400, 422) and lower < len(FORMATS):
                    self._format = FORMATS[
                        lower
                    ]  # this endpoint does not take that response_format
                    continue
                raise

    def _body(self, call: ProviderCall, fmt: str) -> dict[str, Any]:
        messages = [dict(m) for m in call.messages]
        if fmt != "json_schema" and messages and messages[0]["role"] == "system":
            messages[0]["content"] += (
                "\n\nReply with one JSON object only, no other text, matching this JSON Schema: "
                + json.dumps(call.schema, sort_keys=True, separators=(",", ":"))
            )
        body: dict[str, Any] = {
            "model": call.model,
            "messages": messages,
            "temperature": call.temperature,
            "max_tokens": call.max_tokens,
        }
        if call.seed is not None:
            body["seed"] = call.seed
        if fmt == "json_schema":
            body["response_format"] = {
                "type": "json_schema",
                "json_schema": {"name": call.schema_name, "strict": True, "schema": call.schema},
            }
        elif fmt == "json_object":
            body["response_format"] = {"type": "json_object"}
        return body

    def _once(self, call: ProviderCall, fmt: str) -> ProviderReply:
        try:
            response = self._client.post(
                self._url,
                json=self._body(call, fmt),
                headers={
                    "Authorization": f"Bearer {self._key}",
                    "Content-Type": "application/json",
                },
                timeout=call.timeout_s,
            )
        except httpx.TimeoutException:
            raise ProviderTransportError("timeout") from None
        except httpx.HTTPError as error:
            raise ProviderTransportError(type(error).__name__) from None
        if response.status_code >= 400:
            retry_after: float | None = None
            try:
                retry_after = float(response.headers.get("retry-after", ""))
            except ValueError:
                retry_after = None
            raise ProviderHttpError(response.status_code, retry_after, response.text)
        try:
            payload = response.json()
            text = payload["choices"][0]["message"]["content"]
            usage = payload.get("usage") or {}
        except (ValueError, KeyError, IndexError, TypeError):
            raise ProviderTransportError("undecodable body") from None
        if not isinstance(text, str):
            raise ProviderTransportError("no text content")
        return ProviderReply(
            text, _count(usage.get("prompt_tokens")), _count(usage.get("completion_tokens"))
        )


def _count(value: object) -> int | None:
    return value if isinstance(value, int) and not isinstance(value, bool) else None
