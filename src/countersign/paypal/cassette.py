"""Record and replay PayPal exchanges for integration tests, with credentials and accounts scrubbed.

Recording is off unless `PAYPAL_RECORD_CASSETTES=1` (`recording_enabled`). A `RecordingTransport`
wraps the real transport, remembers each exchange in scrubbed form, and `save` refuses to write a
file that still contains anything it should have removed. `CassetteTransport` replays a file and
answers strictly in order: each request must match the next recorded one (method, path, request id
and JSON body), so a client that changes what it sends fails the replay instead of passing silently.

Scrubbing. Authorization headers are never recorded. Request bodies keep their shape (only known
secret strings are replaced, so a replay can match them exactly). In responses, the token, application id, nonce,
scope, merchant (account) ids and e-mail addresses are replaced by key, whole `payer`, `shipping` and
`payment_source` objects are dropped (they hold names, addresses and account ids, and no model reads
them), and any known secret string (the client id and secret, and every access token seen) is replaced
wherever it appears. As a last check `save` rejects the file if it still contains a known secret, a
`Bearer` token, or an `@` anywhere (an e-mail address).
"""

from __future__ import annotations

import json
from collections.abc import Iterable, Mapping
from pathlib import Path
from typing import Any

import httpx

from countersign.canonical.jsonstrict import JsonSyntaxError, StrictJsonError, loads_strict

VERSION = 1
SCRUBBED = "SCRUBBED"
_KEYS = frozenset(
    {
        "access_token",
        "app_id",
        "nonce",
        "scope",
        "merchant_id",
        "account_id",
        "payer_id",
        "email_address",
    }
)
_DROP = frozenset({"payer", "shipping", "payment_source"})
_KEPT_RESPONSE_HEADERS = ("paypal-debug-id", "content-type")


class CassetteError(Exception):
    """A cassette could not be written safely, or a replayed request did not match."""


def recording_enabled(env: Mapping[str, str]) -> bool:
    return env.get("PAYPAL_RECORD_CASSETTES") == "1"


def scrub(value: Any, secrets: Iterable[str], *, structural: bool = True) -> Any:
    """A copy of `value` with the sensitive members and known secret strings removed.

    With `structural` false only the known secret strings are replaced: request bodies keep their
    shape (a replay matches them exactly) and are checked for secrets, not restructured.
    """
    known = [s for s in secrets if isinstance(s, str) and len(s) >= 4]

    def walk(node: Any, parent: str = "") -> Any:
        if isinstance(node, dict):
            out: dict[str, Any] = {}
            for key, item in node.items():
                # `breakdown.shipping` is an amount the order terms depend on, not the payer's address.
                if structural and key in _DROP and parent != "breakdown":
                    out[key] = {}
                elif structural and key in _KEYS:
                    out[key] = f"{SCRUBBED}_{key.upper()}"
                else:
                    out[key] = walk(item, key)
            return out
        if isinstance(node, list):
            return [walk(x, parent) for x in node]
        if isinstance(node, str):
            for secret in known:
                node = node.replace(secret, SCRUBBED)
            return node
        return node

    return walk(value)


def check_clean(text: str, secrets: Iterable[str]) -> None:
    """Raise `CassetteError` if serialized cassette text still holds anything sensitive."""
    for secret in secrets:
        if isinstance(secret, str) and len(secret) >= 4 and secret in text:
            raise CassetteError("the cassette still contains a known secret; nothing was written")
    if "Bearer " in text or "@" in text:
        raise CassetteError("the cassette contains a bearer token or an e-mail address")


def _json_or_none(content: bytes, content_type: str) -> Any:
    if "json" not in content_type or not content:
        return None
    try:
        return loads_strict(content)
    except JsonSyntaxError:
        return None
    except StrictJsonError as exc:
        raise CassetteError(
            f"a JSON body was refused by the strict JSON loader: {type(exc).__name__}"
        ) from None


class RecordingTransport(httpx.BaseTransport):
    def __init__(
        self,
        inner: httpx.BaseTransport,
        *,
        secrets: Iterable[str],
        meta: Mapping[str, Any] | None = None,
    ) -> None:
        self._inner = inner
        self._secrets = [s for s in secrets if s]
        self._meta = dict(meta or {})
        self._interactions: list[dict[str, Any]] = []

    def handle_request(self, request: httpx.Request) -> httpx.Response:
        body = request.read()
        response = self._inner.handle_request(request)
        response.read()
        payload = _json_or_none(response.content, response.headers.get("content-type", ""))
        if isinstance(payload, dict) and isinstance(payload.get("access_token"), str):
            self._secrets.append(payload["access_token"])
        request_json = _json_or_none(body, request.headers.get("content-type", ""))
        self._interactions.append(
            {
                "request": {
                    "method": request.method,
                    "path": request.url.raw_path.decode(),
                    "request_id": request.headers.get("paypal-request-id"),
                    "body": request_json,
                },
                "response": {
                    "status": response.status_code,
                    "headers": {
                        k: response.headers[k]
                        for k in _KEPT_RESPONSE_HEADERS
                        if k in response.headers
                    },
                    "body": payload,
                },
            }
        )
        return response

    def save(self, path: Path) -> None:
        interactions = [
            {
                "request": scrub(i["request"], self._secrets, structural=False),
                "response": scrub(i["response"], self._secrets),
            }
            for i in self._interactions
        ]
        document = {
            "version": VERSION,
            "meta": scrub(self._meta, self._secrets, structural=False),
            "interactions": interactions,
        }
        text = json.dumps(document, indent=2, sort_keys=True) + "\n"
        check_clean(text, self._secrets)
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(text, encoding="utf-8")

    def close(self) -> None:
        self._inner.close()


def load_cassette(path: Path) -> dict[str, Any]:
    try:
        data = loads_strict(path.read_bytes(), max_bytes=None)
    except StrictJsonError as exc:
        raise CassetteError(
            f"the cassette file was refused by the strict JSON loader: {type(exc).__name__}"
        ) from None
    if (
        not isinstance(data, dict)
        or data.get("version") != VERSION
        or not isinstance(data.get("interactions"), list)
    ):
        raise CassetteError("unsupported cassette file")
    return data


class CassetteTransport(httpx.BaseTransport):
    """Replays a cassette strictly in order."""

    def __init__(self, document: Mapping[str, Any]) -> None:
        self._interactions = list(document["interactions"])
        self._next = 0

    @property
    def remaining(self) -> int:
        return len(self._interactions) - self._next

    def handle_request(self, request: httpx.Request) -> httpx.Response:
        if self._next >= len(self._interactions):
            raise CassetteError(
                f"unexpected request {request.method} {request.url.raw_path.decode()}"
            )
        recorded = self._interactions[self._next]
        want = recorded["request"]
        got_path = request.url.raw_path.decode()
        if request.method != want["method"] or got_path != want["path"]:
            raise CassetteError(
                f"request {self._next + 1} was {request.method} {got_path}, "
                f"the cassette has {want['method']} {want['path']}"
            )
        if request.headers.get("paypal-request-id") != want["request_id"]:
            raise CassetteError(f"request {self._next + 1} has a different PayPal-Request-Id")
        if want["body"] is not None:
            sent = _json_or_none(request.read(), request.headers.get("content-type", ""))
            if sent != want["body"]:
                raise CassetteError(f"request {self._next + 1} has a different body")
        self._next += 1
        answer = recorded["response"]
        body = answer["body"]
        return httpx.Response(
            answer["status"],
            headers=answer["headers"],
            **({"json": body} if body is not None else {}),
        )

    def assert_exhausted(self) -> None:
        if self.remaining:
            raise CassetteError(f"{self.remaining} recorded exchanges were never requested")
