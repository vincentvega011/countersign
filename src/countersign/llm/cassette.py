"""Record and replay of model calls: one file per request in eval/cassettes/llm/.

A cassette is named by the request key (`request.request_key`) and holds the scrubbed messages, the
model, the schema hash and the provider's reply text with token counts. No header, URL, key or account id
is ever stored: the writer takes only those fields, and every string also goes through `scrub`. Replay
reads by key; a missing file is a typed error (the gateway fails closed). Cassettes are never edited by hand.
"""

from __future__ import annotations

import hashlib
import json
import re
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from countersign.llm.provider import ProviderReply

ROOT = Path(__file__).resolve().parents[3]
DEFAULT_DIR = ROOT / "eval" / "cassettes" / "llm"
VERSION = 1

_PATTERNS = (
    re.compile(r"(?i)bearer\s+[A-Za-z0-9._~+/=-]{8,}"),
    re.compile(r"AIza[0-9A-Za-z_-]{20,}"),
    re.compile(r"\bgsk_[A-Za-z0-9]{16,}"),
    re.compile(r"\bsk-[A-Za-z0-9_-]{16,}"),
    re.compile(r"(?i)\b(org|proj|project|acct|account)[-_][A-Za-z0-9]{8,}"),
    re.compile(
        r"""(?i)(api[_-]?key|authorization|x-goog-api-key|token)\s*[:=]\s*(?!\[redacted)[^\s"',}\]]{6,}"""
    ),
)
REDACTED = "[redacted]"


def scrub(text: str, secrets: tuple[str, ...] = ()) -> str:
    """Remove anything that looks like a credential or an account id, and any known secret value."""
    for secret in secrets:
        if secret and len(secret) >= 6:
            text = text.replace(secret, REDACTED)
    for pattern in _PATTERNS:
        text = pattern.sub(REDACTED, text)
    return text


def _scrub_value(value: Any, secrets: tuple[str, ...]) -> Any:
    if isinstance(value, str):
        return scrub(value, secrets)
    if isinstance(value, list):
        return [_scrub_value(v, secrets) for v in value]
    if isinstance(value, dict):
        return {scrub(str(k), secrets): _scrub_value(v, secrets) for k, v in value.items()}
    return value


def scrub_reply(text: str, secrets: tuple[str, ...] = ()) -> str:
    """Scrub a model reply. JSON is scrubbed value by value and written back as JSON, so the redaction
    can never break the structure that replay has to parse; anything else is scrubbed as text."""
    try:
        return json.dumps(_scrub_value(json.loads(text), secrets), sort_keys=True)
    except ValueError:
        return scrub(text, secrets)


@dataclass(frozen=True)
class Recorded:
    reply: ProviderReply
    model: str
    task: str


class CassetteStore:
    def __init__(self, directory: Path = DEFAULT_DIR) -> None:
        self.directory = directory

    def path(self, key: str) -> Path:
        if not re.fullmatch(r"[0-9a-f]{64}", key):
            raise ValueError("a cassette key is 64 hex characters")
        return self.directory / f"{key}.json"

    def load(self, key: str) -> Recorded | None:
        path = self.path(key)
        if not path.is_file():
            return None
        data = json.loads(path.read_text(encoding="utf-8"))
        if data.get("v") != VERSION or data.get("key") != key:
            return None
        usage = data.get("usage") or {}
        return Recorded(
            ProviderReply(
                str(data["reply"]), usage.get("prompt_tokens"), usage.get("completion_tokens")
            ),
            str(data["model"]),
            str(data["task"]),
        )

    def save(
        self,
        key: str,
        *,
        task: str,
        model: str,
        messages: list[dict[str, str]],
        schema: dict[str, Any],
        temperature: float,
        reply: ProviderReply,
        secrets: tuple[str, ...] = (),
    ) -> Path:
        self.directory.mkdir(parents=True, exist_ok=True)
        body = {
            "v": VERSION,
            "key": key,
            "task": task,
            "model": model,
            "temperature": temperature,
            "schema_sha256": hashlib.sha256(
                json.dumps(schema, sort_keys=True, separators=(",", ":")).encode()
            ).hexdigest(),
            "messages": [
                {"role": m["role"], "content": scrub(m["content"], secrets)} for m in messages
            ],
            "reply": scrub_reply(reply.text, secrets),
            "usage": {
                "prompt_tokens": reply.prompt_tokens,
                "completion_tokens": reply.completion_tokens,
            },
        }
        path = self.path(key)
        path.write_text(json.dumps(body, indent=2, sort_keys=True) + "\n", encoding="utf-8")
        return path
