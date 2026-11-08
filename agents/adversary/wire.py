"""The adversary's own byte-level helpers: base64url, a signature rewrite, a tamper and a JSON with a
duplicate key. Nothing here imports `countersign`; nothing here signs on behalf of a customer."""

from __future__ import annotations

import base64
import json
from typing import Any

P256_ORDER = 0xFFFFFFFF00000000FFFFFFFFFFFFFFFFBCE6FAADA7179E84F3B9CAC2FC632551


def b64url(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode("ascii")


def unb64(text: str) -> bytes:
    return base64.urlsafe_b64decode(text + "=" * (-len(text) % 4))


def malleate_signature(token: str) -> str:
    """The same signed credential with its issuer signature rewritten as (r, n - s).

    Anyone can do this without a key; ECDSA verifiers accept both forms, so one issued mandate has two
    serializations with two different digests."""
    jwt, rest = token.split("~", 1)
    header, payload, signature = jwt.split(".")
    raw = unb64(signature)
    r, s = int.from_bytes(raw[:32], "big"), int.from_bytes(raw[32:], "big")
    flipped = r.to_bytes(32, "big") + (P256_ORDER - s).to_bytes(32, "big")
    return f"{header}.{payload}.{b64url(flipped)}~{rest}"


def flip_middle(token: str) -> str:
    """Change one character in the middle of a token (a forged or corrupted credential)."""
    mid = len(token) // 2
    return token[:mid] + ("A" if token[mid] != "A" else "B") + token[mid + 1 :]


def with_duplicate_key(obj: dict[str, Any], key: str, second: Any) -> bytes:
    """A JSON object that carries `key` twice: the value in `obj`, then `second`."""
    raw = json.dumps(obj)
    return (raw[:-1] + ", " + json.dumps(key) + ": " + json.dumps(second) + "}").encode()
