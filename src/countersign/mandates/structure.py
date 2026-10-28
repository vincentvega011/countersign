"""Strict structural validation of a mandate string (docs/PROTOCOL.md Decision 9).

The UCP pattern for `ap2.checkout_mandate` rejects valid mandates, so Countersign validates the
string itself, before any decoding or signature work. Checks, in order:

1. It is `str` and at most `MAX_MANDATE_CHARS` long. Reason: bound the work an attacker can force.
2. Only base64url characters, `.` and `~`. Reason: whitespace, padding `=` and non-ASCII text are
   where two parsers disagree about what was signed. Whitespace is never trimmed.
3. The Delegate SD-JWT split rules. The string ends with `~` (a trailing key-binding JWT, which AP2
   mandates do not use, is refused). Links are separated by exactly one empty component, so `~~`
   between links and never `~` alone or `~~~`. Reason: with a single `~` the key-binding JWT would
   parse as a disclosure of the previous link, and an extra empty component hides a component.
4. Each link is a JWT of exactly three dot-separated segments followed by disclosures. A duplicate
   disclosure inside one link is refused. Reason: duplicates make the digest table ambiguous.

`decode_b64url` is the only base64url decoder in this package. It insists on canonical text:
re-encoding the decoded bytes must reproduce the input. Without that, the final character of a
segment carries unused bits that can be flipped without changing the decoded bytes, so an altered
string would still verify (the signature segment) or hash differently from what was verified.
"""

from __future__ import annotations

import base64
import re
from dataclasses import dataclass

from countersign.canonical import b64url
from countersign.mandates.errors import (
    Base64UrlError,
    ChainSeparatorError,
    CharacterSetError,
    DuplicateDisclosureError,
    MandateTooLargeError,
    MandateTypeError,
    MissingTrailingTildeError,
    SegmentCountError,
    TrailingKeyBindingError,
)

# Decision 8 sets 16 KiB for a payment mandate token. Checkout mandates embed a checkout_jwt and
# are no larger in practice; one limit keeps the rule simple.
MAX_MANDATE_CHARS = 16 * 1024

_CHARSET = re.compile(r"[A-Za-z0-9_.~-]*")
_BASE64URL = re.compile(r"[A-Za-z0-9_-]*")


@dataclass(frozen=True)
class RawLink:
    """One link of the chain: a compact JWT and the disclosures presented with it."""

    jwt: str
    disclosures: tuple[str, ...]

    @property
    def serialization(self) -> str:
        """`<jwt>~<disclosure 1>~...~<disclosure N>~`, the input to `sd_hash` (RFC 9901 4.3.1)."""
        return "~".join((self.jwt, *self.disclosures)) + "~"


def decode_b64url(text: str, what: str) -> bytes:
    """Decode canonical unpadded base64url, or raise `Base64UrlError`."""
    if not _BASE64URL.fullmatch(text) or len(text) % 4 == 1:
        raise Base64UrlError(f"{what} is not base64url")
    raw = base64.urlsafe_b64decode(text + "=" * (-len(text) % 4))
    if b64url(raw) != text:
        raise Base64UrlError(f"{what} is not canonical base64url")
    return raw


def split_chain(token: object) -> tuple[RawLink, ...]:
    """Split a mandate string into links under the rules in the module docstring."""
    if not isinstance(token, str):
        raise MandateTypeError("a mandate must be a str")
    if len(token) > MAX_MANDATE_CHARS:
        raise MandateTooLargeError(f"mandate is longer than {MAX_MANDATE_CHARS} characters")
    if not _CHARSET.fullmatch(token):
        raise CharacterSetError("mandate contains characters outside base64url, '.' and '~'")
    parts = token.split("~")
    last = parts.pop()
    if last:
        if "." in last:
            raise TrailingKeyBindingError("a trailing key-binding JWT is not used by AP2 mandates")
        raise MissingTrailingTildeError("mandate must end with '~'")
    links: list[RawLink] = []
    i = 0
    while True:
        jwt = parts[i] if i < len(parts) else ""
        if not jwt:
            raise ChainSeparatorError("expected a JWT (empty, dangling or extra '~' component)")
        if jwt.count(".") != 2:
            raise SegmentCountError("a JWT must have exactly three segments")
        i += 1
        disclosures: list[str] = []
        while i < len(parts) and parts[i]:
            if "." in parts[i]:
                raise ChainSeparatorError("links must be separated by '~~'")
            disclosures.append(parts[i])
            i += 1
        if len(set(disclosures)) != len(disclosures):
            raise DuplicateDisclosureError("a disclosure appears twice in one link")
        links.append(RawLink(jwt, tuple(disclosures)))
        if i == len(parts):
            return tuple(links)
        i += 1  # the single empty component between links
