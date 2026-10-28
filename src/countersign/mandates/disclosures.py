"""Selective disclosure resolution (RFC 9901 section 7.1) for one link.

Security reasoning. A disclosure is only trusted through its digest in the signed JWT, so the
resolver replaces a digest with its value only when the digest of the received disclosure string
matches (the digest covers the base64url text, not the decoded bytes). It then refuses every
ambiguity RFC 9901 lists, because each one lets a holder present a different document than the
issuer signed:

- a digest that appears twice anywhere in the signed document (`DuplicateDigestError`);
- a disclosure never referenced, directly or through another disclosure
  (`UnreferencedDisclosureError`), which would be unsigned content riding along;
- a disclosed claim name that collides with a plaintext claim or another disclosure
  (`ClaimCollisionError`), and the reserved names `_sd` and `...`;
- a disclosure of the wrong kind for where its digest sits: an object property needs three
  elements, an array element two (`DisclosureMalformedError`);
- a `_sd_alg` other than `sha-256` (`UnsupportedSdAlgError`), so the digest algorithm is never
  attacker-chosen.

Digests that match no presented disclosure are legitimate (decoys, or withheld claims) and are
ignored. Array elements whose digest has no disclosure are removed from the result.
Every disclosure is decoded with the strict JSON loader.
"""

from __future__ import annotations

import hashlib
from collections.abc import Sequence

from countersign.canonical import JsonValue, StrictJsonError, b64url, loads_strict
from countersign.mandates.errors import (
    ClaimCollisionError,
    DisclosureMalformedError,
    DuplicateDigestError,
    DuplicateDisclosureError,
    MandateJsonError,
    UnreferencedDisclosureError,
    UnsupportedSdAlgError,
)
from countersign.mandates.structure import decode_b64url

MAX_DEPTH = 32
_RESERVED = ("_sd", "...")

type Disclosed = tuple[str | None, JsonValue]  # (claim name or None for an array element, value)


def disclosure_digest(disclosure: str) -> str:
    """base64url(SHA-256(US-ASCII bytes of the disclosure text)), RFC 9901 section 4.2.3."""
    return b64url(hashlib.sha256(disclosure.encode("ascii")).digest())


def _decode(disclosure: str) -> Disclosed:
    try:
        decoded = loads_strict(decode_b64url(disclosure, "disclosure"))
    except StrictJsonError as error:
        raise MandateJsonError(f"disclosure: {error}", error.code) from None
    if not isinstance(decoded, list) or len(decoded) not in (2, 3):
        raise DisclosureMalformedError("a disclosure is a JSON array of two or three elements")
    if not isinstance(decoded[0], str):
        raise DisclosureMalformedError("a disclosure salt must be a string")
    if len(decoded) == 2:
        return None, decoded[1]
    name = decoded[1]
    if not isinstance(name, str) or name in _RESERVED:
        raise DisclosureMalformedError("a disclosed claim name must be a string, not _sd or ...")
    return name, decoded[2]


class _Resolver:
    def __init__(self, disclosures: Sequence[str]) -> None:
        self.table: dict[str, Disclosed] = {}
        for text in disclosures:
            digest = disclosure_digest(text)
            if digest in self.table:
                raise DuplicateDisclosureError("a disclosure is presented twice")
            self.table[digest] = _decode(text)
        self.seen: set[str] = set()  # digests present in the signed document
        self.used: set[str] = set()  # digests replaced by a disclosure

    def _see(self, digest: object) -> str:
        if not isinstance(digest, str):
            raise DisclosureMalformedError("a digest must be a string")
        if digest in self.seen:
            raise DuplicateDigestError("a digest appears twice in the signed document")
        self.seen.add(digest)
        return digest

    def resolve(self, node: JsonValue, depth: int = 0) -> JsonValue:
        if depth > MAX_DEPTH:
            raise DisclosureMalformedError("document is nested too deeply")
        if isinstance(node, dict):
            return self._object(node, depth)
        if isinstance(node, list):
            return self._array(node, depth)
        return node

    def _object(self, node: dict[str, JsonValue], depth: int) -> dict[str, JsonValue]:
        out = {k: self.resolve(v, depth + 1) for k, v in node.items() if k != "_sd"}
        digests = node.get("_sd", [])
        if not isinstance(digests, list):
            raise DisclosureMalformedError("_sd must be an array")
        for item in digests:
            digest = self._see(item)
            entry = self.table.get(digest)
            if entry is None:
                continue
            name, value = entry
            if name is None:
                raise DisclosureMalformedError("an array element disclosure sits in an _sd list")
            if name in out:
                raise ClaimCollisionError("a disclosed claim name is already present")
            self.used.add(digest)
            out[name] = self.resolve(value, depth + 1)
        return out

    def _array(self, node: list[JsonValue], depth: int) -> list[JsonValue]:
        out: list[JsonValue] = []
        for element in node:
            if isinstance(element, dict) and "..." in element:
                if len(element) != 1:
                    raise DisclosureMalformedError("a '...' object has no other keys")
                digest = self._see(element["..."])
                entry = self.table.get(digest)
                if entry is None:
                    continue
                name, value = entry
                if name is not None:
                    raise DisclosureMalformedError("an object property disclosure sits in an array")
                self.used.add(digest)
                out.append(self.resolve(value, depth + 1))
            else:
                out.append(self.resolve(element, depth + 1))
        return out


def resolve_claims(
    payload: dict[str, JsonValue], disclosures: Sequence[str]
) -> dict[str, JsonValue]:
    """Return `payload` with every presented disclosure applied, or raise a `DisclosureError`."""
    sd_alg = payload.get("_sd_alg", "sha-256")
    if sd_alg != "sha-256":
        raise UnsupportedSdAlgError("only _sd_alg sha-256 is supported")
    resolver = _Resolver(disclosures)
    result = resolver.resolve(payload)
    if resolver.used != set(resolver.table):
        raise UnreferencedDisclosureError("a disclosure is not referenced by the signed document")
    if not isinstance(result, dict):
        raise DisclosureMalformedError("the signed payload must be an object")
    result.pop("_sd_alg", None)
    return result
