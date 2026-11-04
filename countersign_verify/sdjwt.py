"""Reading and verifying the two-link mandate chains the bundle carries (AP2 SD-JWT, Decision 23)."""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any

from countersign_verify.crypto import Invalid, digest, loads, unb64, verify_jws


def _disclosures(parts: list[str]) -> dict[str, list[Any]]:
    found: dict[str, list[Any]] = {}
    for text in parts:
        if not text:
            continue
        if "." in text:
            raise Invalid("a disclosure looks like a JWT")
        decoded = loads(unb64(text))
        if not isinstance(decoded, list) or len(decoded) not in (2, 3):
            raise Invalid("a disclosure is not a salted array")
        key = digest(text)
        if key in found:
            raise Invalid("a disclosure appears twice")
        found[key] = decoded
    return found


def _single_content(payload: dict[str, Any], disclosed: dict[str, list[Any]]) -> dict[str, Any]:
    delegate = payload.get("delegate_payload")
    if (
        payload.get("_sd_alg") != "sha-256"
        or not isinstance(delegate, list)
        or len(delegate) != 1
        or not isinstance(delegate[0], dict)
        or set(delegate[0]) != {"..."}
    ):
        raise Invalid("a mandate does not have exactly one hidden content element")
    entry = disclosed.get(delegate[0]["..."])
    if entry is None or len(entry) != 2 or not isinstance(entry[1], dict):
        raise Invalid("the content disclosure is missing")
    content: dict[str, Any] = entry[1]
    return content


@dataclass(frozen=True)
class OpenMandate:
    payload: dict[str, Any]
    content: dict[str, Any]


@dataclass(frozen=True)
class ClosedMandate:
    link: str
    payload: dict[str, Any]
    content: dict[str, Any]
    checkout_jwt: str


def split(chain: object) -> tuple[str, str]:
    """`(open serialization, closed link)` of `<open>~~<kb jwt>~<disclosures>~`."""
    if not isinstance(chain, str) or not chain.endswith("~"):
        raise Invalid("a mandate does not end with '~'")
    head, sep, link = chain.partition("~~")
    if not sep or not link or "~~" in link:
        raise Invalid("a mandate is not a two link chain")
    return head + "~", link


def read_open(serialization: str, platform_jwk: Any, vct: str) -> OpenMandate:
    parts = serialization.split("~")
    header, payload = verify_jws(parts[0], platform_jwk, typ="dc+sd-jwt")
    if not isinstance(payload, dict) or not isinstance(header, dict):
        raise Invalid("an open mandate payload is not an object")
    disclosed = _disclosures(parts[1:])
    content = _single_content(payload, disclosed)
    if set(disclosed) != {payload["delegate_payload"][0]["..."]}:
        raise Invalid("an open mandate carries a disclosure nothing refers to")
    if content.get("vct") != vct:
        raise Invalid("an open mandate has the wrong vct")
    cnf = content.get("cnf")
    if not isinstance(cnf, dict) or not isinstance(cnf.get("jwk"), dict):
        raise Invalid("an open mandate binds no agent key")
    if not isinstance(payload.get("sub"), str) or not payload["sub"]:
        raise Invalid("an open mandate names no customer")
    return OpenMandate(payload, content)


def read_closed(
    link: str, open_serialization: str, open_mandate: OpenMandate, vct: str, audience: str,
    hash_member: str,
) -> ClosedMandate:  # fmt: skip
    parts = link.split("~")
    _, payload = verify_jws(parts[0], open_mandate.content["cnf"]["jwk"], typ="kb+sd-jwt")
    if not isinstance(payload, dict):
        raise Invalid("a key binding payload is not an object")
    if payload.get("sd_hash") != digest(open_serialization):
        raise Invalid("the key binding is not bound to this open mandate")
    if payload.get("aud") != audience:
        raise Invalid("the key binding has the wrong audience")
    if not isinstance(payload.get("nonce"), str) or not payload["nonce"]:
        raise Invalid("the key binding has no nonce")
    iat, exp = payload.get("iat"), open_mandate.content.get("exp")
    if type(iat) is not int or type(exp) is not int or iat > exp:
        raise Invalid("the closed mandate was signed after the open mandate expired")
    disclosed = _disclosures(parts[1:])
    content = _single_content(payload, disclosed)
    hidden = content.get("_sd")
    if not isinstance(hidden, list) or len(hidden) != 1:
        raise Invalid("the closed mandate hides no checkout_jwt")
    cj = disclosed.get(hidden[0])
    if cj is None or len(cj) != 3 or cj[1] != "checkout_jwt" or not isinstance(cj[2], str):
        raise Invalid("the checkout_jwt disclosure is missing")
    if set(disclosed) != {payload["delegate_payload"][0]["..."], hidden[0]}:
        raise Invalid("the closed mandate carries a disclosure nothing refers to")
    if content.get("vct") != vct:
        raise Invalid("a closed mandate has the wrong vct")
    if content.get(hash_member) != digest(cj[2]):
        raise Invalid(f"{hash_member} is not the hash of the disclosed checkout_jwt")
    return ClosedMandate(link, payload, content, cj[2])
