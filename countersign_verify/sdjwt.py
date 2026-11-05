"""Reading and verifying the two-link mandate chains the bundle carries (AP2 SD-JWT, Decision 23)."""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any

from countersign_verify.crypto import Invalid, digest, is_int, loads, unb64, verify_jws


def _key(value: Any) -> Any:
    """A value used to look up a disclosure: unhashable values fail as malformed, like a dict lookup."""
    if isinstance(value, (dict, list)):
        raise TypeError("unhashable lookup key")
    return value


def _disclosures(parts: list[str]) -> dict[str, list[Any]]:
    found: dict[str, list[Any]] = {}
    for text in parts:
        if not text:
            continue
        if "." in text:
            raise Invalid("disclosure_is_jwt", "a disclosure looks like a JWT")
        decoded = loads(unb64(text))
        if not isinstance(decoded, list) or len(decoded) not in (2, 3):
            raise Invalid("disclosure_shape", "a disclosure is not a salted array")
        key = digest(text)
        if key in found:
            raise Invalid("disclosure_repeated", "a disclosure appears twice")
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
        raise Invalid(
            "mandate_content_shape", "a mandate does not have exactly one hidden content element"
        )
    entry = disclosed.get(_key(delegate[0]["..."]))
    if entry is None or len(entry) != 2 or not isinstance(entry[1], dict):
        raise Invalid("mandate_content_missing", "the content disclosure is missing")
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
        raise Invalid("chain_shape", "a mandate does not end with '~'")
    head, sep, link = chain.partition("~~")
    if not sep or not link or "~~" in link:
        raise Invalid("chain_shape", "a mandate is not a two link chain")
    return head + "~", link


def read_open(serialization: str, platform_jwk: Any, vct: str) -> OpenMandate:
    parts = serialization.split("~")
    header, payload = verify_jws(parts[0], platform_jwk, typ="dc+sd-jwt")
    if not isinstance(payload, dict) or not isinstance(header, dict):
        raise Invalid("open_payload_shape", "an open mandate payload is not an object")
    disclosed = _disclosures(parts[1:])
    content = _single_content(payload, disclosed)
    if set(disclosed) != {payload["delegate_payload"][0]["..."]}:
        raise Invalid(
            "open_extra_disclosure", "an open mandate carries a disclosure nothing refers to"
        )
    if content.get("vct") != vct:
        raise Invalid("open_vct", "an open mandate has the wrong vct")
    cnf = content.get("cnf")
    if not isinstance(cnf, dict) or not isinstance(cnf.get("jwk"), dict):
        raise Invalid("open_no_agent_key", "an open mandate binds no agent key")
    if not isinstance(payload.get("sub"), str) or not payload["sub"]:
        raise Invalid("open_no_customer", "an open mandate names no customer")
    return OpenMandate(payload, content)


def read_closed(
    link: str, open_serialization: str, open_mandate: OpenMandate, vct: str, audience: str,
    hash_member: str,
) -> ClosedMandate:  # fmt: skip
    parts = link.split("~")
    _, payload = verify_jws(parts[0], open_mandate.content["cnf"]["jwk"], typ="kb+sd-jwt")
    if not isinstance(payload, dict):
        raise Invalid("closed_payload_shape", "a key binding payload is not an object")
    if payload.get("sd_hash") != digest(open_serialization):
        raise Invalid("closed_sd_hash", "the key binding is not bound to this open mandate")
    if payload.get("aud") != audience:
        raise Invalid("closed_audience", "the key binding has the wrong audience")
    if not isinstance(payload.get("nonce"), str) or not payload["nonce"]:
        raise Invalid("closed_no_nonce", "the key binding has no nonce")
    iat, exp = payload.get("iat"), open_mandate.content.get("exp")
    if not is_int(iat) or not is_int(exp) or iat > exp:
        raise Invalid(
            "closed_after_expiry", "the closed mandate was signed after the open one expired"
        )
    disclosed = _disclosures(parts[1:])
    content = _single_content(payload, disclosed)
    hidden = content.get("_sd")
    if not isinstance(hidden, list) or len(hidden) != 1:
        raise Invalid("closed_no_checkout_jwt", "the closed mandate hides no checkout_jwt")
    cj = disclosed.get(_key(hidden[0]))
    if cj is None or len(cj) != 3 or cj[1] != "checkout_jwt" or not isinstance(cj[2], str):
        raise Invalid("closed_no_checkout_jwt", "the checkout_jwt disclosure is missing")
    if set(disclosed) != {payload["delegate_payload"][0]["..."], hidden[0]}:
        raise Invalid(
            "closed_extra_disclosure", "a closed mandate carries a disclosure nothing refers to"
        )
    if content.get("vct") != vct:
        raise Invalid("closed_vct", "a closed mandate has the wrong vct")
    if content.get(hash_member) != digest(cj[2]):
        raise Invalid(
            "closed_hash_member", f"{hash_member} is not the hash of the disclosed checkout_jwt"
        )
    return ClosedMandate(link, payload, content, cj[2])
