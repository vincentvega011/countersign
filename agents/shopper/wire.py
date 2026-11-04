"""The agent's own wire and crypto helpers: JCS, ES256, SD-JWT reading and closed-mandate signing.

Written for the agent and importing nothing from `countersign` (Decision 98): the agent is a separate
process that talks to the service over HTTP, so a defect in the server's helpers must not be mirrored
here. It doubles as an independent implementation: what it signs the server verifies, and what the
server signs it verifies.

Nothing here decides about money. The agent checks what it is given (a merchant signature, the
terms of an open mandate) before it trusts it; the service checks everything again.
"""

from __future__ import annotations

import base64
import hashlib
import json
import secrets
from typing import Any

import rfc8785
from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.asymmetric.utils import encode_dss_signature

VCT_CHECKOUT_CLOSED = "mandate.checkout.1"
VCT_PAYMENT_CLOSED = "mandate.payment.1"
AUD_CHECKOUT = "merchant"
AUD_PAYMENT = "credential-provider"


class WireError(ValueError):
    """Malformed or unverifiable wire data. The message never carries a secret."""


def b64url(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode("ascii")


def unb64(text: str) -> bytes:
    if not isinstance(text, str) or not text.isascii():
        raise WireError("not base64url")
    try:
        return base64.urlsafe_b64decode(text + "=" * (-len(text) % 4))
    except ValueError:
        raise WireError("not base64url") from None


def jcs(value: Any) -> bytes:
    try:
        return rfc8785.dumps(value)
    except (TypeError, ValueError, OverflowError):
        raise WireError("no canonical form") from None


def thumbprint(jwk: dict[str, Any]) -> str:
    """RFC 7638 for an EC key, over the JCS bytes of the four required members."""
    members = {m: jwk.get(m) for m in ("crv", "kty", "x", "y")}
    if not all(isinstance(v, str) for v in members.values()):
        raise WireError("not an EC public JWK")
    return b64url(hashlib.sha256(jcs(members)).digest())


def public_key_of(jwk: dict[str, Any]) -> ec.EllipticCurvePublicKey:
    if jwk.get("kty") != "EC" or jwk.get("crv") != "P-256":
        raise WireError("not a P-256 key")
    x, y = unb64(str(jwk.get("x"))), unb64(str(jwk.get("y")))
    if len(x) != 32 or len(y) != 32:
        raise WireError("bad coordinates")
    try:
        return ec.EllipticCurvePublicNumbers(
            int.from_bytes(x, "big"), int.from_bytes(y, "big"), ec.SECP256R1()
        ).public_key()
    except ValueError:
        raise WireError("the point is not on the curve") from None


def verify_es256(jwk: dict[str, Any], signing_input: bytes, signature_b64: str) -> bool:
    raw = unb64(signature_b64)
    if len(raw) != 64:
        return False
    der = encode_dss_signature(int.from_bytes(raw[:32], "big"), int.from_bytes(raw[32:], "big"))
    try:
        public_key_of(jwk).verify(der, signing_input, ec.ECDSA(hashes.SHA256()))
    except InvalidSignature:
        return False
    return True


def digest(text: str) -> str:
    """`sd_hash`-style digest: unpadded base64url of SHA-256 over the US-ASCII text."""
    return b64url(hashlib.sha256(text.encode("ascii")).digest())


# ------------------------------------------------------------------------------------ the checkout


def checkout_jwt_of(body: dict[str, Any], published_keys: list[dict[str, Any]]) -> str:
    """Verify `ap2.merchant_authorization` of a checkout response and return the compact checkout JWT.

    The signature covers the JCS bytes of the response without its `ap2` member (UCP AP2 mandates
    extension). Raises `WireError` for a missing, malformed or unverifiable authorization: the agent
    must not trust, or sign for, such a checkout.
    """
    ap2 = body.get("ap2")
    value = ap2.get("merchant_authorization") if isinstance(ap2, dict) else None
    if not isinstance(value, str) or value.count(".") != 2 or ".." not in value:
        raise WireError("merchant_authorization is missing or not a detached JWS")
    header_part, signature_part = value.split("..")
    try:
        header = json.loads(unb64(header_part))
    except (ValueError, WireError):
        raise WireError("merchant_authorization header is unreadable") from None
    if not isinstance(header, dict) or header.get("alg") != "ES256":
        raise WireError("merchant_authorization is not ES256")
    kid = header.get("kid")
    matches = [k for k in published_keys if isinstance(k, dict) and k.get("kid") == kid]
    if len(matches) != 1:
        raise WireError("merchant_authorization names no published key")
    payload = jcs({k: v for k, v in body.items() if k != "ap2"})
    signing_input = f"{header_part}.{b64url(payload)}".encode("ascii")
    if not verify_es256(matches[0], signing_input, signature_part):
        raise WireError("merchant_authorization does not verify")
    return f"{header_part}.{b64url(payload)}.{signature_part}"


# ------------------------------------------------------------------------------------ mandates


def _disclosure(value: Any, name: str | None = None) -> tuple[str, str]:
    salt = b64url(secrets.token_bytes(16))
    items = [salt, value] if name is None else [salt, name, value]
    text = b64url(json.dumps(items, separators=(",", ":")).encode())
    return text, digest(text)


def open_content(token: str) -> dict[str, Any]:
    """The disclosed content of an issued open mandate (`vct`, `exp`, `cnf`, `constraints`).

    Reads, does not verify: the platform signature is checked by the service on every use. The agent
    reads the content to learn the terms it must stay inside and to check them against its proposal.
    """
    parts = token.split("~")
    try:
        payload = json.loads(unb64(parts[0].split(".")[1]))
        wanted = {e["..."] for e in payload["delegate_payload"]}
    except (IndexError, KeyError, TypeError, ValueError, WireError):
        raise WireError("the open mandate is unreadable") from None
    for text in parts[1:]:
        if text and digest(text) in wanted:
            try:
                decoded = json.loads(unb64(text))
                content = decoded[1]
            except (ValueError, IndexError, KeyError, WireError):
                raise WireError("the open mandate is unreadable") from None
            if isinstance(content, dict):
                return content
    raise WireError("the open mandate has no readable content")


def constraint(content: dict[str, Any], kind: str) -> dict[str, Any]:
    for entry in content.get("constraints", []):
        if isinstance(entry, dict) and entry.get("type") == kind:
            return entry
    raise WireError(f"the open mandate has no {kind} constraint")


def sign_closed(
    open_token: str,
    key: Any,
    *,
    kind: str,
    checkout_jwt: str,
    extra: dict[str, Any],
    now: int,
    nonce: str | None = None,
) -> str:
    """Sign a closed mandate chained to `open_token`: `<open>~<kb jwt>~<disclosures>~`.

    `key` signs (anything with `sign(bytes) -> b64url` and `jwk`). The key binding carries `aud`, a
    fresh `nonce`, `iat` and `sd_hash` over the open serialization, so it cannot be moved to another
    open mandate or audience. `extra` holds the closed values: for a checkout mandate nothing, for a
    payment mandate the payee, amount and instrument.
    """
    if kind not in ("checkout", "payment") or not open_token.endswith("~"):
        raise WireError("bad closed mandate request")
    cj_text, cj_digest = _disclosure(checkout_jwt, "checkout_jwt")
    content: dict[str, Any] = {
        "vct": VCT_CHECKOUT_CLOSED if kind == "checkout" else VCT_PAYMENT_CLOSED,
        "_sd": [cj_digest],
        ("checkout_hash" if kind == "checkout" else "transaction_id"): digest(checkout_jwt),
        **extra,
    }
    content_text, content_digest = _disclosure(content)
    payload = {
        "delegate_payload": [{"...": content_digest}],
        "iat": now,
        "aud": AUD_CHECKOUT if kind == "checkout" else AUD_PAYMENT,
        "nonce": nonce or b64url(secrets.token_bytes(16)),
        "_sd_alg": "sha-256",
        "sd_hash": digest(open_token),
    }
    header = {"alg": "ES256", "typ": "kb+sd-jwt"}
    signing_input = (
        b64url(json.dumps(header, separators=(",", ":")).encode())
        + "."
        + b64url(json.dumps(payload, separators=(",", ":")).encode())
    )
    kb_jwt = f"{signing_input}.{key.sign(signing_input.encode('ascii'))}"
    return f"{open_token}~{kb_jwt}~{cj_text}~{content_text}~"
