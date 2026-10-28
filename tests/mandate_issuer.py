"""Test-only issuer of AP2 mandate chains, valid and deliberately invalid (never imported from src/).

It builds `<open SD-JWT>~~<KB-SD-JWT>~<disclosures>~` in the shape of the worked examples in
spec/vendor/ap2/docs (docs/PROTOCOL.md 1.2.3): the content of every link sits in a disclosed
`delegate_payload` element, the key binding carries `iat`, `aud`, `nonce` and `sd_hash`.

It deliberately shares no code with src/countersign/mandates: JWS signing uses `cryptography`
directly, digests use `hashlib`, so a mistake in the verifier is not mirrored here.

Valid output is the default. Each keyword of `issue` introduces one defect (or one legitimate
variation), so a test names exactly what is wrong with a credential.
"""

from __future__ import annotations

import hashlib
import hmac
import json
import secrets
from collections.abc import Callable
from dataclasses import dataclass, field
from typing import Any

from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.asymmetric.utils import decode_dss_signature
from joserfc.jwk import ECKey

NOW = 1_800_000_000
OPEN_VCT = {"checkout": "mandate.checkout.open.1", "payment": "mandate.payment.open.1"}
CLOSED_VCT = {"checkout": "mandate.checkout.1", "payment": "mandate.payment.1"}


def b64e(data: bytes) -> str:
    import base64

    return base64.urlsafe_b64encode(data).rstrip(b"=").decode()


def digest(text: str) -> str:
    return b64e(hashlib.sha256(text.encode("ascii")).digest())


def compact_json(value: Any) -> str:
    return json.dumps(value, separators=(",", ":"))


def sign_jwt(
    header: dict[str, Any] | str,
    payload: dict[str, Any] | str,
    key: ECKey | None,
    *,
    alg: str = "ES256",
    hmac_secret: bytes = b"",
) -> str:
    """Sign arbitrary header and payload text. `alg` picks the signing method, not the header."""
    header_text = header if isinstance(header, str) else compact_json(header)
    payload_text = payload if isinstance(payload, str) else compact_json(payload)
    signing_input = f"{b64e(header_text.encode())}.{b64e(payload_text.encode())}"
    if alg == "none":
        return signing_input + "."
    if alg == "HS256":
        mac = hmac.new(hmac_secret, signing_input.encode(), hashlib.sha256).digest()
        return f"{signing_input}.{b64e(mac)}"
    assert key is not None
    der = key.private_key.sign(signing_input.encode(), ec.ECDSA(hashes.SHA256()))
    r, s = decode_dss_signature(der)
    return f"{signing_input}.{b64e(r.to_bytes(32) + s.to_bytes(32))}"


def disclosure(value: Any, name: str | None = None, salt: str | None = None) -> tuple[str, str]:
    """Return (disclosure text, its digest). Array element if `name` is None."""
    salt = salt or b64e(secrets.token_bytes(16))
    items = [salt, value] if name is None else [salt, name, value]
    text = b64e(compact_json(items).encode())
    return text, digest(text)


@dataclass
class Keys:
    issuer: ECKey = field(default_factory=lambda: ECKey.generate_key("P-256"))
    agents: list[ECKey] = field(
        default_factory=lambda: [ECKey.generate_key("P-256") for _ in range(3)]
    )
    merchant: ECKey = field(default_factory=lambda: ECKey.generate_key("P-256"))
    stranger: ECKey = field(default_factory=lambda: ECKey.generate_key("P-256"))

    @property
    def agent(self) -> ECKey:
        return self.agents[0]


def public_jwk(key: ECKey) -> dict[str, Any]:
    return dict(key.as_dict(private=False))


@dataclass
class Issued:
    token: str
    keys: Keys
    open_token: str  # the first link as a standalone SD-JWT, with its trailing '~'
    audience: str
    nonce: str
    kind: str
    now: int


def checkout_jwt(keys: Keys) -> str:
    checkout = {"id": "chk_1", "currency": "USD", "totals": [{"type": "total", "amount": 7900}]}
    return sign_jwt({"alg": "ES256", "kid": "merchant-key-1"}, checkout, keys.merchant)


def issue(
    kind: str = "checkout",
    *,
    keys: Keys | None = None,
    now: int = NOW,
    hops: int = 2,
    audience: str = "merchant",
    nonce: str = "nonce-0001",
    # link 0 (open)
    open_vct: str | None = None,
    omit_open_vct: bool = False,
    open_exp: float | bool | str | None = NOW + 3600,
    open_nbf: int | None = None,
    open_iat: int | None = None,
    cnf: dict[str, Any] | None | str = "default",
    issuer_typ: str = "dc+sd-jwt",
    issuer_alg_header: str = "ES256",
    issuer_sign_alg: str = "ES256",
    issuer_signer: ECKey | None = None,
    issuer_header: str | None = None,
    issuer_header_extra: dict[str, Any] | None = None,
    open_payload_text: str | None = None,
    edit_open_payload: Callable[[dict[str, Any]], None] | None = None,
    edit_open_content: Callable[[dict[str, Any]], None] | None = None,
    extra_open_disclosures: int = 0,
    plaintext_delegate: bool = False,
    two_delegate_elements: bool = False,
    duplicate_open_disclosure: bool = False,
    # key binding link(s)
    closed_vct: str | None = None,
    omit_closed_vct: bool = False,
    kb_typ: str = "kb+sd-jwt",
    kb_alg_header: str = "ES256",
    kb_sign_alg: str = "ES256",
    kb_signer: ECKey | None = None,
    kb_header_extra: dict[str, Any] | None = None,
    kb_aud: str | None = None,
    kb_nonce: str | None = None,
    omit_aud: bool = False,
    omit_nonce: bool = False,
    omit_iat: bool = False,
    kb_iat: int | None = None,
    sd_hash_value: str | None = None,
    sd_hash_over: Callable[[str], str] | None = None,
    omit_sd_hash: bool = False,
    issuer_jwt_hash_only: bool = False,
    closed_exp: int | None = None,
    closed_nbf: int | None = None,
    edit_kb_payload: Callable[[dict[str, Any]], None] | None = None,
    edit_kb_content: Callable[[dict[str, Any]], None] | None = None,
    extra_kb_disclosures: int = 0,
    kb_payload_text: str | None = None,
    kb_disclosure_text: str | None = None,
    checkout_jwt_value: str | None = None,
    checkout_hash_value: str | None = None,
    omit_checkout_jwt: bool = False,
    reuse_open_token: str | None = None,
) -> Issued:
    keys = keys or Keys()
    cj = checkout_jwt_value or checkout_jwt(keys)

    # ----- link 0: the open mandate, signed by the issuer (the platform) -----
    item_disc, d_item = disclosure({"id": "sku-headphones", "title": "Over-ear headphones"})
    open_disclosures = [item_disc]
    constraints: list[dict[str, Any]] = [
        {
            "type": "checkout.line_items" if kind == "checkout" else "payment.reference",
            "items": [{"id": "line_1", "acceptable_items": [{"...": d_item}], "quantity": 1}],
        }
    ]
    open_content: dict[str, Any] = {
        "vct": OPEN_VCT[kind] if open_vct is None else open_vct,
        "constraints": constraints,
    }
    if omit_open_vct:
        del open_content["vct"]
    if cnf == "default":
        open_content["cnf"] = {"jwk": public_jwk(keys.agents[0])}
    elif cnf is not None:
        open_content["cnf"] = cnf
    if open_iat is not None:
        open_content["iat"] = open_iat
    else:
        open_content["iat"] = now
    if open_exp is not None:
        open_content["exp"] = open_exp
    if open_nbf is not None:
        open_content["nbf"] = open_nbf
    if edit_open_content:
        edit_open_content(open_content)
    if d_item not in compact_json(open_content):  # edited constraints no longer use the item
        open_disclosures.remove(item_disc)
    open_disc, d_open = disclosure(open_content)
    open_disclosures.append(open_disc)
    delegate: list[Any] = [{"...": d_open}]
    if plaintext_delegate:
        delegate = [dict(open_content)]
        open_disclosures.clear()
    if two_delegate_elements:
        second, d_second = disclosure({"vct": OPEN_VCT[kind], "exp": now + 10})
        open_disclosures.append(second)
        delegate.append({"...": d_second})
    for _ in range(extra_open_disclosures):
        extra, _ = disclosure("unreferenced")
        open_disclosures.append(extra)
    if duplicate_open_disclosure:
        open_disclosures.append(open_disclosures[0])
    open_payload: dict[str, Any] = {
        "iss": "https://platform.example",
        "delegate_payload": delegate,
        "_sd_alg": "sha-256",
    }
    if edit_open_payload:
        edit_open_payload(open_payload)
    open_header: dict[str, Any] = {"alg": issuer_alg_header, "typ": issuer_typ, "kid": "platform-1"}
    open_header.update(issuer_header_extra or {})
    open_jwt = sign_jwt(
        issuer_header or open_header,
        open_payload_text or open_payload,
        issuer_signer or keys.issuer,
        alg=issuer_sign_alg,
        hmac_secret=compact_json(public_jwk(keys.issuer)).encode(),
    )
    previous_serialization = "~".join([open_jwt, *open_disclosures]) + "~"
    if reuse_open_token is not None:  # a second closed mandate under an existing open mandate
        previous_serialization = reuse_open_token
    open_token = previous_serialization
    token = previous_serialization

    # ----- links 1..hops-1: key bindings, each signed by the previous link's cnf key -----
    for hop in range(1, hops):
        final = hop == hops - 1
        signer = keys.agents[hop - 1]
        content: dict[str, Any]
        if final:
            content = {"vct": CLOSED_VCT[kind] if closed_vct is None else closed_vct}
            if omit_closed_vct:
                del content["vct"]
            kb_disclosures = []
            if not omit_checkout_jwt:
                cj_disc, d_cj = disclosure(cj, "checkout_jwt")
                kb_disclosures = [cj_disc]
                content["_sd"] = [d_cj]
            hash_name = "checkout_hash" if kind == "checkout" else "transaction_id"
            content[hash_name] = checkout_hash_value or digest(cj)
            if closed_exp is not None:
                content["exp"] = closed_exp
            if closed_nbf is not None:
                content["nbf"] = closed_nbf
        else:
            content = {
                "vct": OPEN_VCT[kind],
                "cnf": {"jwk": public_jwk(keys.agents[hop])},
                "iat": now,
                "exp": now + 3000,
            }
            kb_disclosures = []
        if edit_kb_content and final:
            edit_kb_content(content)
        closed_disc, d_closed = disclosure(content)
        kb_disclosures.append(closed_disc)
        for _ in range(extra_kb_disclosures if final else 0):
            extra, _ = disclosure("unreferenced")
            kb_disclosures.append(extra)
        if kb_disclosure_text is not None and final:
            kb_disclosures[-1] = kb_disclosure_text
        payload: dict[str, Any] = {
            "delegate_payload": [{"...": d_closed}],
            "iat": kb_iat if kb_iat is not None and final else now,
            "aud": (kb_aud or audience) if final else "next-hop",
            "nonce": (kb_nonce or nonce) if final else f"hop-{hop}",
            "_sd_alg": "sha-256",
        }
        hash_input = (
            sd_hash_over(previous_serialization)
            if sd_hash_over and final
            else previous_serialization
        )
        if omit_sd_hash and final:
            pass
        elif issuer_jwt_hash_only and final:
            payload["issuer_jwt_hash"] = digest(previous_serialization.split("~")[0])
        else:
            payload["sd_hash"] = sd_hash_value if sd_hash_value and final else digest(hash_input)
        if omit_aud and final:
            del payload["aud"]
        if omit_nonce and final:
            del payload["nonce"]
        if omit_iat and final:
            del payload["iat"]
        if edit_kb_payload and final:
            edit_kb_payload(payload)
        header: dict[str, Any] = {
            "alg": kb_alg_header if final else "ES256",
            "typ": kb_typ if final else "kb-sd-jwt+kb",
        }
        if final:
            header.update(kb_header_extra or {})
        kb_jwt = sign_jwt(
            header,
            kb_payload_text if kb_payload_text and final else payload,
            (kb_signer or signer) if final else signer,
            alg=kb_sign_alg if final else "ES256",
            hmac_secret=compact_json(public_jwk(keys.agents[hop - 1])).encode(),
        )
        link = "~".join([kb_jwt, *kb_disclosures]) + "~"
        token = f"{token}~{link}"
        previous_serialization = link
    return Issued(token, keys, open_token, audience, nonce, kind, now)


def issue_human_present(
    keys: Keys,
    *,
    checkout_jwt_value: str,
    now: int = NOW,
    exp: int | None = NOW + 600,
    signer: ECKey | None = None,
    checkout_hash_value: str | None = None,
) -> str:
    """A closed Checkout Mandate signed directly by the platform key (Human Present mode)."""
    cj_disc, d_cj = disclosure(checkout_jwt_value, "checkout_jwt")
    content: dict[str, Any] = {
        "_sd": [d_cj],
        "vct": CLOSED_VCT["checkout"],
        "checkout_hash": checkout_hash_value or digest(checkout_jwt_value),
        "iat": now,
    }
    if exp is not None:
        content["exp"] = exp
    content_disc, d_content = disclosure(content)
    jwt = sign_jwt(
        {"alg": "ES256", "typ": "dc+sd-jwt", "kid": "platform-1"},
        {"iss": "https://platform.example", "delegate_payload": [{"...": d_content}]},
        signer or keys.issuer,
    )
    return f"{jwt}~{cj_disc}~{content_disc}~"
