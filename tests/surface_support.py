"""Test support for device key enrolment: a Python "browser" that makes keys and signs records.

The record is built here, independently of `countersign.trusted_surface.keys.registration_record`,
so a defect in the production builder (a dropped or renamed member) shows up as a failed signature.
"""

from __future__ import annotations

import base64
import secrets
from dataclasses import dataclass, field
from typing import Any

from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.asymmetric.utils import decode_dss_signature

from countersign.canonical.jcs import canonicalize

ORIGIN = "https://surface.example.test"
PURPOSE = "countersign.device-key.register.v1"
PURPOSE_REVOKE = "countersign.device-key.revoke.v1"
PURPOSE_CONSENT = "countersign.consent.open-mandates.v1"
BASE = "/trusted-surface/keys"


def b64(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode()


@dataclass
class Device:
    private: ec.EllipticCurvePrivateKey = field(
        default_factory=lambda: ec.generate_private_key(ec.SECP256R1())
    )

    @property
    def jwk(self) -> dict[str, str]:
        n = self.private.public_key().public_numbers()
        return {
            "kty": "EC",
            "crv": "P-256",
            "x": b64(n.x.to_bytes(32, "big")),
            "y": b64(n.y.to_bytes(32, "big")),
        }

    @property
    def thumbprint(self) -> str:
        import hashlib

        j = self.jwk
        text = canonicalize({"crv": j["crv"], "kty": j["kty"], "x": j["x"], "y": j["y"]})
        return b64(hashlib.sha256(text).digest())

    def sign(self, record: bytes) -> str:
        der = self.private.sign(record, ec.ECDSA(hashes.SHA256()))
        r, s = decode_dss_signature(der)
        return b64(r.to_bytes(32, "big") + s.to_bytes(32, "big"))


def record_for(
    issued: dict[str, Any],
    thumbprint: str,
    *,
    customer_id: str | None = None,
    origin: str = ORIGIN,
    override: dict[str, Any] | None = None,
) -> bytes:
    fields: dict[str, Any] = {
        "v": 1,
        "purpose": PURPOSE,
        "challenge_id": issued["challenge_id"],
        "challenge": issued["nonce"],
        "thumbprint": thumbprint,
        "customer_id": customer_id,
        "origin": origin,
    }
    fields.update(override or {})
    return canonicalize(fields)


def body_for(
    device: Device,
    challenge: dict[str, Any],
    *,
    customer_id: str | None = None,
    authorizer: Device | None = None,
    signer: Device | None = None,
    origin: str = ORIGIN,
    sign_origin: str | None = None,
    **override: Any,
) -> dict[str, Any]:
    """A registration body signed by `signer` (default: the new key) over the matching record."""
    record = record_for(
        challenge, device.thumbprint, customer_id=customer_id, origin=sign_origin or origin
    )
    body: dict[str, Any] = {
        "jwk": device.jwk,
        "challenge_id": challenge["challenge_id"],
        "customer_id": customer_id,
        "origin": origin,
        "signature": (signer or device).sign(record),
    }
    if authorizer is not None:
        body["authorizer"] = {
            "thumbprint": authorizer.thumbprint,
            "signature": authorizer.sign(record),
        }
    body.update(override)
    return body


def fresh_id() -> str:
    return secrets.token_urlsafe(16)


def revoke_record_for(
    issued: dict[str, Any],
    *,
    customer_id: str,
    target: str,
    signer: str,
    origin: str = ORIGIN,
    override: dict[str, Any] | None = None,
) -> bytes:
    fields: dict[str, Any] = {
        "v": 1,
        "purpose": PURPOSE_REVOKE,
        "challenge_id": issued["challenge_id"],
        "challenge": issued["nonce"],
        "customer_id": customer_id,
        "target_thumbprint": target,
        "signer_thumbprint": signer,
        "origin": origin,
    }
    fields.update(override or {})
    return canonicalize(fields)


def revoke_body_for(
    signer: Device,
    issued: dict[str, Any],
    *,
    customer_id: str,
    target: Device | str | None = None,
    sign_with: Device | None = None,
    origin: str = ORIGIN,
    override: dict[str, Any] | None = None,
    **body_override: Any,
) -> dict[str, Any]:
    """A revocation of `target` (default: the signer itself) signed by `signer`."""
    victim = signer.thumbprint if target is None else getattr(target, "thumbprint", target)
    record = revoke_record_for(
        issued, customer_id=customer_id, target=victim, signer=signer.thumbprint, origin=origin,
        override=override,
    )  # fmt: skip
    body: dict[str, Any] = {
        "challenge_id": issued["challenge_id"],
        "customer_id": customer_id,
        "target": victim,
        "signer": signer.thumbprint,
        "origin": origin,
        "signature": (sign_with or signer).sign(record),
    }
    body.update(body_override)
    return body


# ------------------------------------------------------------------------------------ consent


def agent_thumbprint(jwk: dict[str, Any]) -> str:
    import hashlib

    text = canonicalize({"crv": jwk["crv"], "kty": jwk["kty"], "x": jwk["x"], "y": jwk["y"]})
    return b64(hashlib.sha256(text).digest())


def terms_for(
    agent_jwk: dict[str, Any],
    *,
    items: list[dict[str, Any]] | None = None,
    ceiling: int = 8000,
    mandate_exp: int,
    merchant: dict[str, str] | None = None,
) -> dict[str, Any]:
    from countersign.catalog.catalog import load_catalog

    first = load_catalog().items[0]
    return {
        "merchant": merchant
        or {"id": "merchant-1", "name": "Countersign demo store", "website": ORIGIN},
        "items": items or [{"id": first.id, "title": first.title, "quantity": 1}],
        "ceiling_minor": ceiling,
        "currency": "USD",
        "mandate_expires_at": mandate_exp,
        "agent_thumbprint": agent_thumbprint(agent_jwk),
    }


def mandate_twin(terms: dict[str, Any]) -> dict[str, Any]:
    """The contents the platform must rebuild for `terms`, written independently of the backend."""
    lines = [
        {
            "id": f"line_{n}",
            "acceptable_items": [{"id": i["id"], "title": i["title"]}],
            "quantity": i["quantity"],
        }
        for n, i in enumerate(terms["items"], start=1)
    ]
    merchant = dict(terms["merchant"])
    cap, cur, exp = terms["ceiling_minor"], terms["currency"], terms["mandate_expires_at"]
    return {
        "checkout": {
            "vct": "mandate.checkout.open.1",
            "exp": exp,
            "constraints": [
                {"type": "checkout.line_items", "items": lines},
                {"type": "checkout.allowed_merchants", "allowed": [merchant]},
            ],
        },
        "payment": {
            "vct": "mandate.payment.open.1",
            "exp": exp,
            "constraints": [
                {"type": "payment.amount_range", "currency": cur, "min": 1, "max": cap},
                {"type": "payment.allowed_payees", "allowed": [dict(merchant)]},
                {"type": "payment.budget", "max": cap, "currency": cur},
                {
                    "type": "payment.agent_recurrence",
                    "frequency": "ON_DEMAND",
                    "max_occurrences": 1,
                },
            ],
        },
    }


def consent_record_for(
    device: Device,
    customer_id: str,
    issued: dict[str, Any],
    terms: dict[str, Any],
    *,
    origin: str = ORIGIN,
    lifetime: int = 300,
    mandate: dict[str, Any] | None = None,
    override: dict[str, Any] | None = None,
) -> dict[str, Any]:
    start = int(issued["issued_at"])
    record: dict[str, Any] = {
        "v": 1,
        "purpose": PURPOSE_CONSENT,
        "customer_id": customer_id,
        "device_thumbprint": device.thumbprint,
        "challenge_id": issued["challenge_id"],
        "challenge": issued["nonce"],
        "issued_at": start,
        "expires_at": start + lifetime,
        "origin": origin,
        "terms": terms,
        "mandate": mandate if mandate is not None else mandate_twin(terms),
    }
    record.update(override or {})
    return record


def consent_body(
    device: Device,
    record: dict[str, Any],
    agent_jwk: dict[str, Any],
    *,
    sign_with: Device | None = None,
) -> dict[str, Any]:
    return {
        "record": record,
        "signature": (sign_with or device).sign(canonicalize(record)),
        "agent_jwk": agent_jwk,
    }
