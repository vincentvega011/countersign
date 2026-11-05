"""A forger of properly SIGNED evidence bundles, with one controllable defect at a time.

Tampering a real bundle byte by byte breaks a signature, so it only shows that signatures are checked. The
checks that compare two signed things (an amount in the mandate with the amount in the checkout, a receipt
reference with a mandate, the audience of a key binding) can only be tested with bundles in which each
signature is valid and the signed content disagrees. This module holds throwaway keys and builds such
bundles from scratch, independent of the service: it uses `cryptography` and `hashlib` directly, and only
the verifier's own log hashing for the decision log. Every value is synthetic.
"""

from __future__ import annotations

import base64
import hashlib
import json
import secrets
from collections.abc import Callable
from dataclasses import dataclass, field
from typing import Any

from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.asymmetric.utils import decode_dss_signature

from countersign_verify import log as vlog
from countersign_verify.crypto import b64url, domain_hash, jcs

NOW = 1_800_000_000
CHECKOUT_ID = "chk_forgedforgedforgedforg"
ITEM = {"id": "hp-forged-headphones", "title": "Forged Headphones", "price": 4500}
MERCHANT = {"id": "m-forge", "name": "Forge Store", "website": "https://forge.example.test"}
GATE = (
    "G-FETCH",
    "G-STATUS",
    "G-REVERSE",
    "G-TERMS",
    "G-AMOUNT",
    "G-MANDATE",
    "G-BUDGET",
    "G-LOCK",
    "G-CHECKOUT",
)


def compact(value: Any) -> str:
    return json.dumps(value, separators=(",", ":"))


def digest(text: str) -> str:
    return b64url(hashlib.sha256(text.encode("ascii")).digest())


class Key:
    def __init__(self) -> None:
        self.private = ec.generate_private_key(ec.SECP256R1())

    @property
    def jwk(self) -> dict[str, str]:
        n = self.private.public_key().public_numbers()
        return {
            "kty": "EC",
            "crv": "P-256",
            "x": b64url(n.x.to_bytes(32, "big")),
            "y": b64url(n.y.to_bytes(32, "big")),
        }

    def sign(self, data: bytes) -> str:
        r, s = decode_dss_signature(self.private.sign(data, ec.ECDSA(hashes.SHA256())))
        return b64url(r.to_bytes(32, "big") + s.to_bytes(32, "big"))

    def jws(self, header: dict[str, Any], payload: Any, *, canonical: bool = False) -> str:
        body = jcs(payload) if canonical else compact(payload).encode()
        signing = f"{b64url(compact(header).encode())}.{b64url(body)}"
        return f"{signing}.{self.sign(signing.encode())}"


def disclosure(value: Any, name: str | None = None) -> tuple[str, str]:
    salt = b64url(secrets.token_bytes(16))
    text = b64url(compact([salt, value] if name is None else [salt, name, value]).encode())
    return text, digest(text)


@dataclass
class Defects:
    """What to get wrong. Every default builds a bundle that verifies."""

    total: int = 4500
    payment_amount: int | None = None
    transaction_id: str | None = None
    checkout_hash: str | None = None
    payee: dict[str, str] | None = None
    budget: int = 8000
    kb_aud_checkout: str = "merchant"
    kb_aud_payment: str = "credential-provider"
    kb_typ: str = "kb+sd-jwt"
    # (terms, open checkout content, open payment content), edited before the device signs
    contents_edit: Callable[[dict[str, Any], dict[str, Any], dict[str, Any]], None] | None = None
    kb_sd_hash: Callable[[str], str] | None = None
    closed_iat: int = NOW + 10
    open_exp: int = NOW + 3600
    extra_closed_disclosure: bool = False
    reference_constraint: str | None = None
    payment_sub: str | None = None
    receipt_reference_checkout: str | None = None
    receipt_reference_payment: str | None = None
    receipt_status: str = "Success"
    checkout_receipt_order: str | None = None
    payment_receipt_capture: str | None = None
    receipt_typ_checkout: str = "checkout-receipt+jwt"
    consent_edit: Callable[[dict[str, Any]], None] | None = None
    sign_consent_with: Key | None = None
    paypal_edit: Callable[[dict[str, Any]], None] | None = None
    captured_reference: str | None = None
    captured_amount: str | None = None
    skip_gate_step: str | None = None
    double_gate_step: str | None = None
    checkout_edit: Callable[[dict[str, Any]], None] | None = None
    payment_checkout_edit: Callable[[dict[str, Any]], None] | None = None
    jwt_alg: str = "ES256"
    extra: dict[str, Any] = field(default_factory=dict)


def build(d: Defects | None = None) -> dict[str, Any]:
    d = d or Defects()
    platform, merchant, agent, device = Key(), Key(), Key(), Key()
    customer = "cus_" + b64url(secrets.token_bytes(16))
    checkout = {
        "id": CHECKOUT_ID,
        "currency": "USD",
        "status": "ready_for_complete",
        "line_items": [{"id": "li_1", "item": ITEM, "quantity": 1}],
        "totals": [{"type": "subtotal", "amount": 4500}, {"type": "total", "amount": d.total}],
    }
    if d.checkout_edit:
        d.checkout_edit(checkout)
    mkid = {"alg": d.jwt_alg, "kid": "forge-merchant"}
    checkout_jwt = merchant.jws(mkid, checkout, canonical=True)

    # ---- the terms and the open mandates (what the platform issues after the device signs)
    terms = {
        "merchant": MERCHANT,
        "items": [{"id": ITEM["id"], "title": ITEM["title"], "quantity": 1}],
        "ceiling_minor": d.budget,
        "currency": "USD",
        "mandate_expires_at": d.open_exp,
        "agent_thumbprint": _thumb(agent.jwk),
    }
    checkout_content = {
        "vct": "mandate.checkout.open.1",
        "exp": d.open_exp,
        "constraints": [
            {
                "type": "checkout.line_items",
                "items": [
                    {
                        "id": "line_1",
                        "quantity": 1,
                        "acceptable_items": [{"id": ITEM["id"], "title": ITEM["title"]}],
                    }
                ],
            },
            {"type": "checkout.allowed_merchants", "allowed": [MERCHANT]},
        ],
    }
    payment_content = {
        "vct": "mandate.payment.open.1",
        "exp": d.open_exp,
        "constraints": [
            {"type": "payment.amount_range", "currency": "USD", "min": 1, "max": d.budget},
            {"type": "payment.allowed_payees", "allowed": [MERCHANT]},
            {"type": "payment.budget", "max": d.budget, "currency": "USD"},
            {"type": "payment.agent_recurrence", "frequency": "ON_DEMAND", "max_occurrences": 1},
        ],
    }
    if d.contents_edit:
        d.contents_edit(terms, checkout_content, payment_content)
    record = {
        "v": 1,
        "purpose": "countersign.consent.open-mandates.v1",
        "customer_id": customer,
        "device_thumbprint": _thumb(device.jwk),
        "challenge_id": "kch_forged",
        "challenge": "n",
        "issued_at": NOW,
        "expires_at": NOW + 300,
        "origin": "https://forge.example.test",
        "terms": terms,
        "mandate": {
            "checkout": json.loads(json.dumps(checkout_content)),
            "payment": json.loads(json.dumps(payment_content)),
        },
    }
    if d.consent_edit:
        d.consent_edit(record)
    record_text = jcs(record).decode()
    consent = {
        "record": record_text,
        "signature": (d.sign_consent_with or device).sign(record_text.encode()),
        "device_jwk": device.jwk,
        "customer_id": customer,
    }

    def issue(content: dict[str, Any], sub: str) -> str:
        full = {**content, "cnf": {"jwk": agent.jwk}, "iat": NOW}
        text, dig = disclosure(full)
        payload = {
            "iss": "https://forge.example.test",
            "sub": sub,
            "iat": NOW,
            "delegate_payload": [{"...": dig}],
            "_sd_alg": "sha-256",
        }
        jwt = platform.jws({"alg": "ES256", "typ": "dc+sd-jwt", "kid": "forge-platform"}, payload)
        return f"{jwt}~{text}~"

    open_checkout = issue(checkout_content, customer)
    payment_content = {
        **payment_content,
        "constraints": [
            {
                "type": "payment.reference",
                "conditional_transaction_id": d.reference_constraint or digest(open_checkout),
            },
            *payment_content["constraints"],
        ],
    }
    open_payment = issue(payment_content, d.payment_sub or customer)

    cj_hash = digest(checkout_jwt)
    other_jwt = checkout_jwt
    if d.payment_checkout_edit:  # a second, validly signed checkout that the Payment Mandate names
        second = json.loads(json.dumps(checkout))
        d.payment_checkout_edit(second)
        other_jwt = merchant.jws(mkid, second, canonical=True)

    def close(open_ser: str, kind: str, extra: dict[str, Any], audience: str) -> str:
        jwt_value = checkout_jwt if kind == "checkout" else other_jwt
        cj_text, cj_dig = disclosure(jwt_value, "checkout_jwt")
        name = "checkout_hash" if kind == "checkout" else "transaction_id"
        override = d.checkout_hash if kind == "checkout" else d.transaction_id
        content = {
            "vct": "mandate.checkout.1" if kind == "checkout" else "mandate.payment.1",
            "_sd": [cj_dig],
            name: override or digest(jwt_value),
            **extra,
        }
        content_text, content_dig = disclosure(content)
        payload = {
            "delegate_payload": [{"...": content_dig}],
            "iat": d.closed_iat,
            "aud": audience,
            "nonce": b64url(secrets.token_bytes(8)),
            "_sd_alg": "sha-256",
            "sd_hash": d.kb_sd_hash(open_ser) if d.kb_sd_hash else digest(open_ser),
        }
        kb = agent.jws({"alg": "ES256", "typ": d.kb_typ}, payload)
        extra_parts = [disclosure("unreferenced")[0]] if d.extra_closed_disclosure else []
        return f"{open_ser}~{kb}~{cj_text}~{content_text}~" + "".join(p + "~" for p in extra_parts)

    closed_checkout = close(open_checkout, "checkout", {}, d.kb_aud_checkout)
    closed_payment = close(
        open_payment,
        "payment",
        {
            "payee": d.payee or MERCHANT,
            "payment_amount": {"amount": d.payment_amount or d.total, "currency": "USD"},
            "payment_instrument": {"id": "w1", "type": "paypal"},
        },
        d.kb_aud_payment,
    )
    link_c, link_p = closed_checkout.split("~~", 1)[1], closed_payment.split("~~", 1)[1]

    # ---- PayPal objects, the evidence reference, receipts
    custom = "cs1." + b64url(
        domain_hash(
            "cs.evidence.ref.v1",
            jcs(
                {
                    "v": 1,
                    "checkout_hash": cj_hash,
                    "checkout_mandate": digest(link_c),
                    "payment_mandate": digest(link_p),
                }
            ),
        )
    )
    money = {"currency_code": "USD", "value": f"{d.total / 100:.2f}"}
    item_money = {"currency_code": "USD", "value": "45.00"}
    auth = {
        "id": "AUTH1",
        "status": "CAPTURED",
        "amount": money,
        "invoice_id": CHECKOUT_ID,
        "custom_id": custom,
    }
    cap = {
        "id": "CAP1",
        "status": "COMPLETED",
        "amount": money,
        "final_capture": True,
        "invoice_id": CHECKOUT_ID,
        "custom_id": custom,
    }
    order = {
        "id": "ORD1",
        "status": "COMPLETED",
        "intent": "AUTHORIZE",
        "purchase_units": [
            {
                "reference_id": "default",
                "invoice_id": CHECKOUT_ID,
                "custom_id": custom,
                "amount": {**money, "breakdown": {"item_total": dict(item_money)}},
                "items": [
                    {
                        "name": ITEM["title"],
                        "sku": ITEM["id"],
                        "quantity": "1",
                        "unit_amount": dict(item_money),
                    }
                ],
                "payee": {"merchant_id": "SYNTHETICMERCHANT"},
                "payments": {"authorizations": [auth], "captures": [cap]},
            }
        ],
    }
    paypal = {"order": [order], "authorization": [auth], "capture": [cap]}
    if d.paypal_edit:
        d.paypal_edit(paypal)
    mk = {"alg": "ES256", "kid": "forge-merchant"}
    pay_ref = d.receipt_reference_payment or digest(link_p)
    receipts = {
        "checkout": merchant.jws(
            {**mk, "typ": d.receipt_typ_checkout},
            {
                "status": d.receipt_status,
                "iss": "forge",
                "iat": NOW,
                "reference": d.receipt_reference_checkout or digest(link_c),
                "order_id": d.checkout_receipt_order or CHECKOUT_ID,
            },
            canonical=True,
        ),
        "payment": merchant.jws(
            {**mk, "typ": "payment-receipt+jwt"},
            {
                "status": d.receipt_status,
                "iss": "forge",
                "iat": NOW,
                "reference": pay_ref,
                "payment_id": CHECKOUT_ID,
                "psp_confirmation_id": d.payment_receipt_capture or "CAP1",
                "network_confirmation_id": "CAP1",
            },
            canonical=True,
        ),
    }

    # ---- the decision log
    entries: list[dict[str, Any]] = []

    def add(kind: str, payload: dict[str, Any]) -> None:
        entry = {
            "seq": len(entries) + 1,
            "ts_us": NOW * 1_000_000 + len(entries),
            "checkout_id": CHECKOUT_ID,
            "kind": kind,
            "payload": jcs(payload).decode(),
            "policy_hash": b64url(b"\x07" * 32),
            "prev_hash": entries[-1]["entry_hash"] if entries else b64url(b"\x00" * 32),
        }
        entry["entry_hash"] = b64url(vlog.entry_hash({**entry, "entry_hash": ""}))
        entries.append(entry)

    add("checkout.created", {"status": "ready_for_complete"})
    for code in GATE:
        if code != d.skip_gate_step:
            add("gate.step", {"code": code, "outcome": "pass"})
        if code == d.double_gate_step:
            add("gate.step", {"code": code, "outcome": "pass"})
    add(
        "gate.captured",
        {
            "amount": d.captured_amount or f"USD:{d.total}",
            "authorization_id": "AUTH1",
            "capture_id": "CAP1",
            "order_id": "ORD1",
            "reference": d.captured_reference or pay_ref,
        },
    )
    hashes = [vlog.entry_hash(e) for e in entries]
    proofs = [_proof(hashes, i) for i in range(len(hashes))]
    bundle = {
        "v": 1,
        "kind": "countersign.evidence",
        "capture_id": "CAP1",
        "checkout_id": CHECKOUT_ID,
        "order_id": "ORD1",
        "authorization_id": "AUTH1",
        "checkout_jwt": checkout_jwt,
        "mandates": {
            "checkout_open": open_checkout,
            "checkout_closed": closed_checkout,
            "payment_open": open_payment,
            "payment_closed": closed_payment,
        },
        "receipts": receipts,
        "consent": consent,
        "paypal": paypal,
        "gate": {"state": "captured", "custom_id": custom},
        "log": {
            "entries": entries,
            "size": len(entries),
            "root": b64url(vlog.root_of(hashes)),
            "proofs": proofs,
        },
        "keys": {"merchant": {**merchant.jwk, "kid": "forge-merchant"}, "platform": platform.jwk},
    }
    bundle.update(d.extra)
    return bundle


def _thumb(jwk: dict[str, str]) -> str:
    return b64url(hashlib.sha256(jcs({m: jwk[m] for m in ("crv", "kty", "x", "y")})).digest())


def _proof(hashes: list[bytes], index: int) -> dict[str, Any]:
    def path(lo: int, hi: int, i: int) -> list[bytes]:
        if hi - lo == 1:
            return []
        k = 1
        while k * 2 < hi - lo:
            k *= 2
        if i - lo < k:
            return [*path(lo, lo + k, i), vlog.root_of_subtree(hashes[lo + k : hi])]
        return [*path(lo + k, hi, i), vlog.root_of_subtree(hashes[lo : lo + k])]

    return {
        "v": 1,
        "index": index,
        "size": len(hashes),
        "path": [b64url(h) for h in path(0, len(hashes), index)],
    }


_ = base64
