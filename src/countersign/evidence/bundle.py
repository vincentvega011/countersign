"""Assemble the evidence bundle for one captured checkout (docs/PROTOCOL.md Decision 104).

Security reasoning. The bundle is what a merchant hands over in a dispute, and a stranger checks it with
`countersign_verify` without trusting the service. So nothing here is computed from a claim: every part
is read from a row that was written before the capture was answered (the mandates the Credential
Provider verified, the consent record the device key signed, the receipts the service signed, the
sanitized PayPal objects it read, the decision log entries of the checkout), and the verifier recomputes
every relation between them. The bundle holds no private key, no header and no PayPal token.
"""

from __future__ import annotations

import base64
import json
from typing import Any

from sqlalchemy import Connection, select

from countersign.canonical import b64url, canonicalize
from countersign.ledger import store as ledger_store
from countersign.ledger.merkle import inclusion_proof, merkle_root
from countersign.tables import (
    attempt_mandates,
    consent_records,
    payment_attempts,
    paypal_observations,
)

VERSION = 1
KIND = "countersign.evidence"
MAX_OBSERVATIONS = 20


class EvidenceUnavailable(Exception):
    """The checkout has no captured payment, or a part of its evidence is missing."""


def _unb64(text: str) -> bytes:
    return base64.urlsafe_b64decode(text + "=" * (-len(text) % 4))


def split_open(chain: str) -> str:
    """The open mandate (with its trailing `~`) at the start of a chained presentation."""
    head, sep, _ = chain.partition("~~")
    if not sep:
        raise EvidenceUnavailable("the presented mandate is not a chain")
    return head + "~"


def embedded_checkout_jwt(closed_chain: str) -> str:
    """The `checkout_jwt` disclosed inside the closed Checkout Mandate."""
    for part in closed_chain.split("~~", 1)[1].split("~"):
        if not part:
            continue
        try:
            decoded = json.loads(_unb64(part))
        except ValueError:
            continue
        if isinstance(decoded, list) and len(decoded) == 3 and decoded[1] == "checkout_jwt":
            return str(decoded[2])
    raise EvidenceUnavailable("the closed Checkout Mandate discloses no checkout_jwt")


def _observed(conn: Connection, object_id: str) -> list[dict[str, Any]]:
    rows = conn.execute(
        select(paypal_observations.c.body)
        .where(paypal_observations.c.object_id == object_id)
        .order_by(paypal_observations.c.seq)
    ).all()
    bodies: list[dict[str, Any]] = []
    for row in rows:
        body = json.loads(row.body)
        if not bodies or bodies[-1] != body:
            bodies.append(body)
    return bodies[-MAX_OBSERVATIONS:]


def assemble(
    conn: Connection,
    checkout_id: str,
    *,
    receipts: dict[str, str],
    merchant_jwk: dict[str, Any],
    platform_jwk: dict[str, Any],
) -> dict[str, Any]:
    attempt = conn.execute(
        select(payment_attempts).where(payment_attempts.c.checkout_id == checkout_id)
    ).first()
    if attempt is None or attempt.state != "captured" or not attempt.capture_id:
        raise EvidenceUnavailable("the checkout has no captured payment")
    tokens = conn.execute(
        select(attempt_mandates).where(attempt_mandates.c.checkout_id == checkout_id)
    ).first()
    if tokens is None:
        raise EvidenceUnavailable("the presented mandates were not kept")
    closed_checkout, closed_payment = str(tokens.checkout_mandate), str(tokens.payment_token)
    open_checkout, open_payment = split_open(closed_checkout), split_open(closed_payment)
    consent = conn.execute(
        select(consent_records).where(consent_records.c.checkout_mandate == open_checkout)
    ).first()
    if consent is None:
        raise EvidenceUnavailable("no device consent record backs the open mandate")
    if set(receipts) != {"checkout_receipt", "payment_receipt"}:
        raise EvidenceUnavailable("both receipts are needed")
    entries = ledger_store.entries_for_checkout(conn, checkout_id)
    hashes = [e.entry_hash for e in entries]
    return {
        "v": VERSION,
        "kind": KIND,
        "capture_id": str(attempt.capture_id),
        "checkout_id": checkout_id,
        "order_id": str(attempt.order_id),
        "authorization_id": str(attempt.authorization_id),
        "checkout_jwt": embedded_checkout_jwt(closed_checkout),
        "mandates": {
            "checkout_open": open_checkout,
            "checkout_closed": closed_checkout,
            "payment_open": open_payment,
            "payment_closed": closed_payment,
        },
        "receipts": {
            "checkout": receipts["checkout_receipt"],
            "payment": receipts["payment_receipt"],
        },
        "consent": {
            "record": str(consent.record),
            "signature": str(consent.signature),
            "device_jwk": json.loads(consent.device_jwk),
            "customer_id": str(consent.customer_id),
        },
        "paypal": {
            "order": _observed(conn, str(attempt.order_id)),
            "authorization": _observed(conn, str(attempt.authorization_id)),
            "capture": _observed(conn, str(attempt.capture_id)),
        },
        "gate": {"state": str(attempt.state), "custom_id": str(attempt.custom_id)},
        "log": {
            "entries": [
                {
                    "seq": e.seq,
                    "ts_us": e.ts_us,
                    "checkout_id": e.checkout_id,
                    "kind": e.kind,
                    "payload": e.payload.decode(),
                    "policy_hash": b64url(e.policy_hash),
                    "prev_hash": b64url(e.prev_hash),
                    "entry_hash": b64url(e.entry_hash),
                }
                for e in entries
            ],
            "size": len(entries),
            "root": b64url(merkle_root(hashes)),
            "proofs": [inclusion_proof(hashes, i).to_dict() for i in range(len(entries))],
        },
        "keys": {"merchant": merchant_jwk, "platform": platform_jwk},
    }


def serialize(bundle: dict[str, Any]) -> str:
    return canonicalize(bundle).decode()
