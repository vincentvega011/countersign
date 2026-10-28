"""The evidence reference carried in the PayPal `custom_id` (docs/PROTOCOL.md Decision 34).

`custom_id` must say, for anyone holding the PayPal order, which evidence record justifies it, without
carrying the evidence (PayPal limits it to 255 characters and it is visible in PayPal's tools). It is
`cs1.` plus the unpadded base64url of a domain separated SHA-256 over the JCS bytes of

    {"v": 1, "checkout_hash": ..., "checkout_mandate": ..., "payment_mandate": ...}

where the two mandate members are the `sd_hash`-style digests of the closed Checkout Mandate and the
closed Payment Mandate. It is 47 characters, so nothing is truncated and the full 256 bit digest is
kept. The evidence bundle (P3) contains these three values, so it can be matched to the order and
the reference recomputed; anyone changing the checkout or either mandate changes `custom_id`.
"""

from __future__ import annotations

from countersign.canonical import b64url, canonicalize, domain_hash

EVIDENCE_DOMAIN = "cs.evidence.ref.v1"
PREFIX = "cs1."


def evidence_reference(
    *, checkout_hash: str, checkout_mandate_digest: str, payment_mandate_digest: str
) -> bytes:
    return canonicalize(
        {
            "v": 1,
            "checkout_hash": checkout_hash,
            "checkout_mandate": checkout_mandate_digest,
            "payment_mandate": payment_mandate_digest,
        }
    )


def custom_id_for(reference: bytes) -> str:
    return PREFIX + b64url(domain_hash(EVIDENCE_DOMAIN, reference))
