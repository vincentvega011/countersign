"""Deterministic `PayPal-Request-Id` values.

A Request-Id is derived from the checkout id and the operation (and, where one checkout can have
several distinct operations of a kind, the facts that distinguish them), so a retry of the same
operation sends the same id and PayPal replays the original result instead of repeating it
(docs/PROTOCOL.md section 4.2: create order, authorize, capture, refund and void all replayed).

Form: `cs1.<operation>.<digest>` where `digest` is the unpadded base64url of
`domain_hash("cs.paypal.request.v1", fields)` and `fields` is each of the checkout id, the operation
and the extra parts as a 4 byte big-endian length followed by its UTF-8 bytes. Length prefixes mean
no two different field lists encode alike. The result is at most 4 + 12 + 1 + 43 = 60 characters,
inside PayPal's 108; the client checks every Request-Id against the limit again before sending.
"""

from __future__ import annotations

import struct
from enum import StrEnum

from countersign.canonical.hashing import b64url, domain_hash

DOMAIN = "cs.paypal.request.v1"
PREFIX = "cs1"


class Operation(StrEnum):
    CREATE_ORDER = "create_order"
    AUTHORIZE = "authorize"
    CAPTURE = "capture"
    VOID = "void"
    REFUND = "refund"


def derive_request_id(checkout_id: str, operation: Operation, *parts: str) -> str:
    """The Request-Id for `operation` on `checkout_id`, with optional distinguishing `parts`."""
    if not isinstance(operation, Operation):
        raise TypeError("operation must be an Operation")
    fields = [checkout_id, operation.value, *parts]
    if not all(isinstance(f, str) and f for f in fields[:2]) or not all(
        isinstance(f, str) for f in fields
    ):
        raise ValueError("the checkout id and every part must be strings, the id non-empty")
    data = b"".join(struct.pack(">I", len(b)) + b for b in (f.encode("utf-8") for f in fields))
    digest = b64url(domain_hash(DOMAIN, data))
    return f"{PREFIX}.{operation.value}.{digest}"


def create_order_request_id(checkout_id: str, terms_hash: bytes) -> str:
    """The Request-Id for creating the order of `checkout_id` with the terms hashed as `terms_hash`.

    PayPal replays the first response for a repeated Request-Id even when the body differs
    (docs/PROTOCOL.md section 4.2), so an id from the checkout id alone would hand back a stale order
    after the checkout is re-priced. Including the canonical terms hash makes a changed checkout a
    different request, and an unchanged one the same request.
    """
    if not isinstance(terms_hash, bytes) or len(terms_hash) != 32:
        raise ValueError("the terms hash must be 32 bytes")
    return derive_request_id(checkout_id, Operation.CREATE_ORDER, b64url(terms_hash))
