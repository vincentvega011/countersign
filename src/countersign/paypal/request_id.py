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
from collections.abc import Mapping
from enum import StrEnum
from typing import Any

from countersign.canonical.hashing import b64url, domain_hash
from countersign.canonical.jcs import canonicalize
from countersign.canonical.money import Money

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


ORDER_REQUEST_DOMAIN = "cs.paypal.order_request.v1"


def order_request_hash(body: Mapping[str, Any]) -> bytes:
    """Domain separated SHA-256 over the JCS bytes of the create-order body that is sent."""
    return domain_hash(ORDER_REQUEST_DOMAIN, canonicalize(body))


def create_order_request_id(checkout_id: str, body: Mapping[str, Any]) -> str:
    """The Request-Id for creating an order of `checkout_id` with exactly this request `body`.

    PayPal replays the first response for a repeated Request-Id even when the body differs
    (docs/PROTOCOL.md section 4.2), so an id from the checkout id alone would hand back a stale order
    after the checkout is re-priced. The id covers the hash of the body that is actually sent, so a
    changed request is a different request and an identical one is the same request. The caller
    cannot supply the hash: it is derived here, from the bytes that go out.
    """
    return derive_request_id(checkout_id, Operation.CREATE_ORDER, b64url(order_request_hash(body)))


def authorize_request_id(checkout_id: str, order_id: str) -> str:
    """The Request-Id for authorizing `order_id` of `checkout_id`.

    A checkout can have more than one order over its life (a re-priced checkout creates a new one), and
    PayPal replays the first result for a repeated id, so the id names the order it applies to. The
    order id fixes the terms: the order was created from a request whose hash is in its own id.
    """
    return derive_request_id(checkout_id, Operation.AUTHORIZE, order_id)


def capture_request_id(
    checkout_id: str, authorization_id: str, total: Money, invoice_id: str, custom_id: str
) -> str:
    """The Request-Id for capturing `authorization_id` for exactly these approved terms.

    It names the authorization and the approved total, `invoice_id` and `custom_id`, so a capture of
    another authorization, or for other terms, never replays this one.
    """
    return derive_request_id(
        checkout_id,
        Operation.CAPTURE,
        authorization_id,
        f"{total.currency}:{total.to_paypal()}",
        invoice_id,
        custom_id,
    )


def void_request_id(checkout_id: str, authorization_id: str) -> str:
    """The Request-Id for voiding `authorization_id` of `checkout_id`.

    A void has no body and no terms, so the authorization id is all there is to name. A second
    authorization of the same checkout, after the first was voided, gets its own id.
    """
    return derive_request_id(checkout_id, Operation.VOID, authorization_id)
