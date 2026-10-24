"""Building UCP responses from the canonical model.

Security reasoning. A response is built from a `Checkout` (already validated and consistent) and a
status, never from request data, so nothing a platform sent can appear in what the business
returns or later signs. The only free-form content is the messages, which are produced by
Countersign's own code (`messages.py`).

Shape (vendored `shopping/checkout.json`): required `ucp`, `id`, `line_items`, `status`,
`currency`, `totals`, `links`. `ucp` carries the version, `status: success`, the checkout
capability and an empty `payment_handlers` (required by the response schema). `links` is an empty
array: Countersign has no legal pages to link (docs/LIMITATIONS.md). `expires_at` is RFC 3339 UTC.
"""

from __future__ import annotations

from datetime import UTC, datetime, timedelta
from typing import Any

from countersign.canonical.models import Checkout
from countersign.protocols.ucp.checkout_state import Status
from countersign.protocols.ucp.profile import CHECKOUT_CAPABILITY, UCP_VERSION

_EPOCH = datetime(1970, 1, 1, tzinfo=UTC)


def rfc3339(us: int) -> str:
    """Microseconds since the Unix epoch as an RFC 3339 UTC timestamp with whole seconds."""
    moment = _EPOCH + timedelta(microseconds=us)
    return moment.strftime("%Y-%m-%dT%H:%M:%SZ")


def checkout_response(
    checkout: Checkout,
    status: Status,
    expires_us: int,
    messages: list[dict[str, Any]] | None = None,
) -> dict[str, Any]:
    """The checkout resource as returned by every operation."""
    body: dict[str, Any] = {
        "ucp": {
            "version": UCP_VERSION,
            "status": "success",
            "capabilities": {CHECKOUT_CAPABILITY: [{"version": UCP_VERSION}]},
            "payment_handlers": {},
        },
        **checkout.to_ucp(),
        "status": status.value,
        "links": [],
        "expires_at": rfc3339(expires_us),
    }
    if messages:
        body["messages"] = list(messages)
    return body
