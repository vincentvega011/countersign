"""The customer a mandate was issued for: the `sub` claim of the issuer-signed JWT (Decision 47).

Security reasoning. The issuer-signed JWT of link 0 is signed by the one trusted platform provider
(docs/PROTOCOL.md Decision 5), and `verify_chain` has already checked that signature, so a `sub` in it
is an assertion by the provider, not by the agent. The agent holds the mandate but cannot change the
signed payload, and a top-level claim is never selectively disclosed away from the verifier. The
value is returned only if it is a short printable string; anything else counts as "no customer id",
which the lock treats as unknown and fails closed (INV-10), never as unlocked.
"""

from __future__ import annotations

from collections.abc import Mapping

from countersign.canonical import JsonValue

MAX_CUSTOMER_ID = 128


def customer_id_of(claims: Mapping[str, JsonValue]) -> str | None:
    value = claims.get("sub")
    if not isinstance(value, str) or not value or len(value) > MAX_CUSTOMER_ID:
        return None
    if not value.isprintable() or value != value.strip():
        return None
    return value
