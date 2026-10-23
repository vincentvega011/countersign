"""Hash helpers, in two families that must never be mixed up.

AP2 hashes. `checkout_hash`, `transaction_id`, `sd_hash` and the receipt `reference` are defined by
the AP2 and SD-JWT specifications as plain SHA-256 over the US-ASCII bytes of a string, written as
unpadded base64url (docs/PROTOCOL.md section 1.2.4). They carry no prefix: a verifier that prefixed
them would compute a different value than every other implementation and every worked example.

Countersign-internal hashes (decision log, evidence reference, terms hash) use `domain_hash`:
SHA-256 over a fixed ASCII domain name, a NUL byte, then the data. The domain keeps a hash made
for one purpose from being replayed as another. The domain name is restricted to
`cs.<words>.v<N>` (lowercase ASCII, no NUL), so the NUL always marks where the domain ends and no
domain can be a prefix trick on another.

Security reasoning for the AP2 inputs. The most likely mistake is hashing the wrong string, so each
function checks the shape of its input: a Checkout JWT is exactly three non-empty dot-separated
parts and contains no `~`; an SD-JWT serialization must end with the trailing `~` that `sd_hash`
covers. Non-ASCII input is rejected rather than encoded some other way.
"""

from __future__ import annotations

import base64
import hashlib
import re

_DOMAIN = re.compile(r"cs\.[a-z][a-z0-9_.]*\.v[1-9][0-9]*")


class HashInputError(ValueError):
    """The input is not in the shape the hash is defined over."""

    code = "hash_input_invalid"


def b64url(data: bytes) -> str:
    """Unpadded base64url, the encoding AP2 and SD-JWT use for digests."""
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode("ascii")


def _ascii(text: str, what: str) -> bytes:
    try:
        return text.encode("ascii")
    except UnicodeEncodeError:
        raise HashInputError(f"{what} must be US-ASCII") from None


def _ap2_digest(text: str, what: str) -> str:
    return b64url(hashlib.sha256(_ascii(text, what)).digest())


def checkout_hash(checkout_jwt: str) -> str:
    """`checkout_hash`: SHA-256 of the compact `checkout_jwt` string, base64url, no prefix."""
    parts = checkout_jwt.split(".")
    if len(parts) != 3 or not all(parts) or "~" in checkout_jwt:
        raise HashInputError("checkout_jwt must be a compact JWS: three non-empty parts")
    return _ap2_digest(checkout_jwt, "checkout_jwt")


def transaction_id(checkout_jwt: str) -> str:
    """Payment Mandate `transaction_id`: the same hash of the same string as `checkout_hash`."""
    return checkout_hash(checkout_jwt)


def sd_hash(serialization: str) -> str:
    """`sd_hash` over a full SD-JWT serialization, including its trailing `~`."""
    if not serialization.endswith("~"):
        raise HashInputError("an SD-JWT serialization must end with the trailing '~'")
    return _ap2_digest(serialization, "SD-JWT serialization")


def receipt_reference(closed_mandate: str) -> str:
    """Receipt `reference`, computed "in the same manner as the sd_hash would be".

    Which string a receipt covers when a chain is presented (the whole chain or only the last
    link) is the open question recorded in docs/PROTOCOL.md; the caller chooses the string.
    """
    return sd_hash(closed_mandate)


def domain_hash(domain: str, data: bytes) -> bytes:
    """Countersign-internal hash: SHA-256(domain ASCII || 0x00 || data). Never for AP2 values."""
    if not _DOMAIN.fullmatch(domain):
        raise HashInputError("domain must look like 'cs.name.v1'")
    return hashlib.sha256(domain.encode("ascii") + b"\x00" + data).digest()
