"""My agent activity: a device-proven read session and a separately signed revoke (Decisions 91, 92).

Security reasoning. Reading a customer's open mandates needs more than a customer id, which is not a
secret. The page proves possession of a registered, non-revoked device key over a server challenge
(purpose `activity_read`) and receives an opaque session token. Only the SHA-256 of the token is stored
(insert only, so there is nothing to steal from the table and nothing to update); the session lives 5
minutes from `created_us` (computed, never updated); it names exactly one customer, so it cannot list
another customer's mandates. Every use re-checks that the device key is still not revoked.

Revoking is not authorized by that token. It needs its own device-key signature over a record with a
distinct purpose that names the customer, the device key, the open mandate identity, the origin and a
fresh single use challenge (purpose `revoke_open_mandate`). A bearer token alone cannot revoke. The
open mandate must belong to the signing customer (another customer's mandate is `open_mandate_unknown`,
the same answer as a nonexistent one). The revocation itself runs under the open mandate's row lock
(`openmandates.revoke_in`): `in_flight` while a capture has started, `already_used` after one, and an
idempotent success for an already revoked mandate. Deterministic (INV-1); every refusal is logged
before the answer (INV-12).
"""

from __future__ import annotations

import hashlib
import re
import secrets
from dataclasses import dataclass
from typing import TYPE_CHECKING, Any

from sqlalchemy import select

from countersign.canonical.jcs import JcsError, canonicalize
from countersign.openmandates import (
    ALREADY_USED,
    IN_FLIGHT,
    MandateView,
    list_for_customer,
    revoke_in,
)
from countersign.tables import activity_sessions, open_mandates
from countersign.trusted_surface.keys import KeyRefused, validate_public_jwk, verify_signature

if TYPE_CHECKING:
    from countersign.trusted_surface.service import TrustedSurface

PURPOSE_READ = "countersign.activity.read.v1"
PURPOSE_REVOKE = "countersign.open-mandate.revoke.v1"
CHALLENGE_PURPOSE_READ = "activity_read"
CHALLENGE_PURPOSE_REVOKE = "revoke_open_mandate"
SESSION_TTL_US = 5 * 60 * 1_000_000
TOKEN_PREFIX = "ats_"
TOKEN = re.compile(r"ats_[A-Za-z0-9_-]{43}")
CUSTOMER = re.compile(r"cus_[A-Za-z0-9_-]{22}")
THUMBPRINT = re.compile(r"[A-Za-z0-9_-]{43}")
IDENTITY = re.compile(r"[A-Za-z0-9_-]{43}")
LOG_KIND_SESSION = "ts.activity.session"
LOG_KIND_SESSION_REFUSED = "ts.activity.refused"
LOG_KIND_READ_REFUSED = "ts.activity.read.refused"
LOG_KIND_REVOKED = "ts.mandate.revoked"
LOG_KIND_REVOKE_REFUSED = "ts.mandate.revoke.refused"


@dataclass(frozen=True)
class Session:
    token: str
    customer_id: str
    expires_us: int


@dataclass(frozen=True)
class Activity:
    customer_id: str
    now_s: int
    mandates: list[MandateView]


@dataclass(frozen=True)
class MandateRevoked:
    open_mandate: str
    new_revocation: bool


def read_record(
    *, challenge_id: str, nonce: str, customer_id: str, device_thumbprint: str, origin: str
) -> bytes:
    try:
        return canonicalize(
            {
                "v": 1, "purpose": PURPOSE_READ, "challenge_id": challenge_id,
                "challenge": nonce, "customer_id": customer_id,
                "device_thumbprint": device_thumbprint, "origin": origin,
            }
        )  # fmt: skip
    except JcsError:
        raise KeyRefused("proof_invalid") from None


def revoke_record(
    *,
    challenge_id: str,
    nonce: str,
    customer_id: str,
    device_thumbprint: str,
    open_mandate: str,
    origin: str,
) -> bytes:
    try:
        return canonicalize(
            {
                "v": 1, "purpose": PURPOSE_REVOKE, "challenge_id": challenge_id,
                "challenge": nonce, "customer_id": customer_id,
                "device_thumbprint": device_thumbprint, "open_mandate": open_mandate,
                "origin": origin,
            }
        )  # fmt: skip
    except JcsError:
        raise KeyRefused("proof_invalid") from None


def _token_hash(token: str) -> str:
    return hashlib.sha256(token.encode("ascii")).hexdigest()


def _live_device(ts: TrustedSurface, conn: Any, customer_id: str, thumbprint: str) -> Any:
    device = ts.key_by_thumbprint(conn, thumbprint)
    if device is None:
        raise ts.refusal_for("device_key_unknown")
    if device.customer_id != customer_id:
        raise ts.refusal_for("device_key_customer_mismatch")
    if device.rev is not None:
        raise ts.refusal_for("device_key_revoked")
    return device


def open_session(
    ts: TrustedSurface,
    *,
    challenge_id: object,
    customer_id: object,
    device_thumbprint: object,
    origin: object,
    signature: object,
    origin_header: str | None = None,
) -> Session:
    from countersign.trusted_surface.service import CHALLENGE_ID, _loads_jwk, _Seen

    seen = _Seen(
        challenge_id=challenge_id
        if isinstance(challenge_id, str) and CHALLENGE_ID.fullmatch(challenge_id)
        else None,
        thumbprint=device_thumbprint
        if isinstance(device_thumbprint, str) and THUMBPRINT.fullmatch(device_thumbprint)
        else None,
    )

    def work() -> Session:
        if not (
            isinstance(customer_id, str) and CUSTOMER.fullmatch(customer_id)
            and isinstance(device_thumbprint, str) and THUMBPRINT.fullmatch(device_thumbprint)
            and isinstance(signature, str) and seen.challenge_id is not None
        ):  # fmt: skip
            raise ts.refusal_for("malformed_request")
        ts.check_origin(origin, origin_header)
        with ts.engine.begin() as conn:
            now_us = ts.now_us()
            challenge = ts.challenge(conn, seen.challenge_id, CHALLENGE_PURPOSE_READ, now_us)
            device = _live_device(ts, conn, customer_id, device_thumbprint)
            record = read_record(
                challenge_id=seen.challenge_id, nonce=challenge.nonce, customer_id=customer_id,
                device_thumbprint=device_thumbprint, origin=ts.origin,
            )  # fmt: skip
            public = validate_public_jwk(_loads_jwk(device.jwk))
            if not verify_signature(public.verifying_key(), record, signature):
                raise ts.refusal_for("proof_invalid")
            ts.consume(conn, seen.challenge_id, device.thumbprint, now_us)
            token = TOKEN_PREFIX + secrets.token_urlsafe(32)
            conn.execute(
                activity_sessions.insert().values(
                    token_hash=_token_hash(token), customer_id=customer_id,
                    device_thumbprint=device.thumbprint, challenge_id=seen.challenge_id,
                    created_us=now_us,
                )
            )  # fmt: skip
            ts.append(
                conn, LOG_KIND_SESSION, now_us,
                {"customer_id": customer_id, "device_thumbprint": device.thumbprint,
                 "challenge_id": seen.challenge_id},
            )  # fmt: skip
            return Session(token, customer_id, now_us + SESSION_TTL_US)

    result: Session = ts.guard(LOG_KIND_SESSION_REFUSED, seen, work)
    return result


def read_activity(ts: TrustedSurface, token: object) -> Activity:
    from countersign.trusted_surface.service import _Seen

    def work() -> Activity:
        if not isinstance(token, str) or TOKEN.fullmatch(token) is None:
            raise ts.refusal_for("session_unknown")
        with ts.engine.connect() as conn:
            now_us = ts.now_us()
            row = conn.execute(
                select(activity_sessions).where(
                    activity_sessions.c.token_hash == _token_hash(token)
                )
            ).first()
            if row is None:
                raise ts.refusal_for("session_unknown")
            if now_us >= int(row.created_us) + SESSION_TTL_US:
                raise ts.refusal_for("session_expired")
            _live_device(ts, conn, str(row.customer_id), str(row.device_thumbprint))
            views = list_for_customer(conn, str(row.customer_id), now_us // 1_000_000)
            return Activity(str(row.customer_id), now_us // 1_000_000, views)

    result: Activity = ts.guard(LOG_KIND_READ_REFUSED, _Seen(), work)
    return result


def revoke_open_mandate(
    ts: TrustedSurface,
    *,
    challenge_id: object,
    customer_id: object,
    device_thumbprint: object,
    open_mandate: object,
    origin: object,
    signature: object,
    origin_header: str | None = None,
) -> MandateRevoked:
    from countersign.trusted_surface.service import CHALLENGE_ID, _loads_jwk, _Seen

    seen = _Seen(
        challenge_id=challenge_id
        if isinstance(challenge_id, str) and CHALLENGE_ID.fullmatch(challenge_id)
        else None,
        thumbprint=device_thumbprint
        if isinstance(device_thumbprint, str) and THUMBPRINT.fullmatch(device_thumbprint)
        else None,
    )

    def work() -> MandateRevoked:
        if not (
            isinstance(customer_id, str) and CUSTOMER.fullmatch(customer_id)
            and isinstance(device_thumbprint, str) and THUMBPRINT.fullmatch(device_thumbprint)
            and isinstance(open_mandate, str) and IDENTITY.fullmatch(open_mandate)
            and isinstance(signature, str) and seen.challenge_id is not None
        ):  # fmt: skip
            raise ts.refusal_for("malformed_request")
        ts.check_origin(origin, origin_header)
        with ts.engine.begin() as conn:
            now_us = ts.now_us()
            ts.lock_customer(conn, customer_id)
            challenge = ts.challenge(conn, seen.challenge_id, CHALLENGE_PURPOSE_REVOKE, now_us)
            device = _live_device(ts, conn, customer_id, device_thumbprint)
            record = revoke_record(
                challenge_id=seen.challenge_id, nonce=challenge.nonce, customer_id=customer_id,
                device_thumbprint=device_thumbprint, open_mandate=open_mandate, origin=ts.origin,
            )  # fmt: skip
            public = validate_public_jwk(_loads_jwk(device.jwk))
            if not verify_signature(public.verifying_key(), record, signature):
                raise ts.refusal_for("proof_invalid")
            mandate = conn.execute(
                select(open_mandates).where(
                    open_mandates.c.id == open_mandate, open_mandates.c.customer_id == customer_id
                )
            ).first()
            if mandate is None:
                raise ts.refusal_for("open_mandate_unknown")
            outcome = revoke_in(
                conn, payment_identity=str(mandate.id),
                checkout_identity=str(mandate.checkout_identity), currency=str(mandate.currency),
                now_us=now_us, customer_id=customer_id, signer_thumbprint=device.thumbprint,
                challenge_id=seen.challenge_id, record=record.decode(), signature=signature,
            )  # fmt: skip
            if outcome.code in (IN_FLIGHT, ALREADY_USED):
                raise ts.refusal_for(outcome.code)
            ts.consume(conn, seen.challenge_id, device.thumbprint, now_us)
            ts.append(
                conn, LOG_KIND_REVOKED, now_us,
                {"open_mandate": open_mandate, "customer_id": customer_id,
                 "device_thumbprint": device.thumbprint, "new_revocation": outcome.new,
                 "challenge_id": seen.challenge_id},
            )  # fmt: skip
            return MandateRevoked(open_mandate, outcome.new)

    result: MandateRevoked = ts.guard(LOG_KIND_REVOKE_REFUSED, seen, work)
    return result
