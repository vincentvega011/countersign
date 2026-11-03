"""Device keys and consent: challenges, registration, revocation and consent (migrations 0007 to 0009).

Security reasoning. Registration binds a customer id to a P-256 key; consent is that key saying "this
is what I approve"; the platform then signs the open mandates (PROTOCOL.md Decisions 5, 77 to 81). All
three operations share one mechanism: a server-issued, single-use, short-lived challenge bound to a
purpose, a record the device key signs, and a log entry written before the answer.

Challenges. A row in `key_challenges` (random nonce, purpose, issue time). It lives 5 minutes from
`created_us`; nothing is updated to expire it. It is spent by an INSERT into `key_challenge_uses`
whose primary key is the challenge id, so of N simultaneous submissions the unique index lets exactly
one commit and the rest fail with `challenge_used`. A refused operation rolls back and spends nothing.

Registration, in order, each step with a stable refusal code: the JWK (`keys.validate_public_jwk`);
the origin (claimed and `Origin` header) equals the configured one (`origin_mismatch`); the challenge
exists, has the registration purpose, is unexpired and unused; the proof of possession verifies over
the record the server rebuilds (`proof_invalid`); for an existing customer, a registered non-revoked
key of that customer signed the same record; a thumbprint already registered is an idempotent success
for the same customer, `key_conflict` for another and `key_revoked` once revoked; then consume the
challenge, insert the key and append the log entry, in one transaction.

Revocation. A key is revoked when a row exists in `key_revocations` (insert only). The request is
signed by a registered, non-revoked key of the same customer and bound to a challenge; it may name the
signer itself or another key of that customer. Revoking a revoked key is an idempotent success. Per
customer, the work holds an advisory lock, so two keys cannot revoke each other at once and leave a
customer that nobody can speak for by accident of timing.

Consent. See `consent.py` for the record. The work holds the customer lock, so it serializes with a
revocation. The device key must be registered to the record's customer
and not revoked; the signature must verify with the STORED public key (never one from the request); the
challenge must be a consent challenge carrying the record's nonce; the origin, the record's own
expiry, the terms (a real merchant, catalog items shown as they are, a ceiling, a short expiry) and
the byte equality of the claimed contents with the backend's rebuild are all checked before the
platform key signs anything (`issuer.py`). The consent record, its signature, the device key and the
two mandates are stored together, insert only.

Every refusal is appended to the hash-chained log before the answer is returned (INV-12); if the append
fails the answer is `log_unavailable` and nothing else happened (INV-10). The log holds the code, the
thumbprint when one was computed, the challenge id and a fixed internal `detail` token, never a request
body. A success is logged in the transaction that stores it.

Creating a new customer is unauthenticated in this demo (LIMITATIONS.md L35).
"""

from __future__ import annotations

import hashlib
import re
import secrets
import time
from collections.abc import Callable, Mapping
from dataclasses import dataclass
from typing import Any

import structlog
from joserfc.jwk import ECKey
from sqlalchemy import Engine, select, text
from sqlalchemy.exc import IntegrityError

from countersign.canonical.hashing import b64url
from countersign.canonical.jcs import JcsError, canonicalize
from countersign.canonical.jsonstrict import loads_strict
from countersign.catalog.catalog import Catalog, load_catalog
from countersign.ledger import store as ledger_store
from countersign.merchant.keys import MerchantKey
from countersign.merchant.policy import policy_hash as ledger_policy_hash
from countersign.openmandates import register_in
from countersign.tables import (
    consent_records,
    customer_keys,
    key_challenge_uses,
    key_challenges,
    key_revocations,
)
from countersign.trusted_surface import activity, agent_channel, purchase
from countersign.trusted_surface.consent import (
    CHALLENGE_PURPOSE_CONSENT,
    MAX_RECORD_SECONDS,
    SKEW_SECONDS,
    ConsentRecord,
    ConsentRefused,
    build_mandate,
    mismatch_part,
    parse_record,
    validate_terms,
)
from countersign.trusted_surface.issuer import IssuerRefused, issue_open_mandate
from countersign.trusted_surface.keys import (
    KeyRefused,
    PublicKey,
    normalize_origin,
    origin_string,
    registration_record,
    revocation_record,
    validate_public_jwk,
    verify_signature,
)

log = structlog.get_logger("countersign.trusted_surface")

CHALLENGE_PURPOSE = "register_device_key"
CHALLENGE_PURPOSE_REVOKE = "revoke_device_key"
CHALLENGE_PURPOSES = frozenset(
    {
        CHALLENGE_PURPOSE,
        CHALLENGE_PURPOSE_REVOKE,
        CHALLENGE_PURPOSE_CONSENT,
        "agent_proposal",
        "agent_fetch",
        "consent_checkout",
        "activity_read",
        "revoke_open_mandate",
    }
)
CHALLENGE_TTL_US = 5 * 60 * 1_000_000
CUSTOMER_ID = re.compile(r"cus_[A-Za-z0-9_-]{22}")
CHALLENGE_ID = re.compile(r"kch_[A-Za-z0-9_-]{22}")
THUMBPRINT = re.compile(r"[A-Za-z0-9_-]{43}")
LOG_KIND_REFUSED = "ts.key.refused"
LOG_KIND_REGISTERED = "ts.key.registered"
LOG_KIND_REVOKED = "ts.key.revoked"
LOG_KIND_CHALLENGE = "ts.challenge.refused"
LOG_KIND_CONSENT_REFUSED = "ts.consent.refused"
LOG_KIND_CONSENT = "ts.consent.issued"


class Refused(Exception):
    """A refusal with its stable code. `status` is the HTTP status the route answers with."""

    def __init__(self, code: str, status: int = 400) -> None:
        super().__init__(code)
        self.code = code
        self.status = status


_STATUS = {
    "origin_mismatch": 403,
    "challenge_unknown": 404,
    "challenge_used": 409,
    "challenge_expired": 410,
    "customer_unknown": 404,
    "key_conflict": 409,
    "key_revoked": 409,
    "key_unknown": 404,
    "authorizer_required": 403,
    "authorizer_unknown": 403,
    "authorizer_revoked": 403,
    "authorizer_invalid": 403,
    "signer_unknown": 403,
    "signer_revoked": 403,
    "device_key_unknown": 403,
    "device_key_customer_mismatch": 403,
    "device_key_revoked": 403,
    "consent_expired": 410,
    "request_too_large": 413,
    "log_unavailable": 503,
    "unavailable": 503,
    "signing_unavailable": 503,
    "proposal_unknown": 404,
    "proposal_expired": 410,
    "proposal_used": 409,
    "consent_pending": 409,
    "offer_unknown": 404,
    "offer_expired": 410,
    "offer_used": 409,
    "checkout_unknown": 404,
    "session_unknown": 401,
    "session_expired": 401,
    "open_mandate_unknown": 404,
    "in_flight": 409,
    "already_used": 409,
    "checkout_not_ready": 409,
    "checkout_expired": 410,
    "checkout_changed": 409,
    "merchant_authorization_invalid": 502,
}


def refusal(code: str) -> Refused:
    return Refused(code, _STATUS.get(code, 400))


@dataclass(frozen=True)
class Challenge:
    challenge_id: str
    nonce: str
    purpose: str
    issued_at: int  # seconds, the server's clock: the time a record names as its own
    expires_us: int


@dataclass(frozen=True)
class Enrolled:
    customer_id: str
    thumbprint: str
    new_customer: bool  # a customer id was minted by this call
    new_key: bool  # a key row was inserted by this call (False for an idempotent repeat)


@dataclass(frozen=True)
class Revoked:
    customer_id: str
    thumbprint: str
    new_revocation: bool  # False: the key was already revoked (idempotent)


@dataclass(frozen=True)
class Consented:
    open_mandate: str  # the payment open mandate identity (Decision 86)
    consent_id: str
    customer_id: str
    agent_thumbprint: str
    checkout_mandate: str
    payment_mandate: str
    expires_at: int


@dataclass(frozen=True)
class Authorizer:
    thumbprint: str
    signature: str


@dataclass(frozen=True)
class Merchant:
    """The merchant this Trusted Surface speaks for: what a consent record's terms must name."""

    id: str
    name: str
    website: str

    def as_dict(self) -> dict[str, str]:
        return {"id": self.id, "name": self.name, "website": self.website}


@dataclass
class _Seen:
    """What a refusal may name in the log: the thumbprint and challenge id, once known."""

    challenge_id: str | None = None
    thumbprint: str | None = None


def _now_us() -> int:
    return time.time_ns() // 1000


def _loads_jwk(value: str) -> Mapping[str, Any]:
    loaded = loads_strict(value.encode())
    if not isinstance(loaded, dict):
        raise KeyRefused("jwk_malformed")
    return loaded


class TrustedSurface:
    def __init__(
        self,
        engine: Engine,
        *,
        public_origin: str,
        clock_us: Callable[[], int] = _now_us,
        platform_key: ECKey | None = None,
        issuer: str | None = None,
        merchant: Merchant | None = None,
        catalog: Catalog | None = None,
        merchant_key: MerchantKey | None = None,
    ) -> None:
        self._merchant_key = merchant_key
        self._engine = engine
        self._origin = normalize_origin(public_origin)  # a bad configuration stops the start
        self._clock_us = clock_us
        self._policy_hash = ledger_policy_hash()
        self._platform_key = platform_key
        self._issuer = issuer or origin_string(self._origin)
        self._merchant = merchant or Merchant(
            "merchant-1", "Countersign demo store", origin_string(self._origin)
        )
        self._catalog = catalog

    @property
    def origin(self) -> str:
        return origin_string(self._origin)

    # The package's own helpers, public to the modules that extend this service.
    @property
    def engine(self) -> Engine:
        return self._engine

    def now_us(self) -> int:
        return self._clock_us()

    def refusal_for(self, code: str) -> Refused:
        return refusal(code)

    def check_origin(self, origin: object, header: str | None) -> None:
        self._check_origin(origin, header)

    def challenge(
        self, conn: Any, challenge_id: str, purpose: str, now: int, nonce: str | None = None
    ) -> Any:
        return self._challenge(conn, challenge_id, purpose, now, nonce)

    def consume(self, conn: Any, challenge_id: str, thumbprint: str, now: int) -> None:
        self._consume(conn, challenge_id, thumbprint, now)

    def append(self, conn: Any, kind: str, now: int, payload: dict[str, Any]) -> None:
        self._append(conn, kind, now, payload)

    def guard(self, kind: str, seen: _Seen, work: Callable[[], Any]) -> Any:
        return self._guard(kind, seen, work)

    def lock_customer(self, conn: Any, customer_id: str) -> None:
        self._lock_customer(conn, customer_id)

    def key_by_thumbprint(self, conn: Any, thumbprint: str) -> Any:
        return self._key_by_thumbprint(conn, thumbprint)

    @property
    def merchant_key(self) -> MerchantKey | None:
        return self._merchant_key

    @property
    def platform_key(self) -> ECKey | None:
        return self._platform_key

    @property
    def issuer_name(self) -> str:
        return self._issuer

    @property
    def merchant(self) -> Merchant:
        return self._merchant

    @property
    def can_issue(self) -> bool:
        return self._platform_key is not None and bool(self._platform_key.is_private)

    def store_info(self) -> dict[str, Any]:
        """What the Approve intent page may show about this store: authored here, not by an agent."""
        catalog = self._catalog or load_catalog()
        return {
            "merchant": self._merchant.as_dict(),
            "currency": "USD",
            "items": [{"id": item.id, "title": item.title} for item in catalog.items],
        }

    # ------------------------------------------------------------------ log

    def _log_refusal(
        self,
        kind: str,
        code: str,
        *,
        thumbprint: str | None,
        challenge_id: str | None,
        detail: str = "",
    ) -> None:
        """Append the refusal before the answer; if that fails the answer is `log_unavailable`."""
        payload: dict[str, Any] = {
            "code": code, "thumbprint": thumbprint, "challenge_id": challenge_id,
        }  # fmt: skip
        if detail:
            payload["detail"] = detail
        try:
            with self._engine.begin() as conn:
                ledger_store.append(
                    conn, kind=kind, ts_us=self._clock_us(), policy_hash=self._policy_hash,
                    payload=payload,
                )  # fmt: skip
        except Exception as error:  # noqa: BLE001 - INV-10, INV-12
            log.error("ts_log_failed", error=type(error).__name__)
            raise refusal("log_unavailable") from None

    def reject_request(self, code: str, kind: str = LOG_KIND_REFUSED) -> Refused:
        """Log a refusal made before the service ran (a body that is not even the right shape)."""
        self._log_refusal(kind, code, thumbprint=None, challenge_id=None)
        return refusal(code)

    def _guard(self, kind: str, seen: _Seen, work: Callable[[], Any]) -> Any:
        """Run `work`; turn every refusal and every unexpected error into a logged answer."""
        try:
            return work()
        except (Refused, KeyRefused, ConsentRefused, IssuerRefused) as error:
            code = error.code
            self._log_refusal(
                kind, code, thumbprint=seen.thumbprint, challenge_id=seen.challenge_id,
                detail=getattr(error, "detail", ""),
            )  # fmt: skip
            raise refusal(code) from None
        except Exception as error:  # noqa: BLE001 - INV-10: anything unexpected refuses
            log.error("ts_operation_failed", kind=kind, error=type(error).__name__)
            self._log_refusal(
                kind, "unavailable", thumbprint=seen.thumbprint, challenge_id=seen.challenge_id
            )
            raise refusal("unavailable") from None

    # ------------------------------------------------------------------ challenge

    def issue_challenge(self, purpose: object) -> Challenge:
        if purpose not in CHALLENGE_PURPOSES:
            self._log_refusal(
                LOG_KIND_CHALLENGE, "purpose_unknown", thumbprint=None, challenge_id=None
            )
            raise refusal("purpose_unknown")
        assert isinstance(purpose, str)
        challenge_id = "kch_" + secrets.token_urlsafe(16)
        nonce = secrets.token_urlsafe(32)
        created = self._clock_us()
        try:
            with self._engine.begin() as conn:
                conn.execute(
                    key_challenges.insert().values(
                        id=challenge_id, purpose=purpose, nonce=nonce, created_us=created
                    )
                )
        except Exception as error:  # noqa: BLE001 - INV-10
            log.error("ts_challenge_failed", error=type(error).__name__)
            raise refusal("unavailable") from None
        return Challenge(
            challenge_id, nonce, purpose, created // 1_000_000, created + CHALLENGE_TTL_US
        )

    def _challenge(
        self, conn: Any, challenge_id: str, purpose: str, now: int, nonce: str | None = None
    ) -> Any:
        """The challenge row if it is this purpose, unexpired and unused; else a refusal."""
        row = conn.execute(
            select(key_challenges).where(key_challenges.c.id == challenge_id)
        ).first()
        if row is None:
            raise refusal("challenge_unknown")
        if row.purpose != purpose:
            raise refusal("challenge_purpose_mismatch")
        if nonce is not None and row.nonce != nonce:
            raise refusal("challenge_nonce_mismatch")
        if now >= int(row.created_us) + CHALLENGE_TTL_US:
            raise refusal("challenge_expired")
        used = conn.execute(
            select(key_challenge_uses.c.challenge_id).where(
                key_challenge_uses.c.challenge_id == challenge_id
            )
        ).first()
        if used is not None:
            raise refusal("challenge_used")
        return row

    def _consume(self, conn: Any, challenge_id: str, thumbprint: str, now: int) -> None:
        """Spend the challenge: an INSERT, and a unique violation means someone else got there."""
        try:
            with conn.begin_nested():
                conn.execute(
                    key_challenge_uses.insert().values(
                        challenge_id=challenge_id, thumbprint=thumbprint, used_us=now
                    )
                )
        except IntegrityError:
            raise refusal("challenge_used") from None

    def _check_origin(self, origin: object, header: str | None) -> None:
        if normalize_origin(origin) != self._origin:
            raise refusal("origin_mismatch")
        if header is not None and normalize_origin(header) != self._origin:
            raise refusal("origin_mismatch")

    # ------------------------------------------------------------------ key rows

    @staticmethod
    def _keys_of(conn: Any, customer_id: str) -> list[Any]:
        """Every key of a customer, each with `.revoked` (a row in `key_revocations`)."""
        return list(
            conn.execute(
                select(customer_keys, key_revocations.c.thumbprint.label("rev"))
                .select_from(
                    customer_keys.outerjoin(
                        key_revocations, customer_keys.c.thumbprint == key_revocations.c.thumbprint
                    )
                )
                .where(customer_keys.c.customer_id == customer_id)
            ).all()
        )

    @staticmethod
    def _key_by_thumbprint(conn: Any, thumbprint: str) -> Any:
        return conn.execute(
            select(customer_keys, key_revocations.c.thumbprint.label("rev"))
            .select_from(
                customer_keys.outerjoin(
                    key_revocations, customer_keys.c.thumbprint == key_revocations.c.thumbprint
                )
            )
            .where(customer_keys.c.thumbprint == thumbprint)
        ).first()

    @staticmethod
    def _lock_customer(conn: Any, customer_id: str) -> None:
        conn.execute(
            text("SELECT pg_advisory_xact_lock(hashtext(:k))"),
            {"k": f"cs.ts.customer:{customer_id}"},
        )

    # ------------------------------------------------------------------ registration

    def register(
        self,
        *,
        jwk: object,
        challenge_id: object,
        customer_id: object,
        origin: object,
        signature: object,
        authorizer: Authorizer | None,
        origin_header: str | None = None,
    ) -> Enrolled:
        seen = _Seen(
            challenge_id=challenge_id
            if isinstance(challenge_id, str) and CHALLENGE_ID.fullmatch(challenge_id)
            else None
        )
        result: Enrolled = self._guard(
            LOG_KIND_REFUSED, seen,
            lambda: self._register(
                seen, jwk, customer_id, origin, signature, authorizer, origin_header
            ),
        )  # fmt: skip
        return result

    def _register(
        self,
        seen: _Seen,
        jwk: object,
        customer_id: object,
        origin: object,
        signature: object,
        authorizer: Authorizer | None,
        origin_header: str | None,
    ) -> Enrolled:
        key = validate_public_jwk(jwk)
        seen.thumbprint = key.thumbprint
        if customer_id is not None and not (
            isinstance(customer_id, str) and CUSTOMER_ID.fullmatch(customer_id)
        ):
            raise refusal("malformed_request")
        if not isinstance(signature, str) or seen.challenge_id is None:
            raise refusal("malformed_request")
        if authorizer is not None and customer_id is None:
            raise refusal("malformed_request")  # a voucher only means something for a customer
        self._check_origin(origin, origin_header)

        with self._engine.begin() as conn:
            now = self._clock_us()
            challenge = self._challenge(conn, seen.challenge_id, CHALLENGE_PURPOSE, now)
            record = registration_record(
                challenge_id=seen.challenge_id, nonce=challenge.nonce,
                thumbprint=key.thumbprint, customer_id=customer_id, origin=self.origin,
            )  # fmt: skip
            if not verify_signature(key.verifying_key(), record, signature):
                raise refusal("proof_invalid")
            if customer_id is not None:
                self._lock_customer(conn, customer_id)
            existing = self._key_by_thumbprint(conn, key.thumbprint)
            if customer_id is not None:
                self._check_customer(conn, customer_id, record, authorizer, existing)
            if existing is not None:
                return self._repeat(conn, existing, seen, key, now)
            owner = customer_id if customer_id is not None else "cus_" + secrets.token_urlsafe(16)
            return self._insert(conn, seen, key, owner, created=customer_id is None, now=now)

    def _check_customer(
        self, conn: Any, customer_id: str, record: bytes, authorizer: Authorizer | None,
        existing: Any,
    ) -> None:  # fmt: skip
        """Adding to an existing customer: it must exist, and an old key must vouch for the new one."""
        rows = self._keys_of(conn, customer_id)
        if not rows:
            raise refusal("customer_unknown")
        if existing is not None:
            if existing.customer_id != customer_id:
                raise refusal("key_conflict")
            return  # already this customer's key: nothing changes, so no voucher is needed
        if authorizer is None:
            raise refusal("authorizer_required")
        old = next((r for r in rows if r.thumbprint == authorizer.thumbprint), None)
        if old is None:
            raise refusal("authorizer_unknown")
        if old.rev is not None:
            raise refusal("authorizer_revoked")
        public = validate_public_jwk(_loads_jwk(old.jwk))
        if not verify_signature(public.verifying_key(), record, authorizer.signature):
            raise refusal("authorizer_invalid")

    def _repeat(self, conn: Any, existing: Any, seen: _Seen, key: PublicKey, now: int) -> Enrolled:
        """The thumbprint is registered and no other customer was named: an idempotent repeat.

        A revoked key never gets this answer: revocation is final (Decision 78).
        """
        if existing.rev is not None:
            raise refusal("key_revoked")
        assert seen.challenge_id is not None
        self._consume(conn, seen.challenge_id, key.thumbprint, now)
        self._append(
            conn, LOG_KIND_REGISTERED, now,
            {
                "thumbprint": key.thumbprint, "customer_id": existing.customer_id,
                "new_customer": False, "new_key": False, "challenge_id": seen.challenge_id,
            },
        )  # fmt: skip
        return Enrolled(str(existing.customer_id), key.thumbprint, False, False)

    def _insert(
        self, conn: Any, seen: _Seen, key: PublicKey, owner: str, *, created: bool, now: int
    ) -> Enrolled:
        assert seen.challenge_id is not None
        self._consume(conn, seen.challenge_id, key.thumbprint, now)
        try:
            with conn.begin_nested():
                conn.execute(
                    customer_keys.insert().values(
                        customer_id=owner, thumbprint=key.thumbprint,
                        jwk=canonicalize(key.jwk).decode(), created_us=now,
                    )
                )  # fmt: skip
        except IntegrityError:
            raise refusal("key_conflict") from None
        self._append(
            conn, LOG_KIND_REGISTERED, now,
            {
                "thumbprint": key.thumbprint, "customer_id": owner, "new_customer": created,
                "new_key": True, "challenge_id": seen.challenge_id,
            },
        )  # fmt: skip
        return Enrolled(owner, key.thumbprint, created, True)

    def _append(self, conn: Any, kind: str, now: int, payload: dict[str, Any]) -> None:
        ledger_store.append(
            conn, kind=kind, ts_us=now, policy_hash=self._policy_hash, payload=payload
        )

    # ------------------------------------------------------------------ revocation

    def revoke(
        self,
        *,
        challenge_id: object,
        customer_id: object,
        target: object,
        signer: object,
        origin: object,
        signature: object,
        origin_header: str | None = None,
    ) -> Revoked:
        seen = _Seen(
            challenge_id=challenge_id
            if isinstance(challenge_id, str) and CHALLENGE_ID.fullmatch(challenge_id)
            else None,
            thumbprint=target if isinstance(target, str) and THUMBPRINT.fullmatch(target) else None,
        )
        result: Revoked = self._guard(
            LOG_KIND_REFUSED, seen,
            lambda: self._revoke(seen, customer_id, target, signer, origin, signature, origin_header),
        )  # fmt: skip
        return result

    def _revoke(
        self,
        seen: _Seen,
        customer_id: object,
        target: object,
        signer: object,
        origin: object,
        signature: object,
        origin_header: str | None,
    ) -> Revoked:
        if not (
            isinstance(customer_id, str) and CUSTOMER_ID.fullmatch(customer_id)
            and isinstance(target, str) and THUMBPRINT.fullmatch(target)
            and isinstance(signer, str) and THUMBPRINT.fullmatch(signer)
            and isinstance(signature, str) and seen.challenge_id is not None
        ):  # fmt: skip
            raise refusal("malformed_request")
        self._check_origin(origin, origin_header)
        with self._engine.begin() as conn:
            now = self._clock_us()
            challenge = self._challenge(conn, seen.challenge_id, CHALLENGE_PURPOSE_REVOKE, now)
            self._lock_customer(conn, customer_id)
            rows = {r.thumbprint: r for r in self._keys_of(conn, customer_id)}
            if not rows:
                raise refusal("customer_unknown")
            signing = rows.get(signer)
            if signing is None:
                raise refusal("signer_unknown")
            if signing.rev is not None:
                raise refusal("signer_revoked")
            record = revocation_record(
                challenge_id=seen.challenge_id, nonce=challenge.nonce, customer_id=customer_id,
                target_thumbprint=target, signer_thumbprint=signer, origin=self.origin,
            )  # fmt: skip
            public = validate_public_jwk(_loads_jwk(signing.jwk))
            if not verify_signature(public.verifying_key(), record, signature):
                raise refusal("proof_invalid")
            victim = rows.get(target)
            if victim is None:
                raise refusal("key_unknown")
            self._consume(conn, seen.challenge_id, signer, now)
            fresh = victim.rev is None
            if fresh:
                conn.execute(
                    key_revocations.insert().values(
                        thumbprint=target, customer_id=customer_id, signer_thumbprint=signer,
                        challenge_id=seen.challenge_id, record=record.decode(),
                        signature=signature, revoked_us=now,
                    )
                )  # fmt: skip
            self._append(
                conn, LOG_KIND_REVOKED, now,
                {
                    "customer_id": customer_id, "thumbprint": target, "signer": signer,
                    "new_revocation": fresh, "challenge_id": seen.challenge_id,
                },
            )  # fmt: skip
            return Revoked(customer_id, target, fresh)

    # ------------------------------------------------------------------ consent

    def consent(
        self,
        *,
        record: object,
        signature: object,
        proposal_id: object,
        origin_header: str | None = None,
    ) -> Consented:
        seen = _Seen()
        result: Consented = self._guard(
            LOG_KIND_CONSENT_REFUSED, seen,
            lambda: self._consent(seen, record, signature, proposal_id, origin_header),
        )  # fmt: skip
        return result

    def _consent(
        self,
        seen: _Seen,
        raw: object,
        signature: object,
        proposal_id: object,
        origin_header: str | None,
    ) -> Consented:
        if not isinstance(signature, str):
            raise ConsentRefused("consent_malformed", "signature")
        parsed: ConsentRecord = parse_record(raw)
        seen.challenge_id = (
            parsed.challenge_id if CHALLENGE_ID.fullmatch(parsed.challenge_id) else None
        )
        seen.thumbprint = parsed.device_thumbprint
        if seen.challenge_id is None:
            raise ConsentRefused("consent_malformed", "challenge id")
        self._check_origin(parsed.origin, origin_header)
        if not self.can_issue:
            raise refusal("signing_unavailable")
        try:
            record_bytes = canonicalize(parsed.raw)
        except JcsError:
            raise ConsentRefused("consent_malformed", "not canonicalizable") from None

        with self._engine.begin() as conn:
            now_us = self._clock_us()
            now_s = now_us // 1_000_000
            # Serialize with a revocation of this customer's keys: a key revoked a moment ago must not
            # still be read as live by a consent that commits a moment later.
            self._lock_customer(conn, parsed.customer_id)
            self._challenge(
                conn, seen.challenge_id, CHALLENGE_PURPOSE_CONSENT, now_us, nonce=parsed.nonce
            )
            device = self._key_by_thumbprint(conn, parsed.device_thumbprint)
            if device is None:
                raise refusal("device_key_unknown")
            if device.customer_id != parsed.customer_id:
                raise refusal("device_key_customer_mismatch")
            if device.rev is not None:
                raise refusal("device_key_revoked")
            public = validate_public_jwk(_loads_jwk(device.jwk))
            if not verify_signature(public.verifying_key(), record_bytes, signature):
                raise refusal("consent_signature_invalid")

            lifetime = parsed.expires_at - parsed.issued_at
            if not 0 < lifetime <= MAX_RECORD_SECONDS or parsed.issued_at > now_s + SKEW_SECONDS:
                raise ConsentRefused("consent_time_invalid")
            if now_s >= parsed.expires_at:
                raise refusal("consent_expired")

            # The agent key comes from the stored proposal (Decision 87), never from the request.
            proposal = agent_channel.load_proposal(self, conn, proposal_id)
            if now_us >= int(proposal.created_us) + agent_channel.PROPOSAL_TTL_US:
                raise refusal("proposal_expired")
            agent = validate_public_jwk(loads_strict(str(proposal.agent_jwk).encode()))
            if agent.thumbprint != parsed.terms.agent_thumbprint:
                raise ConsentRefused("agent_key_mismatch")
            stored = loads_strict(str(proposal.terms).encode())
            if not (
                isinstance(stored, dict)
                and stored["items"]
                == [{"id": i["id"], "quantity": i["quantity"]} for i in parsed.terms.items]
                and stored["ceiling_minor"] == parsed.terms.ceiling_minor
                and stored["currency"] == parsed.terms.currency
                and stored["mandate_expires_at"] == parsed.terms.mandate_expires_at
            ):
                raise ConsentRefused("consent_proposal_mismatch")
            validate_terms(
                parsed.terms,
                merchant=self._merchant.as_dict(),
                catalog=self._catalog or load_catalog(),
                now_s=now_s,
                record_expires_at=parsed.expires_at,
            )
            expected = build_mandate(parsed.terms)
            try:
                same = canonicalize(parsed.mandate) == canonicalize(expected)
            except JcsError:
                same = False
            if not same:
                raise ConsentRefused(
                    "consent_claims_mismatch", mismatch_part(parsed.mandate, expected)
                )

            assert self._platform_key is not None
            checkout = issue_open_mandate(
                expected["checkout"], kind="checkout", customer_id=parsed.customer_id,
                agent_jwk=agent.jwk, issuer=self._issuer, key=self._platform_key, now_s=now_s,
            )  # fmt: skip
            payment_content = {
                **expected["payment"],
                "constraints": [
                    {"type": "payment.reference", "conditional_transaction_id": checkout.digest},
                    *expected["payment"]["constraints"],
                ],
            }
            payment = issue_open_mandate(
                payment_content, kind="payment", customer_id=parsed.customer_id,
                agent_jwk=agent.jwk, issuer=self._issuer, key=self._platform_key, now_s=now_s,
            )  # fmt: skip

            self._consume(conn, seen.challenge_id, device.thumbprint, now_us)
            consent_id = "csn_" + secrets.token_urlsafe(16)
            conn.execute(
                consent_records.insert().values(
                    id=consent_id, challenge_id=seen.challenge_id, customer_id=parsed.customer_id,
                    device_thumbprint=device.thumbprint, device_jwk=device.jwk,
                    agent_thumbprint=agent.thumbprint, record=record_bytes.decode(),
                    signature=signature, checkout_mandate=checkout.token,
                    payment_mandate=payment.token, checkout_open_digest=checkout.digest,
                    payment_open_digest=payment.digest, mandate_exp=parsed.terms.mandate_expires_at,
                    created_us=now_us,
                )
            )  # fmt: skip
            register_in(
                conn,
                payment_identity=payment.identity,
                checkout_identity=checkout.identity,
                customer_id=parsed.customer_id,
                consent_id=consent_id,
                agent_thumbprint=agent.thumbprint,
                ceiling_minor=parsed.terms.ceiling_minor,
                currency=parsed.terms.currency,
                exp=parsed.terms.mandate_expires_at,
                now_us=now_us,
            )
            agent_channel.spend_proposal(self, conn, str(proposal.id), consent_id, now_us)
            self._append(
                conn, LOG_KIND_CONSENT, now_us,
                {
                    "proposal_id": str(proposal.id), "open_mandate": payment.identity,
                    "consent_id": consent_id, "customer_id": parsed.customer_id,
                    "device_thumbprint": device.thumbprint, "agent_thumbprint": agent.thumbprint,
                    "challenge_id": seen.challenge_id,
                    "record_hash": b64url(hashlib.sha256(record_bytes).digest()),
                    "checkout_open_digest": checkout.digest,
                    "payment_open_digest": payment.digest,
                },
            )  # fmt: skip
            return Consented(
                payment.identity,
                consent_id,
                parsed.customer_id,
                agent.thumbprint,
                checkout.token,
                payment.token,
                parsed.terms.mandate_expires_at,
            )

    # ------------------------------------------------------------------ extensions (own modules)

    def create_proposal(self, **kw: Any) -> agent_channel.Proposed:
        return agent_channel.create_proposal(self, **kw)

    def view_proposal(self, proposal_id: object) -> agent_channel.ProposalView:
        return agent_channel.view_proposal(self, proposal_id)

    def fetch_mandates(self, **kw: Any) -> agent_channel.Fetched:
        return agent_channel.fetch_mandates(self, **kw)

    def create_offer(self, checkout_id: object) -> purchase.Offer:
        return purchase.create_offer(self, checkout_id)

    def consent_purchase(self, **kw: Any) -> purchase.Purchased:
        return purchase.consent_purchase(self, **kw)

    def open_activity_session(self, **kw: Any) -> activity.Session:
        return activity.open_session(self, **kw)

    def read_activity(self, token: object) -> activity.Activity:
        return activity.read_activity(self, token)

    def revoke_open_mandate(self, **kw: Any) -> activity.MandateRevoked:
        return activity.revoke_open_mandate(self, **kw)
