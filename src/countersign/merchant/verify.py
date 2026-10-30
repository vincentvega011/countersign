"""Merchant role: verification of an AP2 Checkout Mandate on `complete` (docs/architecture.md 5.4).

`CheckoutMandateVerifier.verify` runs the steps below in this fixed order, each with its own typed
failure, and returns either `Accepted` (a signed acceptance receipt and a reservation) or
`Rejected` (UCP `messages` and a signed rejection receipt). It is deterministic (INV-1): no model
output, no network, and time only from the injected clock. Parsing and chain verification are the
`countersign.mandates` primitives; nothing from them is re-implemented here.

M1 `mandate_required`. No mandate (None or empty) means AP2 was negotiated and not honoured. The
   mandate is never optional for a locked session (INV-3).
M2 chain. The platform provider key (the only trusted issuer, Decision 5) must have signed the open
   mandate, and the closed mandate must be signed by the key in that open mandate's `cnf`; or, in
   Human Present mode, the platform key signs a single closed mandate. Exact `vct`, algorithm
   allowlist, key binding and expiry are the mandates primitives. A platform without a usable key
   gives `agent_missing_key`, as does an open mandate with no usable agent key. Expiry gives
   `mandate_expired`; every other failure `mandate_invalid_signature`.
M3 checkout hash. The `checkout_hash` claim must equal SHA-256 of the checkout JWT that this
   session issued (rebuilt from our own last signed response). Without it a mandate for another
   checkout, or an older version of this one, could be replayed against this session. The checkout
   id is compared in M5 with the rest of the terms.
M4 merchant authorization. The checkout JWT embedded in the closed mandate must carry a merchant
   authorization that is ours: a missing or stripped signature gives
   `merchant_authorization_missing`, a signature that does not verify against our published keys,
   or an embedded JWT that is not canonical, `merchant_authorization_invalid`. The embedded JWT must
   then be exactly the one that M3 matched, otherwise it is a different checkout we signed.
M5 terms. The embedded checkout's terms (id, currency, line items, totals, no display text) must
   equal the current session state. The first differing path is kept for the log. M3 and M5 differ
   only if the stored state moved without being re-signed, which is exactly what must never be
   accepted.
M6 principal lock: added in P2.6 (between terms and constraints).
M7 constraints. The `ConstraintEvaluator` must return exactly `satisfied=True`. Anything else, or
   an evaluator error, rejects.
M8 reservation. All single-use keys are reserved in one atomic call (Decision 1). It runs last so a
   failure at any earlier step consumes nothing and the same open mandate can retry.

Any other exception inside the steps rejects with reason `internal_error` (INV-10) and aborts a
reservation if one exists. A `DecisionLogError` is not turned into a rejection: it propagates, the
reservation is aborted, and no result is returned (INV-12).
"""

from __future__ import annotations

from collections.abc import Callable, Mapping, Sequence
from dataclasses import dataclass
from typing import Any

from joserfc.jwk import ECKey

from countersign.canonical import HashInputError, JsonValue, StrictJsonError, loads_strict
from countersign.canonical import checkout_hash as hash_checkout_jwt
from countersign.canonical.models import Checkout, UcpShapeError
from countersign.mandates import (
    VCT_CHECKOUT,
    VCT_CHECKOUT_OPEN,
    MandateError,
    VerifiedChain,
    split_chain,
    verify_chain,
)
from countersign.mandates.errors import (
    CnfMalformedError,
    CnfMissingError,
    CnfUnsupportedKeyError,
    ExpiredError,
)
from countersign.mandates.structure import decode_b64url
from countersign.merchant import receipts
from countersign.merchant.authorization import (
    MISSING,
    AuthorizationError,
    checkout_jwt,
    verify_authorization,
)
from countersign.merchant.constraints import (
    ConstraintEvaluator,
    ConstraintOutcome,
    DenyAllConstraints,
)
from countersign.merchant.decision_log import DecisionLog, DecisionLogError
from countersign.merchant.keys import MerchantKey
from countersign.merchant.rejection import (
    AGENT_MISSING_KEY,
    MANDATE_EXPIRED,
    MANDATE_INVALID_SIGNATURE,
    MANDATE_REQUIRED,
    MANDATE_SCOPE_MISMATCH,
    MERCHANT_AUTHORIZATION_INVALID,
    MERCHANT_AUTHORIZATION_MISSING,
    Rejection,
)
from countersign.merchant.reservations import (
    AlreadyReservedError,
    Reservation,
    ReservationRequest,
    ReservationStore,
)

MODE_AUTONOMOUS = "autonomous"
MODE_HUMAN_PRESENT = "human_present"
KIND_ACCEPTED = "merchant.checkout_mandate.accepted"
KIND_REJECTED = "merchant.checkout_mandate.rejected"


@dataclass(frozen=True)
class MerchantConfig:
    issuer: str  # the `iss` of receipts
    signing_key: MerchantKey
    published_keys: Sequence[Mapping[str, Any]]  # our keys[] as published in the profile
    platform_key: ECKey | None  # the trusted platform provider key (Decision 5)
    audience: str = "merchant"  # the `aud` the closed mandate must carry


@dataclass(frozen=True)
class Accepted:
    receipt: str
    reservation: Reservation
    chain: VerifiedChain
    mode: str
    checkout_hash: str
    reference: str


@dataclass(frozen=True)
class Rejected:
    receipt: str
    messages: list[dict[str, Any]]
    step: str
    reason: str
    ucp_code: str
    detail: str
    reference: str


def terms_difference(embedded: JsonValue, current: JsonValue, path: str = "") -> str | None:
    """The first path where two terms documents differ, or None when they are equal."""
    if isinstance(embedded, dict) and isinstance(current, dict):
        for key in embedded.keys() | current.keys():
            if key not in embedded or key not in current:
                return f"{path}.{key}".lstrip(".")
        for key in current:  # current's key order is the canonical order
            found = terms_difference(embedded[key], current[key], f"{path}.{key}")
            if found:
                return found.lstrip(".")
        return None
    if isinstance(embedded, list) and isinstance(current, list):
        if len(embedded) != len(current):
            return path.lstrip(".") + "[length]"
        for index, (a, b) in enumerate(zip(embedded, current, strict=True)):
            found = terms_difference(a, b, f"{path}[{index}]")
            if found:
                return found.lstrip(".")
        return None
    if type(embedded) is not type(current) or embedded != current:
        return path.lstrip(".") or "$"
    return None


def _map_mandate_error(error: MandateError) -> Rejection:
    if isinstance(error, ExpiredError):
        return Rejection("M2", "mandate_expired", MANDATE_EXPIRED)
    if isinstance(error, CnfMissingError | CnfMalformedError | CnfUnsupportedKeyError):
        return Rejection("M2", f"chain:{error.code}", AGENT_MISSING_KEY)
    # Everything else, including a code this table has never seen, is an unverifiable mandate.
    return Rejection("M2", f"chain:{error.code}", MANDATE_INVALID_SIGNATURE)


class CheckoutMandateVerifier:
    def __init__(
        self,
        config: MerchantConfig,
        store: ReservationStore,
        log: DecisionLog,
        clock: Callable[[], float],
        constraints: ConstraintEvaluator | None = None,
    ) -> None:
        self._config = config
        self._store = store
        self._log = log
        self._clock = clock
        self._constraints: ConstraintEvaluator = constraints or DenyAllConstraints()

    # ---- steps ----

    def _m2_chain(self, mandate: str) -> tuple[VerifiedChain, str]:
        if self._config.platform_key is None:
            raise Rejection("M2", "platform_key_missing", AGENT_MISSING_KEY)
        try:
            count = len(split_chain(mandate))
            if count == 2:
                vcts, mode = [VCT_CHECKOUT_OPEN, VCT_CHECKOUT], MODE_AUTONOMOUS
            elif count == 1:
                vcts, mode = [VCT_CHECKOUT], MODE_HUMAN_PRESENT
            else:
                raise Rejection("M2", "chain:structure_chain_length", MANDATE_INVALID_SIGNATURE)
            chain = verify_chain(
                mandate,
                issuer_key=self._config.platform_key,
                expected_vcts=vcts,
                audience=self._config.audience,
                nonce=None,
                clock=self._clock,
            )
        except MandateError as error:
            raise _map_mandate_error(error) from None
        return chain, mode

    def _m3_hash(
        self, chain: VerifiedChain, issued: Mapping[str, Any] | None, current: Checkout
    ) -> str:
        claim = chain.final.content.get("checkout_hash")
        if not isinstance(claim, str):
            raise Rejection("M3", "checkout_hash_missing", MANDATE_SCOPE_MISMATCH)
        try:
            if issued is None:
                # The service keeps no copy of the responses it signed (each signature differs),
                # so the checkout JWT is the one the mandate embeds; M4 verifies our signature on
                # it and M5 compares its terms with the current state (docs/PROTOCOL.md Decision 37).
                embedded = chain.final.content.get("checkout_jwt")
                if embedded is None:
                    raise Rejection("M4", "checkout_jwt_absent", MERCHANT_AUTHORIZATION_MISSING)
                if not isinstance(embedded, str):
                    raise Rejection("M4", "checkout_jwt_not_text", MERCHANT_AUTHORIZATION_INVALID)
                session = hash_checkout_jwt(embedded)
            else:
                session = hash_checkout_jwt(checkout_jwt(issued))
        except (AuthorizationError, HashInputError):
            raise Rejection("M3", "session_checkout_unavailable", MANDATE_SCOPE_MISMATCH) from None
        if claim != session:
            raise Rejection("M3", "checkout_hash_mismatch", MANDATE_SCOPE_MISMATCH)
        return session

    def _m4_authorization(self, chain: VerifiedChain, session_hash: str) -> dict[str, Any]:
        jwt = chain.final.content.get("checkout_jwt")
        if jwt is None:
            raise Rejection("M4", "checkout_jwt_absent", MERCHANT_AUTHORIZATION_MISSING)
        if not isinstance(jwt, str):
            raise Rejection("M4", "checkout_jwt_not_text", MERCHANT_AUTHORIZATION_INVALID)
        parts = jwt.split(".")
        if len(parts) != 3 or not parts[0] or not parts[1]:
            raise Rejection("M4", "checkout_jwt_malformed", MERCHANT_AUTHORIZATION_INVALID)
        if not parts[2]:
            raise Rejection("M4", "signature_stripped", MERCHANT_AUTHORIZATION_MISSING)
        try:
            payload = loads_strict(decode_b64url(parts[1], "embedded checkout"))
        except (MandateError, StrictJsonError):
            raise Rejection(
                "M4", "embedded_checkout_unreadable", MERCHANT_AUTHORIZATION_INVALID
            ) from None
        if not isinstance(payload, dict):
            raise Rejection("M4", "embedded_checkout_not_object", MERCHANT_AUTHORIZATION_INVALID)
        body: dict[str, Any] = dict(payload)
        body["ap2"] = {"merchant_authorization": f"{parts[0]}..{parts[2]}"}
        try:
            verified = verify_authorization(body, self._config.published_keys)
        except AuthorizationError as error:
            code = (
                MERCHANT_AUTHORIZATION_MISSING
                if error.code == MISSING
                else MERCHANT_AUTHORIZATION_INVALID
            )
            raise Rejection("M4", "merchant_authorization_unverified", code) from None
        if verified.checkout_jwt != jwt:
            raise Rejection("M4", "embedded_checkout_not_canonical", MERCHANT_AUTHORIZATION_INVALID)
        try:
            embedded_hash = hash_checkout_jwt(jwt)
        except HashInputError:
            raise Rejection(
                "M4", "checkout_jwt_malformed", MERCHANT_AUTHORIZATION_INVALID
            ) from None
        if embedded_hash != session_hash:
            raise Rejection("M4", "embedded_checkout_is_not_this_session", MANDATE_SCOPE_MISMATCH)
        return body

    def _m5_terms(self, embedded: Mapping[str, Any], current: Checkout) -> None:
        try:
            embedded_terms = Checkout.from_ucp(embedded).terms()
        except (UcpShapeError, ValueError):
            raise Rejection("M5", "embedded_checkout_malformed", MANDATE_SCOPE_MISMATCH) from None
        difference = terms_difference(embedded_terms, current.terms())
        if difference is not None:
            raise Rejection("M5", "terms_mismatch", MANDATE_SCOPE_MISMATCH, detail=difference)

    def _m7_constraints(self, chain: VerifiedChain, current: Checkout, now: float) -> None:
        result = self._constraints.evaluate(chain=chain, checkout=current, now=now)
        if not isinstance(result, ConstraintOutcome) or result.satisfied is not True:
            ok_shape = isinstance(result, ConstraintOutcome)
            reason = result.reason if ok_shape and isinstance(result.reason, str) else "bad_result"
            unresolved = ok_shape and result.unresolved is True
            raise Rejection(
                "M7",
                "constraint_unresolved" if unresolved else "constraint_violated",
                MANDATE_SCOPE_MISMATCH,
                detail=reason[:80],
            )

    def _m8_reserve(
        self, chain: VerifiedChain, mode: str, session_hash: str, current: Checkout
    ) -> Reservation:
        first, final = chain.links[0], chain.final
        scope = None
        if mode == MODE_AUTONOMOUS and first.cnf_thumbprint and final.audience and final.nonce:
            scope = (first.cnf_thumbprint, final.audience, final.nonce)
        elif mode == MODE_AUTONOMOUS:
            raise Rejection("M8", "nonce_scope_unavailable", MANDATE_INVALID_SIGNATURE)
        try:
            return self._store.reserve(
                ReservationRequest(current.id, session_hash, first.digest, scope)
            )
        except AlreadyReservedError as error:
            raise Rejection("M8", error.reason, MANDATE_SCOPE_MISMATCH) from None

    # ---- entry point ----

    def completion_receipt(self, checkout_mandate: str, order_id: str) -> str:
        """A signed Success Checkout Receipt issued when the order completes.

        The acceptance receipt is returned only to the first `complete` call, so a completion that
        needs a payer approval first cannot carry it. This one is made from the same inputs: the
        `reference` is the digest of the final link of the presented Checkout Mandate (the same
        function as at acceptance) and `order_id` is the checkout id. Only call it for a checkout
        whose payment the capture gate confirmed.
        """
        return receipts.sign_receipt(
            receipts.success_claims(
                issuer=self._config.issuer,
                iat=int(self._clock()),
                reference=receipts.reference_for(checkout_mandate),
                order_id=order_id,
            ),
            self._config.signing_key,
        )

    def verify(
        self, *, mandate: object, issued_checkout: Mapping[str, Any] | None, current: Checkout
    ) -> Accepted | Rejected:
        """Verify `mandate` for the session whose last signed response is `issued_checkout`
        (None: the checkout JWT embedded in the mandate stands in for it, see `_m3_hash`).

        `current` is the session state from the store. Raises `DecisionLogError` if the decision
        could not be logged; no result exists in that case.
        """
        now = self._clock()
        reservation: Reservation | None = None
        try:
            if mandate is None or mandate == "":
                raise Rejection("M1", "mandate_missing", MANDATE_REQUIRED)
            if not isinstance(mandate, str):
                raise Rejection("M2", "chain:structure_not_text", MANDATE_INVALID_SIGNATURE)
            chain, mode = self._m2_chain(mandate)
            session_hash = self._m3_hash(chain, issued_checkout, current)
            embedded = self._m4_authorization(chain, session_hash)
            self._m5_terms(embedded, current)
            self._m7_constraints(chain, current, now)
            reservation = self._m8_reserve(chain, mode, session_hash, current)
            reference = chain.final.digest
            receipt = receipts.sign_receipt(
                receipts.success_claims(
                    issuer=self._config.issuer,
                    iat=int(now),
                    reference=reference,
                    order_id=current.id,
                ),
                self._config.signing_key,
            )
            self._log.record(
                kind=KIND_ACCEPTED,
                checkout_id=current.id,
                payload={
                    "result": "accepted",
                    "mode": mode,
                    "checkout_hash": session_hash,
                    "reference": reference,
                    "mandate_digest": chain.links[0].digest,
                },
            )
            return Accepted(receipt, reservation, chain, mode, session_hash, reference)
        except Rejection as rejection:
            return self._reject(rejection, mandate, current)
        except DecisionLogError:
            if reservation is not None:
                self._store.abort(reservation)
            raise
        except Exception:  # noqa: BLE001 - INV-10: anything unexpected is a rejection, not a pass
            if reservation is not None:
                self._store.abort(reservation)
            return self._reject(
                Rejection("M2", "internal_error", MANDATE_INVALID_SIGNATURE), mandate, current
            )

    def _reject(self, rejection: Rejection, presented: object, current: Checkout) -> Rejected:
        reference = receipts.reference_for(presented)
        receipt = receipts.sign_receipt(
            receipts.error_claims(
                issuer=self._config.issuer,
                iat=int(self._clock()),
                reference=reference,
                error=rejection.ucp_code,
                description=rejection.reason,
            ),
            self._config.signing_key,
        )
        self._log.record(
            kind=KIND_REJECTED,
            checkout_id=current.id,
            payload={
                "result": "rejected",
                "step": rejection.step,
                "reason": rejection.reason,
                "ucp_code": rejection.ucp_code,
                "detail": rejection.detail,
                "reference": reference,
            },
        )
        return Rejected(
            receipt,
            [rejection.message()],
            rejection.step,
            rejection.reason,
            rejection.ucp_code,
            rejection.detail,
            reference,
        )
