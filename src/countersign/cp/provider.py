"""Credential Provider role: verify the Payment Mandate, reserve, create the PayPal order, authorize.

The capture gate is P2.5; nothing here captures. Steps, with the failure behaviour of each
(docs/PROTOCOL.md Decisions 34 to 39):

C1 to C4  `verify_payment` (pure). A failure here has reserved nothing.
C5 + C6   ONE database transaction: lock the open mandate's budget row (`FOR UPDATE`), read the
          spend view (which excludes this presentation), evaluate the constraints, then reserve
          the single-use keys, the spend and the payment attempt, and append the decision to the
          log. Two parallel presentations queue on the row lock, so the second reads a view that
          includes the first and cannot pass the same headroom twice (INV-6, INV-7). Any
          rejection or exception rolls back everything but the rejection's log entry.
C7        Create the PayPal order (`intent` AUTHORIZE, `invoice_id` the checkout id, `custom_id`
          the evidence reference, the deterministic Request-Id the client derives). Then either
          the payer approves on PayPal (redirect mode) or, in the sandbox, the wallet vaulted
          earlier is charged without approval (vault mode).
C8        `finish`: re-fetch the live order, require APPROVED, re-derive its terms and authorize only
          on an exact match (Decision 11, the pre-authorize check), then re-fetch and verify the
          authorization. The ablation `ABL_NO_PREAUTH_CHECK` skips those term checks so the
          baseline behaviour can be shown; it is refused when `APP_ENV=demo`.

Fail closed and clean up (INV-10). After the reservation, any exception, PayPal error, schema error
or log failure runs `_cleanup`: an authorization that exists is voided and its final state is
confirmed with a GET (a void response body can be incomplete); the spend entry is voided and the
open mandate released, so the agent can retry with a new checkout; an order that was created but never
approved is abandoned, never authorized. If PayPal's state cannot be confirmed, the attempt is
marked `unresolved` and the budget and the mandate stay reserved: money might be held, so nothing is
released until `reconcile` reads PayPal. `recover` finishes attempts that a crash left behind.

Idempotency (INV-11). The client derives the Request-Id from the checkout id and the operation,
so a retry or a double submit replays the first result. `finish` claims the attempt with a
conditional update (`order_created` to `authorizing`), so two parallel finishes authorize once.

Log before respond (INV-12). Each decision, and each PayPal call before and after it is made, is
appended to the hash-chained log. A failed append raises `DecisionLogError`, which triggers the
cleanup and fails the operation; a PayPal call whose "started" entry cannot be written is not made.
"""

from __future__ import annotations

import secrets
import time
from collections.abc import Callable
from dataclasses import dataclass
from typing import Any

import structlog
from sqlalchemy import Connection, Engine, select, update

from countersign.canonical.models import Checkout
from countersign.canonical.money import Money
from countersign.constraints import PaymentConstraintEvaluator
from countersign.cp.config import CpConfig
from countersign.cp.evidence import custom_id_for, evidence_reference
from countersign.cp.ledger import SpendLedger
from countersign.cp.rejection import MANDATE_SCOPE_MISMATCH, PAYMENT_FAILED, CpRejection
from countersign.cp.verify import VerifiedPayment, verify_payment
from countersign.ledger import store as ledger_store
from countersign.merchant import receipts
from countersign.merchant.constraints import ConstraintOutcome
from countersign.merchant.decision_log import DecisionLogError
from countersign.merchant.pg_reservations import PostgresReservationStore
from countersign.merchant.policy import policy_hash
from countersign.merchant.reservations import (
    AlreadyReservedError,
    Reservation,
    ReservationRequest,
)
from countersign.paypal.client import PayPalClient
from countersign.paypal.errors import PayPalError
from countersign.paypal.models import (
    Authorization,
    ExperienceContext,
    Order,
    VaultCharge,
    VaultEnroll,
)
from countersign.paypal.translate import (
    OrderTerms,
    TranslationError,
    expected_terms,
    order_request_from_checkout,
    paypal_order_to_canonical_terms,
)
from countersign.tables import payer_vault, payment_attempts

log = structlog.get_logger("countersign.cp")

FINAL_STATES = frozenset({"abandoned", "voided", "failed"})
PAYMENT_RECEIPT_TYP = receipts.PAYMENT_RECEIPT_TYP


def now_us() -> int:
    return time.time_ns() // 1000


@dataclass(frozen=True)
class CpRejected:
    receipt: str
    messages: list[dict[str, Any]]
    step: str
    reason: str
    ucp_code: str
    detail: str
    reference: str


@dataclass(frozen=True)
class CpApprovalRequired:
    checkout_id: str
    order_id: str
    approval_url: str


@dataclass(frozen=True)
class CpPending:
    """`finish` was called before the payer approved. Nothing changed."""

    checkout_id: str
    order_id: str
    status: str


@dataclass(frozen=True)
class CpAuthorized:
    checkout_id: str
    order_id: str
    authorization_id: str
    amount: Money
    custom_id: str
    mode: str


CpOutcome = CpRejected | CpApprovalRequired | CpPending | CpAuthorized


@dataclass(frozen=True)
class Attempt:
    checkout_id: str
    reservation: Reservation
    spend_id: str
    mode: str  # redirect | vault
    custom_id: str
    open_digest: str
    payment_reference: str
    principal: str | None = None


def check_terms(
    order: Order, current: Checkout, *, custom_id: str, payee_merchant_id: str
) -> str | None:
    """None if the live order's re-derived terms equal the checkout's; else a fixed reason."""
    try:
        live: OrderTerms = paypal_order_to_canonical_terms(
            order, line_ids=[line.id for line in current.line_items]
        )
        wanted = expected_terms(current, payee_merchant_id=payee_merchant_id, custom_id=custom_id)
    except TranslationError:
        return "order_terms_unreadable"
    return None if live.terms_hash() == wanted.terms_hash() else "order_terms_differ"


class CredentialProvider:
    def __init__(
        self,
        config: CpConfig,
        engine: Engine,
        paypal: PayPalClient,
        *,
        clock: Callable[[], float] = time.time,
        clock_us: Callable[[], int] = now_us,
        evaluator: PaymentConstraintEvaluator | None = None,
        vault_lookup: Callable[[str], str | None] | None = None,
        new_id: Callable[[], str] = lambda: "sp_" + secrets.token_urlsafe(16),
    ) -> None:
        self._config = config
        self._engine = engine
        self._paypal = paypal
        self._clock = clock
        self._clock_us = clock_us
        self._evaluator = evaluator or PaymentConstraintEvaluator()
        self._store = PostgresReservationStore(engine, "cp", clock_us)
        self._ledger = SpendLedger(clock_us)
        self._vault_lookup = vault_lookup or self._vault_from_table
        self._new_id = new_id
        self._policy_hash = policy_hash()

    # ------------------------------------------------------------------ logging

    def _log(self, conn: Connection | None, kind: str, checkout_id: str, **payload: Any) -> None:
        try:
            if conn is None:
                with self._engine.begin() as own:
                    self._append(own, kind, checkout_id, payload)
            else:
                self._append(conn, kind, checkout_id, payload)
        except Exception as error:
            raise DecisionLogError(type(error).__name__) from error

    def _append(
        self, conn: Connection, kind: str, checkout_id: str, payload: dict[str, Any]
    ) -> None:
        ledger_store.append(
            conn,
            kind=kind,
            payload=payload,
            policy_hash=self._policy_hash,
            checkout_id=checkout_id,
            ts_us=self._clock_us(),
        )

    def _paypal_call(self, checkout_id: str, op: str, call: Callable[[], Any]) -> Any:
        """Log the call before it is made and its outcome after (INV-12)."""
        self._log(None, f"cp.paypal.{op}.started", checkout_id)
        try:
            result = call()
        except PayPalError as error:
            self._log(
                None, f"cp.paypal.{op}.failed", checkout_id,
                error=type(error).__name__, status=error.status, name=error.name,
                debug_id=error.debug_id, outcome_unknown=error.outcome_unknown,
            )  # fmt: skip
            raise
        self._log(None, f"cp.paypal.{op}.finished", checkout_id)
        return result

    # ------------------------------------------------------------------ attempts

    def _row(self, checkout_id: str) -> Any:
        with self._engine.connect() as conn:
            return conn.execute(
                select(payment_attempts).where(payment_attempts.c.checkout_id == checkout_id)
            ).first()

    def _set_state(
        self, checkout_id: str, state: str, *, expect: tuple[str, ...] | None = None, **values: Any
    ) -> bool:
        """Move an attempt to `state` (optionally only from `expect`). True if a row changed."""
        stmt = update(payment_attempts).where(payment_attempts.c.checkout_id == checkout_id)
        if expect is not None:
            stmt = stmt.where(payment_attempts.c.state.in_(expect))
        with self._engine.begin() as conn:
            result = conn.execute(stmt.values(state=state, updated_us=self._clock_us(), **values))
            return bool(result.rowcount == 1)

    def _vault_from_table(self, principal: str) -> str | None:
        with self._engine.connect() as conn:
            row = conn.execute(
                select(payer_vault.c.vault_id).where(payer_vault.c.principal == principal)
            ).first()
        return None if row is None else str(row.vault_id)

    def _remember_vault(self, principal: str | None, vault_id: str | None) -> None:
        if not principal or not vault_id:
            return
        from sqlalchemy.dialects.postgresql import insert as pg_insert

        with self._engine.begin() as conn:
            conn.execute(
                pg_insert(payer_vault)
                .values(principal=principal, vault_id=vault_id, created_us=self._clock_us())
                .on_conflict_do_nothing(index_elements=["principal"])
            )

    # ------------------------------------------------------------------ C5 and C6

    def _reserve(
        self, verified: VerifiedPayment, current: Checkout, custom_id: str, mode: str, now: float
    ) -> Attempt:
        """Constraints and reservation in one transaction. Raises `CpRejection` after logging it."""
        rejection: CpRejection | None = None
        attempt: Attempt | None = None
        currency, amount = verified.total.currency, verified.total.minor
        with self._engine.begin() as conn:
            self._ledger.lock(conn, verified.open_payment_digest, currency)
            spend = self._ledger.view(conn, verified.open_payment_digest, currency)
            result = self._evaluator.evaluate_payment(
                payment_chain=verified.payment_chain,
                checkout_chain=verified.checkout_chain,
                spend=spend,
                now=now,
            )
            if not isinstance(result, ConstraintOutcome) or result.satisfied is not True:
                ok_shape = isinstance(result, ConstraintOutcome)
                unresolved = ok_shape and result.unresolved is True
                detail = (
                    result.reason[:80] if ok_shape and isinstance(result.reason, str) else "bad"
                )
                rejection = CpRejection(
                    "C5",
                    "constraint_unresolved" if unresolved else "constraint_violated",
                    MANDATE_SCOPE_MISMATCH,
                    detail,
                )
            else:
                scope = None
                if verified.principal and verified.payment_chain.final.nonce:
                    scope = (
                        verified.principal,
                        self._config.audience,
                        verified.payment_chain.final.nonce,
                    )
                try:
                    reservation = self._store.reserve_in(
                        conn,
                        ReservationRequest(
                            current.id, verified.session_hash, verified.open_payment_digest, scope
                        ),
                    )
                except AlreadyReservedError as error:
                    rejection = CpRejection("C6", error.reason, MANDATE_SCOPE_MISMATCH)
                else:
                    spend_id = self._new_id()
                    self._ledger.reserve(
                        conn,
                        spend_id=spend_id,
                        digest=verified.open_payment_digest,
                        checkout_id=current.id,
                        amount_minor=amount,
                        currency=currency,
                    )
                    now_us_ = self._clock_us()
                    conn.execute(
                        payment_attempts.insert().values(
                            checkout_id=current.id,
                            reservation_handle=reservation.handle,
                            spend_id=spend_id,
                            mandate_digest=verified.open_payment_digest,
                            state="reserved",
                            mode=mode,
                            custom_id=custom_id,
                            principal=verified.principal,
                            created_us=now_us_,
                            updated_us=now_us_,
                        )
                    )
                    attempt = Attempt(
                        current.id, reservation, spend_id, mode, custom_id,
                        verified.open_payment_digest, verified.payment_reference,
                        verified.principal,
                    )  # fmt: skip
                    self._log(
                        conn, "cp.reserved", current.id,
                        mode=mode, amount_minor=amount, currency=currency,
                        spent_captured=spend.captured_minor, spent_in_flight=spend.in_flight_minor,
                        mandate_digest=verified.open_payment_digest,
                        reference=verified.payment_reference,
                    )  # fmt: skip
            if rejection is not None:
                self._log(
                    conn, "cp.payment_mandate.rejected", current.id,
                    step=rejection.step, reason=rejection.reason, detail=rejection.detail,
                    ucp_code=rejection.ucp_code,
                )  # fmt: skip
        if rejection is not None:
            raise rejection
        assert attempt is not None
        return attempt

    # ------------------------------------------------------------------ entry points

    def start(
        self,
        *,
        payment_token: object,
        checkout_mandate: object,
        current: Checkout,
    ) -> CpOutcome:
        """Verify, reserve and create the PayPal order. Raises `DecisionLogError` if a decision
        cannot be logged (after cleaning up)."""
        now = self._clock()
        attempt: Attempt | None = None
        try:
            try:
                verified = verify_payment(
                    payment_token=payment_token,
                    checkout_mandate=checkout_mandate,
                    current=current,
                    platform_key=self._config.platform_key,
                    payee_id=self._config.payee["id"],
                    audience=self._config.audience,
                    checkout_audience=self._config.checkout_audience,
                    clock=self._clock,
                )
                custom_id = custom_id_for(
                    evidence_reference(
                        checkout_hash=verified.session_hash,
                        checkout_mandate_digest=verified.checkout_reference,
                        payment_mandate_digest=verified.payment_reference,
                    )
                )
                vault_id = self._vault_id_for(verified)
                mode = "vault" if vault_id else "redirect"
                attempt = self._reserve(verified, current, custom_id, mode, now)
            except CpRejection as rejection:
                return self._reject(rejection, payment_token, current.id)
            return self._create_order(attempt, verified, current, vault_id)
        except DecisionLogError:
            if attempt is not None:
                self._cleanup(attempt.checkout_id, "log_failure")
            raise
        except Exception:  # noqa: BLE001 - INV-10: anything unexpected after this point cleans up
            if attempt is not None:
                self._cleanup(attempt.checkout_id, "internal_error")
            return self._reject(
                CpRejection("C7", "internal_error", PAYMENT_FAILED),
                payment_token,
                current.id,
            )

    def _vault_id_for(self, verified: VerifiedPayment) -> str | None:
        if verified.principal is None:
            return None
        return self._vault_lookup(verified.principal)

    def _create_order(
        self, attempt: Attempt, verified: VerifiedPayment, current: Checkout, vault_id: str | None
    ) -> CpOutcome:
        checkout_id = attempt.checkout_id
        try:
            request = order_request_from_checkout(
                current,
                custom_id=attempt.custom_id,
                experience_context=ExperienceContext(
                    self._config.return_url, self._config.cancel_url
                ),
            )
            if vault_id:
                from dataclasses import replace

                request = replace(request, vault=VaultCharge(vault_id))
            elif self._config.enroll_vault:
                from dataclasses import replace

                request = replace(request, vault=VaultEnroll())
            created = self._paypal_call(
                checkout_id, "create_order", lambda: self._paypal.create_order(checkout_id, request)
            )
            self._set_state(checkout_id, "order_created", order_id=created.resource_id)
            self._log(None, "cp.order_created", checkout_id, order_id=created.resource_id,
                      mode=attempt.mode)  # fmt: skip
            if attempt.mode == "vault":
                return self._after_vault_create(attempt, verified, current, created.resource_id)
            if created.approval_url is None:
                raise CpRejection("C7", "no_approval_link", PAYMENT_FAILED)
            return CpApprovalRequired(checkout_id, created.resource_id, created.approval_url)
        except CpRejection as rejection:
            self._cleanup(checkout_id, rejection.reason)
            return self._reject(rejection, "", checkout_id, attempt.payment_reference)
        except DecisionLogError:
            self._cleanup(checkout_id, "log_failure")
            raise
        except (PayPalError, TranslationError, ValueError) as error:
            self._cleanup(checkout_id, f"c7:{type(error).__name__}")
            reason = f"paypal_error:{type(error).__name__}"
            return self._reject(
                CpRejection("C7", reason, PAYMENT_FAILED), "", checkout_id,
                attempt.payment_reference,
            )  # fmt: skip

    def _after_vault_create(
        self, attempt: Attempt, verified: VerifiedPayment, current: Checkout, order_id: str
    ) -> CpOutcome:
        """Vault mode: PayPal creates and authorizes in one call (sandbox, docs 4.7)."""
        order = self._paypal_call(
            attempt.checkout_id, "get_order", lambda: self._paypal.get_order(order_id)
        )
        if not order.authorizations:
            raise CpRejection("C7", "vault_requires_payer_action", PAYMENT_FAILED)
        return self._verify_and_record_authorization(attempt, current, order, mode="vault")

    def finish(self, *, checkout_id: str, current: Checkout) -> CpOutcome:
        """Continue after the payer approved on PayPal: pre-authorize check, then authorize."""
        row = self._row(checkout_id)
        if row is None:
            return self._reject(
                CpRejection("C8", "no_payment_attempt", MANDATE_SCOPE_MISMATCH), "", checkout_id
            )
        if row.state == "authorized":
            return CpAuthorized(
                checkout_id, row.order_id, row.authorization_id, self._total(current),
                row.custom_id, row.mode,
            )  # fmt: skip
        if row.state == "authorizing":
            return CpPending(checkout_id, row.order_id, "AUTHORIZING")
        if row.state != "order_created" or row.mode != "redirect":
            return self._reject(
                CpRejection("C8", "attempt_not_pending", MANDATE_SCOPE_MISMATCH), "", checkout_id
            )
        attempt = self._attempt_from_row(row)
        order_id: str = row.order_id
        try:
            order = self._paypal_call(
                checkout_id, "get_order", lambda: self._paypal.get_order(order_id)
            )
            if order.status in ("CREATED", "PAYER_ACTION_REQUIRED"):
                return CpPending(checkout_id, order_id, order.status)
            if order.status != "APPROVED" or order.authorizations:
                raise CpRejection("C8", f"order_not_approvable:{order.status.lower()}"[:60],
                                  MANDATE_SCOPE_MISMATCH)  # fmt: skip
            if not self._config.ablations.no_preauth_check:
                problem = check_terms(
                    order, current, custom_id=row.custom_id,
                    payee_merchant_id=self._config.paypal_payee_merchant_id,
                )  # fmt: skip
                if problem is not None:
                    raise CpRejection("C8", f"preauthorize_{problem}", MANDATE_SCOPE_MISMATCH)
            if not self._set_state(checkout_id, "authorizing", expect=("order_created",)):
                return CpPending(checkout_id, order_id, "AUTHORIZING")
            self._authorize(checkout_id, order_id)
            authorized = self._paypal_call(
                checkout_id, "get_order", lambda: self._paypal.get_order(order_id)
            )
            return self._verify_and_record_authorization(
                attempt, current, authorized, mode="redirect"
            )
        except CpRejection as rejection:
            self._cleanup(checkout_id, rejection.reason)
            return self._reject(rejection, "", checkout_id, attempt.payment_reference)
        except DecisionLogError:
            self._cleanup(checkout_id, "log_failure")
            raise
        except Exception as error:  # noqa: BLE001 - INV-10
            self._cleanup(checkout_id, f"c8:{type(error).__name__}")
            return self._reject(
                CpRejection("C8", "internal_error", PAYMENT_FAILED), "", checkout_id,
                attempt.payment_reference,
            )  # fmt: skip

    def _authorize(self, checkout_id: str, order_id: str) -> None:
        """Authorize with the deterministic Request-Id; resolve an unknown outcome by GET first."""
        try:
            self._paypal_call(
                checkout_id,
                "authorize",
                lambda: self._paypal.authorize_order(checkout_id, order_id),
            )
        except PayPalError as error:
            if not error.outcome_unknown:
                raise
            order = self._paypal_call(
                checkout_id, "get_order", lambda: self._paypal.get_order(order_id)
            )
            if order.authorizations:
                return  # it took effect
            # It did not (yet). One more attempt with the SAME Request-Id replays the first result
            # if the first call lands late, instead of creating a second authorization.
            self._paypal_call(
                checkout_id,
                "authorize",
                lambda: self._paypal.authorize_order(checkout_id, order_id),
            )

    def _verify_and_record_authorization(
        self, attempt: Attempt, current: Checkout, order: Order, *, mode: str
    ) -> CpOutcome:
        checkout_id = attempt.checkout_id
        auths = order.authorizations
        if len(auths) != 1:
            raise CpRejection("C8", "authorization_count", MANDATE_SCOPE_MISMATCH)
        # Record the id first so a cleanup from here on can find and void it.
        self._set_state(checkout_id, "authorizing", authorization_id=auths[0].id,
                        expect=("order_created", "authorizing"))  # fmt: skip
        authorization: Authorization = self._paypal_call(
            checkout_id, "get_authorization", lambda: self._paypal.get_authorization(auths[0].id)
        )
        total = self._total(current)
        if authorization.status != "CREATED":
            raise CpRejection("C8", "authorization_not_created", MANDATE_SCOPE_MISMATCH)
        if not self._config.ablations.no_preauth_check:
            if (
                authorization.amount != total
                or authorization.invoice_id != checkout_id
                or authorization.custom_id != attempt.custom_id
            ):
                raise CpRejection("C8", "authorization_differs", MANDATE_SCOPE_MISMATCH)
            problem = check_terms(
                order, current, custom_id=attempt.custom_id,
                payee_merchant_id=self._config.paypal_payee_merchant_id,
            )  # fmt: skip
            if problem is not None:
                raise CpRejection("C8", f"postauthorize_{problem}", MANDATE_SCOPE_MISMATCH)
        if mode == "redirect" and self._config.enroll_vault:
            self._remember_vault(attempt.principal, order.vault_id)
        if not self._set_state(checkout_id, "authorized", expect=("authorizing",)):
            raise CpRejection("C8", "attempt_state_changed", MANDATE_SCOPE_MISMATCH)
        self._log(
            None, "cp.authorized", checkout_id,
            order_id=order.id, authorization_id=authorization.id, mode=mode,
            amount=f"{total.currency}:{total.minor}", custom_id=attempt.custom_id,
            reference=attempt.payment_reference,
        )  # fmt: skip
        return CpAuthorized(
            checkout_id, order.id, authorization.id, authorization.amount, attempt.custom_id, mode
        )

    @staticmethod
    def _total(current: Checkout) -> Money:
        return next(t.amount for t in current.totals if t.type == "total")

    def _attempt_from_row(self, row: Any) -> Attempt:
        with self._engine.connect() as conn:
            reservation = self._store.load(conn, row.reservation_handle)
        if reservation is None:
            raise RuntimeError("the reservation of a payment attempt is missing")
        return Attempt(
            row.checkout_id, reservation, row.spend_id, row.mode, row.custom_id,
            row.mandate_digest, "", row.principal,
        )  # fmt: skip

    def attempt_state(self, checkout_id: str) -> str | None:
        """The state of the payment attempt of a checkout, or None if there is none."""
        row = self._row(checkout_id)
        return None if row is None else str(row.state)

    # ------------------------------------------------------------------ cleanup and recovery

    def _void_and_confirm(self, checkout_id: str, authorization_id: str) -> bool:
        """Void an authorization and confirm with a GET that it is voided."""
        try:
            self._paypal_call(
                checkout_id, "void",
                lambda: self._paypal.void_authorization(checkout_id, authorization_id),
            )  # fmt: skip
        except PayPalError:
            pass  # already voided, or unknown: the GET below decides
        try:
            current = self._paypal_call(
                checkout_id, "get_authorization",
                lambda: self._paypal.get_authorization(authorization_id),
            )  # fmt: skip
        except PayPalError:
            return False
        return bool(current.status == "VOIDED")

    def _cleanup(self, checkout_id: str, reason: str) -> None:
        """Void what exists, release what was reserved, or mark the attempt unresolved."""
        row = self._row(checkout_id)
        if row is None or row.state in FINAL_STATES:
            return
        authorization_ids: list[str] = [row.authorization_id] if row.authorization_id else []
        unresolved = False
        if row.order_id and not authorization_ids:
            try:
                order = self._paypal_call(
                    checkout_id, "get_order", lambda: self._paypal.get_order(row.order_id)
                )
                authorization_ids = [a.id for a in order.authorizations]
            except (PayPalError, DecisionLogError):
                unresolved = True  # cannot tell whether PayPal holds an authorization
        for authorization_id in authorization_ids:
            try:
                if not self._void_and_confirm(checkout_id, authorization_id):
                    unresolved = True
            except DecisionLogError:
                unresolved = True
        final = "voided" if authorization_ids else "abandoned"
        try:
            with self._engine.begin() as conn:
                if unresolved:
                    self._set_state_in(conn, checkout_id, "unresolved")
                else:
                    self._ledger.void(conn, row.spend_id)
                    reservation = self._store.load(conn, row.reservation_handle)
                    if reservation is not None:
                        self._store.release_in(conn, reservation)
                    self._set_state_in(conn, checkout_id, final)
                self._append(
                    conn, "cp.cleanup", checkout_id,
                    {"reason": reason[:80], "result": "unresolved" if unresolved else final,
                     "authorizations": len(authorization_ids)},
                )  # fmt: skip
        except Exception:  # noqa: BLE001 - a cleanup that cannot finish leaves the attempt as is
            log.error("cp_cleanup_incomplete", checkout_id=checkout_id)
            self._set_state(checkout_id, "unresolved")

    def _set_state_in(self, conn: Connection, checkout_id: str, state: str) -> None:
        conn.execute(
            update(payment_attempts)
            .where(payment_attempts.c.checkout_id == checkout_id)
            .values(state=state, updated_us=self._clock_us())
        )

    def recover(self, *, older_than_us: int) -> list[str]:
        """Settle attempts a crash left behind: never-approved orders are abandoned, in-doubt
        authorizations are reconciled with PayPal. Returns the checkout ids touched."""
        cutoff = self._clock_us() - older_than_us
        with self._engine.connect() as conn:
            rows = conn.execute(
                select(payment_attempts.c.checkout_id, payment_attempts.c.state).where(
                    payment_attempts.c.state.in_(
                        ("reserved", "order_created", "authorizing", "unresolved")
                    ),
                    payment_attempts.c.updated_us < cutoff,
                )
            ).all()
        touched = []
        for checkout_id, state in rows:
            self._cleanup(checkout_id, f"recover:{state}")
            touched.append(checkout_id)
        return touched

    # ------------------------------------------------------------------ rejection

    def _reject(
        self, rejection: CpRejection, presented: object, checkout_id: str, reference: str = ""
    ) -> CpRejected:
        reference = reference or receipts.reference_for(presented)
        receipt = receipts.sign_receipt(
            {
                "status": receipts.ERROR,
                "iss": self._config.issuer,
                "iat": int(self._clock()),
                "reference": reference,
                "payment_id": checkout_id,
                "error": rejection.ucp_code,
                "error_description": rejection.reason,
            },
            self._config.signing_key,
            PAYMENT_RECEIPT_TYP,
        )
        # A rejection raised by `_reserve` was logged there, in the same transaction.
        if rejection.step not in ("C5", "C6"):
            self._log(
                None, "cp.payment_mandate.rejected", checkout_id,
                step=rejection.step, reason=rejection.reason, detail=rejection.detail,
                ucp_code=rejection.ucp_code,
            )  # fmt: skip
        return CpRejected(
            receipt, [rejection.message()], rejection.step, rejection.reason,
            rejection.ucp_code, rejection.detail, reference,
        )  # fmt: skip
