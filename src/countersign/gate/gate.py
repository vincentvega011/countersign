"""The capture gate (Merchant Payment Processor role): the only code that may capture.

Security reasoning. Money moves only here, and only after every check below passed on PayPal state
fetched for this very run (INV-4). The steps, each logged with its code before the next runs
(INV-12):

G-FETCH    GET the live order and authorization. Nothing is read from a cache; `LiveState` is sealed.
G-STATUS   the authorization is `CREATED`, unexpired (with a skew), alone on its order, uncaptured.
G-REVERSE  re-derive canonical terms from the live order with the P1 reverse translation.
G-TERMS    the re-derived terms equal the signed checkout's; `invoice_id` and `custom_id` equal what
           the Credential Provider set.
G-AMOUNT   the authorized amount, and the order's, equal the checkout total exactly.
G-MANDATE  the Payment and Checkout Mandates verify AGAIN from the stored tokens at the current
           time, neither open mandate is revoked, and both single-use reservations are still held
           by this checkout.
G-BUDGET   the budget still holds under the ledger view, excluding this checkout's own reservation.
G-LOCK     the principal lock policy (a `LockPolicy`; the default denies) still allows the payment.

Pass: mint the sealed `CaptureApproval`, capture the whole authorization with `final_capture` true,
then GET the capture and the authorization and require `COMPLETED` and `CAPTURED`. Capture and void
response bodies can be incomplete, so a capture that is not confirmed is never reported as success.
Only then are the spend entry, both reservations and the attempt finalized, in one transaction, and
a signed Success Payment Receipt issued.

Fail (INV-10): any step failure, exception, timeout, unparseable body or log failure ends in
`_fail`. It reads PayPal first and lets PayPal decide what is true: a captured authorization is
settled as captured (never voided: PayPal refuses it), a `CREATED` one is voided and the void is
confirmed by a GET, a `VOIDED` one is released. Only then are the spend entry and both reservations
released (the open mandate can be used with a NEW checkout; this checkout's id, hash and nonce stay
consumed) and a signed rejection receipt issued. If PayPal cannot be read or the void cannot be
confirmed, the attempt becomes `unresolved` and everything stays reserved, because money might be
held.

Exactly once. `GateStore.claim` is a single conditional UPDATE, so of two gates on one checkout one
runs and the other returns `GatePending` without calling PayPal. The Request-Ids of capture and void
are deterministic (INV-11). A claim older than `claim_stale_us` can be taken over by a retry, which
starts again from G-FETCH: it finds either an uncaptured authorization (and captures with the same
Request-Id) or a captured one (and finalizes without capturing again).

Ablation `ABL_NO_GATE` skips every check and captures what the authorization says, as a naive
integration would. It is refused when `APP_ENV=demo` (`countersign.ablations`).
"""

from __future__ import annotations

import time
from collections.abc import Callable
from dataclasses import dataclass
from datetime import UTC, datetime
from functools import partial
from typing import Any

import structlog
from sqlalchemy import Connection

from countersign.canonical.models import Checkout
from countersign.canonical.money import Money
from countersign.constraints import PaymentConstraintEvaluator
from countersign.cp.config import CpConfig
from countersign.cp.rejection import (
    MANDATE_EXPIRED,
    MANDATE_REQUIRED,
    MANDATE_SCOPE_MISMATCH,
    PAYMENT_FAILED,
    CpRejection,
)
from countersign.cp.verify import VerifiedPayment, verify_payment
from countersign.gate import steps
from countersign.gate.outcomes import (
    G_AMOUNT,
    G_BUDGET,
    G_CAPTURE,
    G_FETCH,
    G_LOCK,
    G_MANDATE,
    G_REVERSE,
    G_STATUS,
    G_TERMS,
    GateFailure,
    GateNotApplicable,
    GateOutcome,
    GatePassed,
    GatePending,
    GateRejected,
    GateUnresolved,
)
from countersign.gate.policy import DenyAllLockPolicy, LockDecision, LockPolicy, LockQuery
from countersign.gate.store import IN_PROGRESS, GateStore
from countersign.ledger import store as ledger_store
from countersign.merchant import receipts
from countersign.merchant.constraints import ConstraintOutcome
from countersign.merchant.decision_log import DecisionLogError
from countersign.merchant.policy import policy_hash
from countersign.paypal.approval import mint_capture_approval
from countersign.paypal.client import PayPalClient
from countersign.paypal.errors import PayPalError

log = structlog.get_logger("countersign.gate")

_CONTENT: dict[str, str] = {
    PAYMENT_FAILED: "The payment could not be processed.",
    MANDATE_EXPIRED: "The payment mandate has expired.",
    MANDATE_SCOPE_MISMATCH: "The payment mandate no longer allows this payment.",
    MANDATE_REQUIRED: "The checkout requires an AP2 payment mandate.",
}
_SEVERITY: dict[str, str] = {
    PAYMENT_FAILED: "recoverable",
    MANDATE_EXPIRED: "unrecoverable",
    MANDATE_SCOPE_MISMATCH: "recoverable",
    MANDATE_REQUIRED: "recoverable",
}


def now_us() -> int:
    return time.time_ns() // 1000


def ucp_code_for(code: str, reason: str) -> str:
    """The UCP error code a gate failure is reported with (docs/PROTOCOL.md Decision 41)."""
    if code == G_MANDATE:
        return MANDATE_EXPIRED if "expired" in reason else MANDATE_SCOPE_MISMATCH
    if code == G_BUDGET:
        return MANDATE_SCOPE_MISMATCH
    if code == G_LOCK:
        return MANDATE_REQUIRED
    return PAYMENT_FAILED


def _message(ucp_code: str) -> dict[str, Any]:
    return {
        "type": "error",
        "code": ucp_code,
        "content": _CONTENT[ucp_code],
        "severity": _SEVERITY[ucp_code],
    }


@dataclass
class _Run:
    """The state of one call of the gate. Never shared between calls."""

    checkout_id: str
    current: Checkout | None
    row: Any
    step: str = G_FETCH
    verified: VerifiedPayment | None = None


class CaptureGate:
    def __init__(
        self,
        config: CpConfig,
        engine: Any,
        paypal: PayPalClient,
        lock_policy: LockPolicy | None = None,
        *,
        clock: Callable[[], float] = time.time,
        clock_us: Callable[[], int] = now_us,
        paypal_now: Callable[[], datetime] = lambda: datetime.now(UTC),
        evaluator: PaymentConstraintEvaluator | None = None,
        expiry_skew_s: int = 60,
        claim_stale_us: int = 60_000_000,
    ) -> None:
        self._config = config
        self._engine = engine
        self._paypal = paypal
        self._lock: LockPolicy = lock_policy if lock_policy is not None else DenyAllLockPolicy()
        self._clock = clock
        self._clock_us = clock_us
        self._paypal_now = paypal_now
        self._evaluator = evaluator or PaymentConstraintEvaluator()
        self._skew = expiry_skew_s
        self._stale_us = claim_stale_us
        self._store = GateStore(engine, clock_us)
        self._policy_hash = policy_hash()

    # ------------------------------------------------------------------ logging

    def _append(
        self, conn: Connection, kind: str, checkout_id: str, payload: dict[str, Any]
    ) -> None:
        ledger_store.append(
            conn, kind=kind, payload=payload, policy_hash=self._policy_hash,
            checkout_id=checkout_id, ts_us=self._clock_us(),
        )  # fmt: skip

    def _log(self, kind: str, checkout_id: str, **payload: Any) -> None:
        try:
            with self._engine.begin() as conn:
                self._append(conn, kind, checkout_id, payload)
        except Exception as error:
            raise DecisionLogError(type(error).__name__) from error

    def _call(self, run: _Run, op: str, call: Callable[[], Any]) -> Any:
        """Log a PayPal call before it is made and its outcome after it (INV-12)."""
        self._log(f"gate.paypal.{op}.started", run.checkout_id)
        try:
            result = call()
        except PayPalError as error:
            self._log(
                f"gate.paypal.{op}.failed", run.checkout_id,
                error=type(error).__name__, status=error.status, name=error.name,
                debug_id=error.debug_id, outcome_unknown=error.outcome_unknown,
            )  # fmt: skip
            raise
        self._log(f"gate.paypal.{op}.finished", run.checkout_id)
        return result

    def _step(self, run: _Run, code: str, check: Callable[[], Any]) -> Any:
        """Run one check and log its code and outcome before the next step runs."""
        run.step = code
        try:
            result = check()
        except GateFailure as failure:
            try:
                self._log("gate.step", run.checkout_id, code=code, outcome="fail",
                          reason=failure.reason)  # fmt: skip
            except DecisionLogError:
                pass  # the fail path below still runs; it logs again and fails closed if it can't
            raise
        self._log("gate.step", run.checkout_id, code=code, outcome="pass")
        return result

    # ------------------------------------------------------------------ entry points

    def run(self, *, checkout_id: str, current: Checkout) -> GateOutcome:
        """Run the gate for an authorized checkout, or report what state it is in instead."""
        row = self._store.row(checkout_id)
        if row is None:
            return GateNotApplicable(checkout_id, "none")
        early = self._claim(row, current)
        if early is not None:
            return early
        return self._guarded(_Run(checkout_id, current, self._store.row(checkout_id)))

    def _claim(self, row: Any, current: Checkout | None) -> GateOutcome | None:
        """None if this call now holds the claim; otherwise the outcome to return."""
        cid, state = row.checkout_id, row.state
        won = False
        if state == "authorized":
            won = self._store.claim(cid, expect=("authorized",))
        elif state in IN_PROGRESS:
            if self._clock_us() - row.updated_us <= self._stale_us:
                return GatePending(cid, state)
            won = self._store.claim(cid, expect=IN_PROGRESS, seen_updated_us=row.updated_us)
        elif state == "unresolved" and row.gate_code:
            won = self._store.claim(
                cid, expect=("unresolved",), seen_updated_us=row.updated_us, require_gate_code=True
            )
        elif state == "captured":
            return self._stored_passed(row)
        elif state == "voided" and row.gate_code:
            return self._stored_rejected(row)
        else:
            return GateNotApplicable(cid, state)
        if won:
            return None
        latest = self._store.row(cid)
        if latest is not None and latest.state == "captured":
            return self._stored_passed(latest)
        if latest is not None and latest.state == "voided" and latest.gate_code:
            return self._stored_rejected(latest)
        return GatePending(cid, "gating" if latest is None else str(latest.state))

    def _stored_passed(self, row: Any) -> GatePassed:
        minor, currency = self._store.spend(row.spend_id)
        return GatePassed(
            row.checkout_id, row.order_id, row.authorization_id, row.capture_id,
            Money(currency, minor), row.custom_id, row.receipt,
        )  # fmt: skip

    @staticmethod
    def _stored_rejected(row: Any) -> GateRejected:
        ucp = ucp_code_for(row.gate_code, row.gate_reason or "")
        return GateRejected(
            row.checkout_id, row.gate_code, row.gate_reason or "", ucp, row.receipt or "",
            (_message(ucp),),
        )  # fmt: skip

    def presented_checkout_mandate(self, checkout_id: str) -> str | None:
        """The Checkout Mandate the Credential Provider verified for this checkout, if recorded."""
        tokens = self._store.tokens(checkout_id)
        return None if tokens is None else tokens[1]

    def settle(self, checkout_id: str) -> bool:
        """Settle one attempt by reading PayPal, as `recover` does. True if this call took it on.

        Only for an attempt that is `authorized` or `unresolved` (by the gate). It captures nothing:
        a captured authorization is finalized as captured, an ended one is released, and a live one
        would be voided, which is why a caller that must never move money (the webhook handler) calls
        this only after its own read showed the authorization already captured or ended.
        """
        row = self._store.row(checkout_id)
        if row is None:
            return False
        if row.state == "authorized":
            won = self._store.claim(checkout_id, expect=("authorized",))
        elif row.state == "unresolved" and row.gate_code:
            won = self._store.claim(
                checkout_id, expect=("unresolved",), seen_updated_us=row.updated_us,
                require_gate_code=True,
            )  # fmt: skip
        else:
            return False
        if not won:
            return False
        run = _Run(checkout_id, None, self._store.row(checkout_id))
        self._fail(run, GateFailure(G_STATUS, "settled_from_webhook"))
        return True

    def recover(self, *, older_than_us: int) -> list[str]:
        """Settle attempts a crash or an unreadable PayPal left behind, by reading PayPal.

        No new capture is ever made here: an authorization that PayPal shows as captured is
        finalized as captured, one still `CREATED` is voided (the safe end), a voided one is
        released. Returns the checkout ids touched.
        """
        cutoff = self._clock_us() - older_than_us
        touched: list[str] = []
        for checkout_id, state in self._store.stale_attempts(
            ("authorized", "gating", "capturing", "unresolved"), cutoff
        ):
            row = self._store.row(checkout_id)
            if row is None or row.state != state or (state == "unresolved" and not row.gate_code):
                continue
            if state == "authorized":
                won = self._store.claim(checkout_id, expect=("authorized",))
            elif state == "unresolved":
                won = self._store.claim(
                    checkout_id, expect=("unresolved",), seen_updated_us=row.updated_us,
                    require_gate_code=True,
                )  # fmt: skip
            else:
                won = self._store.claim(
                    checkout_id, expect=IN_PROGRESS, seen_updated_us=row.updated_us
                )
            if not won:
                continue
            run = _Run(checkout_id, None, self._store.row(checkout_id))
            self._fail(run, GateFailure(G_STATUS, "recovered_stale_attempt"))
            touched.append(checkout_id)
        return touched

    # ------------------------------------------------------------------ the gate itself

    def _guarded(self, run: _Run) -> GateOutcome:
        try:
            return self._execute(run)
        except GateFailure as failure:
            return self._fail(run, failure)
        except DecisionLogError:
            return self._fail(run, GateFailure(run.step, "log_failure"))
        except Exception as error:  # noqa: BLE001 - INV-10: anything unexpected takes the fail path
            return self._fail(run, GateFailure(run.step, f"internal:{type(error).__name__}"))

    def _execute(self, run: _Run) -> GateOutcome:
        if self._config.ablations.no_gate:
            return self._naive(run)
        row, current = run.row, run.current
        assert current is not None
        total = _total(current)
        live = self._step(run, G_FETCH, lambda: self._fetch(run))
        self._step(
            run, G_STATUS,
            lambda: steps.check_status(
                live, authorization_id=row.authorization_id, now=self._paypal_now(),
                skew_s=self._skew,
            ),
        )  # fmt: skip
        reversed_terms = self._step(
            run, G_REVERSE,
            lambda: steps.reverse_terms(live, line_ids=[x.id for x in current.line_items]),
        )  # fmt: skip
        self._step(
            run, G_TERMS,
            lambda: steps.check_terms(
                live, reversed_terms, checkout=current, custom_id=row.custom_id,
                payee_merchant_id=self._config.paypal_payee_merchant_id,
            ),
        )  # fmt: skip
        self._step(run, G_AMOUNT, lambda: steps.check_amount(live, total=total))
        verified: VerifiedPayment = self._step(run, G_MANDATE, lambda: self._check_mandate(run))
        run.verified = verified
        self._step(run, G_BUDGET, lambda: self._check_budget(run, verified))
        self._step(run, G_LOCK, lambda: self._check_lock(run, verified))
        return self._capture(run, total)

    def _fetch(self, run: _Run) -> steps.LiveState:
        row = run.row
        try:
            return steps.fetch_live(
                lambda: self._call(run, "get_order", lambda: self._paypal.get_order(row.order_id)),
                lambda: self._call(
                    run, "get_authorization",
                    lambda: self._paypal.get_authorization(row.authorization_id),
                ),
            )  # fmt: skip
        except PayPalError as error:
            raise GateFailure(G_FETCH, f"paypal_read_failed:{type(error).__name__}") from None

    def _check_mandate(self, run: _Run) -> VerifiedPayment:
        assert run.current is not None
        tokens = self._store.tokens(run.checkout_id)
        if tokens is None:
            raise GateFailure(G_MANDATE, "mandates_not_recorded")
        try:
            verified = verify_payment(
                payment_token=tokens[0], checkout_mandate=tokens[1], current=run.current,
                platform_key=self._config.platform_key, payee_id=self._config.payee["id"],
                audience=self._config.audience, checkout_audience=self._config.checkout_audience,
                clock=self._clock,
            )  # fmt: skip
        except CpRejection as rejection:
            raise GateFailure(G_MANDATE, f"verify:{rejection.reason}") from None
        opens = [verified.open_payment_digest, verified.checkout_chain.links[0].digest]
        if self._store.revoked(opens):
            raise GateFailure(G_MANDATE, "mandate_revoked")
        held = self._store.reservation_rows(run.checkout_id)
        for role in ("merchant", "cp"):
            found = held.get(role)
            if found is None or found.state != "reserved":
                raise GateFailure(G_MANDATE, f"reservation_not_held:{role}")
        nonce = verified.payment_chain.final.nonce
        if verified.principal and nonce and held["cp"].nonce_value != nonce:
            raise GateFailure(G_MANDATE, "nonce_not_reserved_by_checkout")
        return verified

    def _check_budget(self, run: _Run, verified: VerifiedPayment) -> None:
        currency = verified.total.currency
        with self._engine.begin() as conn:
            self._store.ledger.lock(conn, verified.open_payment_digest, currency)
            spend = self._store.ledger.view(
                conn, verified.open_payment_digest, currency, exclude_checkout_id=run.checkout_id
            )
            result = self._evaluator.evaluate_payment(
                payment_chain=verified.payment_chain, checkout_chain=verified.checkout_chain,
                spend=spend, now=self._clock(),
            )  # fmt: skip
        if not isinstance(result, ConstraintOutcome) or result.satisfied is not True:
            unresolved = isinstance(result, ConstraintOutcome) and result.unresolved is True
            raise GateFailure(
                G_BUDGET, "constraint_unresolved" if unresolved else "constraint_violated"
            )

    def _check_lock(self, run: _Run, verified: VerifiedPayment) -> None:
        try:
            decision = self._lock.check(
                LockQuery(run.checkout_id, verified.principal, verified.customer_id, verified.total)
            )
        except Exception:  # noqa: BLE001 - a policy that fails is a denial (INV-10)
            raise GateFailure(G_LOCK, "lock_policy_error") from None
        if not isinstance(decision, LockDecision):
            raise GateFailure(G_LOCK, "lock_policy_bad")
        if decision.allowed is not True:
            raise GateFailure(G_LOCK, f"lock_denied:{decision.reason}"[:80])

    # ------------------------------------------------------------------ capture

    def _capture(self, run: _Run, total: Money) -> GateOutcome:
        run.step = G_CAPTURE
        row = run.row
        if not self._store.set_state(run.checkout_id, "capturing", expect=("gating",)):
            latest = self._store.row(run.checkout_id)
            return GatePending(run.checkout_id, "none" if latest is None else str(latest.state))
        approval = mint_capture_approval(
            checkout_id=run.checkout_id, authorization_id=row.authorization_id,
            expected_total=total, invoice_id=run.checkout_id, custom_id=row.custom_id,
        )  # fmt: skip
        try:
            made = self._call(run, "capture", lambda: self._paypal.capture_authorization(approval))
        except PayPalError as error:
            raise GateFailure(G_CAPTURE, f"capture_failed:{type(error).__name__}") from None
        return self._confirm_and_finalize(run, made.resource_id, total)

    def _confirm_and_finalize(self, run: _Run, capture_id: str, expected: Money) -> GateOutcome:
        """GET the capture and the authorization; only a confirmed capture is success."""
        row = run.row
        try:
            capture = self._call(run, "get_capture", lambda: self._paypal.get_capture(capture_id))
            authorization = self._call(
                run, "get_authorization",
                lambda: self._paypal.get_authorization(row.authorization_id),
            )  # fmt: skip
        except PayPalError as error:
            raise GateFailure(G_CAPTURE, f"capture_unreadable:{type(error).__name__}") from None
        confirmed = (
            capture.status == "COMPLETED"
            and capture.final_capture is True
            and capture.amount == expected
            and capture.custom_id in (None, row.custom_id)
            and authorization.status == "CAPTURED"
        )
        if not confirmed:
            raise GateFailure(G_CAPTURE, "capture_not_confirmed")
        return self._finalize(run, capture_id, expected)

    def _finalize(self, run: _Run, capture_id: str, amount: Money) -> GateOutcome:
        """Ledger, reservations, attempt and log in one transaction; then the Success receipt."""
        row, cid = run.row, run.checkout_id
        try:
            reference = self._reference(cid)
            receipt = receipts.sign_receipt(
                {
                    "status": receipts.SUCCESS,
                    "iss": self._config.issuer,
                    "iat": int(self._clock()),
                    "reference": reference,
                    "payment_id": cid,
                    "psp_confirmation_id": capture_id,
                    "network_confirmation_id": capture_id,
                },
                self._config.signing_key,
                receipts.PAYMENT_RECEIPT_TYP,
            )
            self._store.finish_captured(
                cid, spend_id=row.spend_id, capture_id=capture_id, receipt=receipt,
                log=lambda conn: self._append(
                    conn, "gate.captured", cid,
                    {"capture_id": capture_id, "order_id": row.order_id,
                     "authorization_id": row.authorization_id,
                     "amount": f"{amount.currency}:{amount.minor}", "reference": reference},
                ),
            )  # fmt: skip
        except Exception:  # noqa: BLE001 - money moved: keep it reserved, never void (INV-10)
            return self._unresolved(run, GateFailure(G_CAPTURE, "bookkeeping_failed"))
        return GatePassed(
            cid, row.order_id, row.authorization_id, capture_id, amount, row.custom_id, receipt
        )

    def _naive(self, run: _Run) -> GateOutcome:
        """`ABL_NO_GATE`: capture whatever was authorized, as a naive integration would."""
        run.step = G_CAPTURE
        row = run.row
        self._log("gate.ablation.no_gate", run.checkout_id)
        authorization = self._call(
            run, "get_authorization", lambda: self._paypal.get_authorization(row.authorization_id)
        )
        if not self._store.set_state(run.checkout_id, "capturing", expect=("gating",)):
            return GatePending(run.checkout_id, "capturing")
        approval = mint_capture_approval(
            checkout_id=run.checkout_id, authorization_id=row.authorization_id,
            expected_total=authorization.amount,
            invoice_id=authorization.invoice_id or run.checkout_id,
            custom_id=authorization.custom_id or row.custom_id,
        )  # fmt: skip
        try:
            made = self._call(run, "capture", lambda: self._paypal.capture_authorization(approval))
        except PayPalError as error:
            raise GateFailure(G_CAPTURE, f"capture_failed:{type(error).__name__}") from None
        return self._confirm_and_finalize(run, made.resource_id, authorization.amount)

    # ------------------------------------------------------------------ the fail path

    def _fail(self, run: _Run, failure: GateFailure) -> GateOutcome:
        """Void what PayPal still holds, confirm it, release the reservations, or end unresolved."""
        row = run.row
        try:
            order = self._call(run, "get_order", lambda: self._paypal.get_order(row.order_id))
            ids = list(dict.fromkeys([row.authorization_id, *(a.id for a in order.authorizations)]))
            statuses: dict[str, str] = {}
            for ident in ids:
                found = self._call(
                    run, "get_authorization", partial(self._paypal.get_authorization, ident)
                )
                statuses[ident] = found.status
        except Exception:  # noqa: BLE001 - PayPal unreadable: money may be held
            return self._unresolved(run, failure)
        own = statuses[row.authorization_id]
        if own in ("CAPTURED", "PARTIALLY_CAPTURED"):
            return self._settle_captured(run, failure)
        for ident, status in statuses.items():
            if status in ("CREATED", "PENDING"):
                try:
                    voided = self._void_confirmed(run, ident)
                except Exception:  # noqa: BLE001
                    voided = False
                if not voided:
                    return self._unresolved(run, failure)
            elif status not in ("VOIDED", "EXPIRED", "DENIED"):
                return self._unresolved(run, failure)
        return self._release(run, failure)

    def _void_confirmed(self, run: _Run, authorization_id: str) -> bool:
        try:
            self._call(
                run, "void",
                lambda: self._paypal.void_authorization(run.checkout_id, authorization_id),
            )  # fmt: skip
        except PayPalError:
            pass  # already voided, or unknown: the GET below decides
        current = self._call(
            run, "get_authorization", lambda: self._paypal.get_authorization(authorization_id)
        )
        return bool(current.status == "VOIDED")

    def _settle_captured(self, run: _Run, failure: GateFailure) -> GateOutcome:
        """PayPal shows the authorization captured (this gate's capture, finished by a retry)."""
        row = run.row
        try:
            minor, currency = self._store.spend(row.spend_id)
            expected = Money(currency, minor)
            order = self._call(run, "get_order", lambda: self._paypal.get_order(row.order_id))
            if len(order.captures) != 1:
                return self._unresolved(run, GateFailure(G_CAPTURE, "captures_not_one"))
            capture_id = order.captures[0].id
            return self._confirm_and_finalize(run, capture_id, expected)
        except GateFailure as inner:
            return self._unresolved(run, inner)
        except Exception:  # noqa: BLE001
            return self._unresolved(run, failure)

    def _release(self, run: _Run, failure: GateFailure) -> GateOutcome:
        cid, row = run.checkout_id, run.row
        ucp = failure.ucp_code or ucp_code_for(failure.code, failure.reason)
        try:
            reference = self._reference(cid)
            receipt = receipts.sign_receipt(
                {
                    "status": receipts.ERROR,
                    "iss": self._config.issuer,
                    "iat": int(self._clock()),
                    "reference": reference,
                    "payment_id": cid,
                    "error": ucp,
                    "error_description": failure.reason,
                },
                self._config.signing_key,
                receipts.PAYMENT_RECEIPT_TYP,
            )
            self._store.finish_released(
                cid, spend_id=row.spend_id, code=failure.code, reason=failure.reason,
                receipt=receipt,
                log=lambda conn: self._append(
                    conn, "gate.rejected", cid,
                    {"code": failure.code, "reason": failure.reason, "ucp_code": ucp,
                     "reference": reference},
                ),
            )  # fmt: skip
        except Exception:  # noqa: BLE001 - the money is safe but the books are not: unresolved
            return self._unresolved(run, failure)
        return GateRejected(cid, failure.code, failure.reason, ucp, receipt, (_message(ucp),))

    def _unresolved(self, run: _Run, failure: GateFailure) -> GateOutcome:
        """Keep everything reserved: money might be held. `recover` or a retry settles it."""
        cid = run.checkout_id
        try:
            self._store.set_state(
                cid, "unresolved", expect=("gating", "capturing", "authorized"),
                gate_code=failure.code, gate_reason=failure.reason[:80],
            )  # fmt: skip
        except Exception:  # noqa: BLE001 - the row stays as it is; a stale claim is taken over
            log.error("gate_unresolved_not_recorded", checkout_id=cid)
        try:
            self._log("gate.unresolved", cid, code=failure.code, reason=failure.reason)
        except DecisionLogError:
            log.error("gate_unresolved_not_logged", checkout_id=cid)
        return GateUnresolved(cid, failure.code, failure.reason)

    def _reference(self, checkout_id: str) -> str:
        tokens = self._store.tokens(checkout_id)
        return receipts.reference_for(tokens[0] if tokens else "")


def _total(checkout: Checkout) -> Money:
    return next(t.amount for t in checkout.totals if t.type == "total")
