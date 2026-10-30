"""UCP complete: Merchant verification, then the Credential Provider (docs/PROTOCOL.md Decision 38).

This glue module is the only place where the two roles meet. The UCP service calls it through a
port it defines (`CompletionPort`), and `cp/` and `merchant/` import neither the service nor any
protocol adapter.

Order. A first complete runs the Merchant's eight steps on the Checkout Mandate. If they accept, the
Merchant's single-use reservation is held and the Credential Provider verifies the Payment Mandate,
reserves budget and the payment's own keys, and creates the PayPal order. A complete for a checkout
that already has a payment attempt does not verify anything again: it continues that attempt (payer
approval, pre-authorize check, authorization), because the mandates were verified when it began.

The lock. Every entry point asks the one shared function `PrincipalLock.decide` (INV-3, INV-5): the
service for create and update, and here for complete, once before the Merchant when no mandate was
presented and once after the Merchant accepted (with the principal named by the verified chain). The
gate reaches the same function through `GateLockAdapter`, built here because the gate may not import
the lock.

Capture. When the Credential Provider reports the payment authorized (in the same call in vault
mode, in the continuing call after the payer approved otherwise), the capture gate runs
(docs/PROTOCOL.md Decision 41). Nothing here captures or voids: the gate does, and the coordinator
only turns its four outcomes into a completion outcome. A gate that is not configured leaves the
payment authorized and in flight (fail closed: nothing is captured).

Cleanup. If the Credential Provider rejects, or anything fails after the Merchant reserved, the
Merchant reservation is released (the open mandate becomes usable again; the checkout's hash and id
stay consumed, so the service cancels that checkout). A gate rejection releases both reservations
itself.
"""

from __future__ import annotations

from countersign.canonical.models import Checkout
from countersign.cp import (
    CpApprovalRequired,
    CpAuthorized,
    CpPending,
    CpRejected,
    CredentialProvider,
)
from countersign.gate import (
    CaptureGate,
    GateNotApplicable,
    GatePassed,
    GatePending,
    GateRejected,
    GateUnresolved,
)
from countersign.gate.policy import LockDecision, LockQuery
from countersign.lock import LockRequest, Principal, PrincipalLock, principal_from_chain
from countersign.merchant.pg_reservations import PostgresReservationStore
from countersign.merchant.verify import Accepted, CheckoutMandateVerifier, Rejected
from countersign.protocols.ucp import messages as m
from countersign.protocols.ucp.service import CompletionOutcome

_PAYMENT_TOKEN_MISSING = m.error_message(
    m.MANDATE_REQUIRED,
    "This checkout requires an AP2 payment mandate in a Countersign payment instrument.",
    "recoverable",
    "$.payment.instruments",
)
_UNRESOLVED = m.error_message(
    "payment_failed",
    "The payment could not be confirmed yet; complete again later.",
    "recoverable",
)
_ATTEMPT_ENDED = m.error_message(
    "payment_attempt_ended",
    "The payment for this checkout has ended; create a new checkout.",
    "unrecoverable",
)


_LOCK_DENIED = m.error_message(
    m.MANDATE_REQUIRED,
    "This agent must use AP2: negotiate the AP2 mandates capability and present a mandate.",
    "recoverable",
    "$.ap2.checkout_mandate",
)


class GateLockAdapter:
    """The gate's `LockPolicy`, answered by the shared lock (built at the composition root)."""

    def __init__(self, lock: PrincipalLock) -> None:
        self._lock = lock

    def check(self, query: LockQuery) -> LockDecision:
        verdict = self._lock.decide(
            LockRequest(
                "capture",
                query.checkout_id,
                Principal(query.customer_id, query.principal),
                negotiated_ap2=True,
                mandate_valid=True,
                amount=query.amount,
            )
        )
        return LockDecision(verdict.allowed, verdict.reason)


class CompleteCoordinator:
    def __init__(
        self,
        merchant: CheckoutMandateVerifier,
        merchant_store: PostgresReservationStore,
        credential_provider: CredentialProvider,
        gate: CaptureGate | None = None,
        lock: PrincipalLock | None = None,
    ) -> None:
        self._lock = lock
        self._merchant = merchant
        self._merchant_store = merchant_store
        self._cp = credential_provider
        self._gate = gate

    def _lock_denies(
        self,
        checkout: Checkout,
        principal: Principal | None,
        *,
        negotiated: bool,
        mandate_valid: bool,
    ) -> bool:
        if self._lock is None:
            return False
        total = next(t.amount for t in checkout.totals if t.type == "total")
        verdict = self._lock.decide(
            LockRequest(
                "complete",
                checkout.id,
                principal,
                negotiated_ap2=negotiated,
                mandate_valid=mandate_valid,
                amount=total,
            )
        )
        return not verdict.allowed

    def complete(
        self,
        *,
        checkout: Checkout,
        mandate: str | None,
        payment_token: str | None,
        resume: bool,
        principal: Principal | None = None,
        negotiated: bool = False,
    ) -> CompletionOutcome:
        state = self._cp.attempt_state(checkout.id)
        if state is not None:
            return self._continue(checkout, state)
        if resume:
            # Another request is verifying this checkout right now.
            return CompletionOutcome("in_progress")
        if (not mandate or not payment_token) and self._lock_denies(
            checkout, principal, negotiated=negotiated, mandate_valid=False
        ):
            return CompletionOutcome("rejected", (_LOCK_DENIED,), consumed=False)
        if not payment_token:
            # Refuse before the Merchant reserves anything: the checkout stays completable.
            return CompletionOutcome("rejected", (_PAYMENT_TOKEN_MISSING,), consumed=False)
        verdict = self._merchant.verify(mandate=mandate, issued_checkout=None, current=checkout)
        if isinstance(verdict, Rejected):
            return CompletionOutcome("rejected", tuple(verdict.messages), consumed=False)
        assert isinstance(verdict, Accepted)
        named = principal_from_chain(verdict.chain)
        if self._lock_denies(checkout, named, negotiated=True, mandate_valid=True):
            self._merchant_store.release(verdict.reservation)
            return CompletionOutcome("rejected", (_LOCK_DENIED,), consumed=True)
        try:
            result = self._cp.start(
                payment_token=payment_token, checkout_mandate=mandate, current=checkout
            )
        except Exception:
            self._merchant_store.release(verdict.reservation)
            raise
        if isinstance(result, CpRejected):
            self._merchant_store.release(verdict.reservation)
            return CompletionOutcome("rejected", tuple(result.messages), consumed=True)
        return self._outcome(result, checkout)

    def _continue(self, checkout: Checkout, state: str) -> CompletionOutcome:
        gated = self._gated(checkout)
        if gated is not None:
            return gated
        if state in ("abandoned", "voided", "failed", "unresolved"):
            return CompletionOutcome("rejected", (_ATTEMPT_ENDED,), consumed=True)
        result = self._cp.finish(checkout_id=checkout.id, current=checkout)
        if isinstance(result, CpRejected):
            self._release_merchant(checkout)
            return CompletionOutcome("rejected", tuple(result.messages), consumed=True)
        return self._outcome(result, checkout)

    def _gated(self, checkout: Checkout) -> CompletionOutcome | None:
        """Run the capture gate. None if there is no gate or nothing for it to act on."""
        if self._gate is None:
            return None
        outcome = self._gate.run(checkout_id=checkout.id, current=checkout)
        if isinstance(outcome, GatePassed):
            found = {"payment_receipt": outcome.receipt}
            mandate = self._gate.presented_checkout_mandate(checkout.id)
            if mandate is not None:
                found["checkout_receipt"] = self._merchant.completion_receipt(mandate, checkout.id)
            return CompletionOutcome("captured", receipts=found)
        if isinstance(outcome, GateRejected):
            return CompletionOutcome("rejected", tuple(outcome.messages), consumed=True)
        if isinstance(outcome, GatePending):
            return CompletionOutcome("in_progress")
        if isinstance(outcome, GateUnresolved):
            return CompletionOutcome("unresolved", (_UNRESOLVED,))
        assert isinstance(outcome, GateNotApplicable)
        return None

    def _release_merchant(self, checkout: Checkout) -> None:
        self._merchant_store.release_checkout(checkout.id)

    def _outcome(
        self, result: CpApprovalRequired | CpPending | CpAuthorized, checkout: Checkout
    ) -> CompletionOutcome:
        if isinstance(result, CpApprovalRequired):
            return CompletionOutcome("approval_required", continue_url=result.approval_url)
        if isinstance(result, CpPending):
            return CompletionOutcome("pending")
        gated = self._gated(checkout)
        return gated if gated is not None else CompletionOutcome("authorized")
