"""UCP complete: Merchant verification, then the Credential Provider (docs/PROTOCOL.md Decision 38).

This glue module is the only place where the two roles meet. The UCP service calls it through a
port it defines (`CompletionPort`), and `cp/` and `merchant/` import neither the service nor any
protocol adapter.

Order. A first complete runs the Merchant's eight steps on the Checkout Mandate. If they accept, the
Merchant's single-use reservation is held and the Credential Provider verifies the Payment Mandate,
reserves budget and the payment's own keys, and creates the PayPal order. A complete for a checkout
that already has a payment attempt does not verify anything again: it continues that attempt (payer
approval, pre-authorize check, authorization), because the mandates were verified when it began.

Cleanup. If the Credential Provider rejects, or anything fails after the Merchant reserved, the
Merchant reservation is released (the open mandate becomes usable again; the checkout's hash and id
stay consumed, so the service cancels that checkout). Nothing is captured here: the capture gate is
P2.5, so an authorized payment stays authorized and in flight.
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
_ATTEMPT_ENDED = m.error_message(
    "payment_attempt_ended",
    "The payment for this checkout has ended; create a new checkout.",
    "unrecoverable",
)


class CompleteCoordinator:
    def __init__(
        self,
        merchant: CheckoutMandateVerifier,
        merchant_store: PostgresReservationStore,
        credential_provider: CredentialProvider,
    ) -> None:
        self._merchant = merchant
        self._merchant_store = merchant_store
        self._cp = credential_provider

    def complete(
        self, *, checkout: Checkout, mandate: str | None, payment_token: str | None, resume: bool
    ) -> CompletionOutcome:
        state = self._cp.attempt_state(checkout.id)
        if state is not None:
            return self._continue(checkout, state)
        if resume:
            # Another request is verifying this checkout right now.
            return CompletionOutcome("in_progress")
        if not payment_token:
            # Refuse before the Merchant reserves anything: the checkout stays completable.
            return CompletionOutcome("rejected", (_PAYMENT_TOKEN_MISSING,), consumed=False)
        verdict = self._merchant.verify(mandate=mandate, issued_checkout=None, current=checkout)
        if isinstance(verdict, Rejected):
            return CompletionOutcome("rejected", tuple(verdict.messages), consumed=False)
        assert isinstance(verdict, Accepted)
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
        return self._outcome(result)

    def _continue(self, checkout: Checkout, state: str) -> CompletionOutcome:
        if state in ("abandoned", "voided", "failed", "unresolved"):
            return CompletionOutcome("rejected", (_ATTEMPT_ENDED,), consumed=True)
        result = self._cp.finish(checkout_id=checkout.id, current=checkout)
        if isinstance(result, CpRejected):
            self._release_merchant(checkout)
            return CompletionOutcome("rejected", tuple(result.messages), consumed=True)
        return self._outcome(result)

    def _release_merchant(self, checkout: Checkout) -> None:
        self._merchant_store.release_checkout(checkout.id)

    @staticmethod
    def _outcome(result: CpApprovalRequired | CpPending | CpAuthorized) -> CompletionOutcome:
        if isinstance(result, CpApprovalRequired):
            return CompletionOutcome("approval_required", continue_url=result.approval_url)
        if isinstance(result, CpPending):
            return CompletionOutcome("pending")
        return CompletionOutcome("authorized")
