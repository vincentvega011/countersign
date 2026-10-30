"""Credential Provider: verification of a Payment Mandate token (docs/PROTOCOL.md Decisions 8, 35).

Pure and deterministic (INV-1): no database, no network, time only from the injected clock. The
steps run in this order and each has its own typed failure (`CpRejection`):

C1 token present. A locked session needs a Payment Mandate as well as a Checkout Mandate (INV-3).
C2 chains. The Payment Mandate chain and the Checkout Mandate chain presented with it are both
   verified with the `mandates` primitives against the one trusted platform key (Decision 5), with
   the audiences `credential-provider` and `merchant`. Each role verifies independently from the
   same inputs and trusts no other role's result (Decision 8).
C3 `transaction_id`. It must equal the hash of the checkout JWT embedded in the Checkout Mandate and
   the Checkout Mandate's `checkout_hash`. This is what scopes the payment to the checkout
   (AP2 "Merchant Payment Processor"): a Payment Mandate made for another checkout carries another
   hash.
C4 payee, amount, currency. The payee must be this merchant (by `id`), the amount must equal the
   checkout total to the minor unit and the currency the checkout currency, compared with the
   current session state. A mandate for $1 cannot pay for a $100 checkout and the reverse.

C5 (constraints) and C6 (reservation) need the database and are in `provider.py`, in one transaction.
"""

from __future__ import annotations

from collections.abc import Callable, Mapping
from dataclasses import dataclass

from joserfc.jwk import ECKey

from countersign.canonical import HashInputError, JsonValue
from countersign.canonical import checkout_hash as hash_checkout_jwt
from countersign.canonical.models import Checkout
from countersign.canonical.money import Money
from countersign.cp.rejection import (
    AGENT_MISSING_KEY,
    MANDATE_EXPIRED,
    MANDATE_INVALID_SIGNATURE,
    MANDATE_REQUIRED,
    MANDATE_SCOPE_MISMATCH,
    CpRejection,
)
from countersign.mandates import (
    VCT_CHECKOUT,
    VCT_CHECKOUT_OPEN,
    VCT_PAYMENT,
    VCT_PAYMENT_OPEN,
    MandateError,
    VerifiedChain,
    customer_id_of,
    split_chain,
    verify_chain,
)
from countersign.mandates.errors import (
    CnfMalformedError,
    CnfMissingError,
    CnfUnsupportedKeyError,
    ExpiredError,
)

MODE_AUTONOMOUS = "autonomous"
MODE_HUMAN_PRESENT = "human_present"


@dataclass(frozen=True)
class VerifiedPayment:
    payment_chain: VerifiedChain
    checkout_chain: VerifiedChain
    mode: str
    session_hash: str  # hash of the checkout JWT, equal to transaction_id and checkout_hash
    total: Money
    payment_reference: str  # digest of the closed Payment Mandate, computed like sd_hash
    checkout_reference: str  # digest of the closed Checkout Mandate
    open_payment_digest: str  # key of the budget and of the mandate-in-flight reservation
    principal: str | None  # thumbprint of the agent key named in the open Payment Mandate
    customer_id: str | None = (
        None  # `sub` of the platform-signed issuer JWT, if both mandates agree
    )


def _map(error: MandateError, step: str, prefix: str) -> CpRejection:
    if isinstance(error, ExpiredError):
        return CpRejection(step, f"{prefix}:mandate_expired", MANDATE_EXPIRED)
    if isinstance(error, CnfMissingError | CnfMalformedError | CnfUnsupportedKeyError):
        return CpRejection(step, f"{prefix}:{error.code}", AGENT_MISSING_KEY)
    return CpRejection(step, f"{prefix}:{error.code}", MANDATE_INVALID_SIGNATURE)


def _verify(
    token: str,
    key: ECKey,
    open_vct: str,
    closed_vct: str,
    audience: str,
    clock: Callable[[], float],
    prefix: str,
) -> tuple[VerifiedChain, str]:
    try:
        count = len(split_chain(token))
        if count == 2:
            vcts, mode = [open_vct, closed_vct], MODE_AUTONOMOUS
        elif count == 1:
            vcts, mode = [closed_vct], MODE_HUMAN_PRESENT
        else:
            raise CpRejection("C2", f"{prefix}:structure_chain_length", MANDATE_INVALID_SIGNATURE)
        chain = verify_chain(
            token, issuer_key=key, expected_vcts=vcts, audience=audience, nonce=None, clock=clock
        )
    except MandateError as error:
        raise _map(error, "C2", prefix) from None
    return chain, mode


def _customer(payment: VerifiedChain, checkout: VerifiedChain) -> str | None:
    """The customer both mandates name; None if either names none or they disagree (Decision 47)."""
    first, second = (
        customer_id_of(payment.links[0].claims),
        customer_id_of(checkout.links[0].claims),
    )
    return first if first is not None and first == second else None


def verify_payment(
    *,
    payment_token: object,
    checkout_mandate: object,
    current: Checkout,
    platform_key: ECKey | None,
    payee_id: str,
    audience: str,
    checkout_audience: str,
    clock: Callable[[], float],
) -> VerifiedPayment:
    if not payment_token or not checkout_mandate:
        raise CpRejection("C1", "mandate_missing", MANDATE_REQUIRED)
    if not isinstance(payment_token, str) or not isinstance(checkout_mandate, str):
        raise CpRejection("C2", "chain:structure_not_text", MANDATE_INVALID_SIGNATURE)
    if platform_key is None:
        raise CpRejection("C2", "platform_key_missing", AGENT_MISSING_KEY)
    payment, mode = _verify(
        payment_token, platform_key, VCT_PAYMENT_OPEN, VCT_PAYMENT, audience, clock, "payment"
    )
    checkout, checkout_mode = _verify(
        checkout_mandate, platform_key, VCT_CHECKOUT_OPEN, VCT_CHECKOUT, checkout_audience, clock,
        "checkout",
    )  # fmt: skip
    if mode != checkout_mode:
        raise CpRejection("C2", "modes_differ", MANDATE_SCOPE_MISMATCH)

    embedded = checkout.final.content.get("checkout_jwt")
    claimed = checkout.final.content.get("checkout_hash")
    try:
        if not isinstance(embedded, str):
            raise HashInputError("no checkout_jwt")
        session_hash = hash_checkout_jwt(embedded)
    except HashInputError:
        raise CpRejection("C3", "checkout_jwt_unavailable", MANDATE_SCOPE_MISMATCH) from None
    transaction_id: JsonValue = payment.final.content.get("transaction_id")
    if not isinstance(transaction_id, str) or transaction_id != session_hash:
        raise CpRejection("C3", "transaction_id_mismatch", MANDATE_SCOPE_MISMATCH)
    if claimed != session_hash:
        raise CpRejection("C3", "checkout_hash_mismatch", MANDATE_SCOPE_MISMATCH)

    total = next(t.amount for t in current.totals if t.type == "total")
    content: Mapping[str, JsonValue] = payment.final.content
    payee = content.get("payee")
    if not isinstance(payee, dict) or payee.get("id") != payee_id:
        raise CpRejection("C4", "payee_mismatch", MANDATE_SCOPE_MISMATCH)
    amount = content.get("payment_amount")
    if not isinstance(amount, dict) or set(amount) != {"amount", "currency"}:
        raise CpRejection("C4", "payment_amount_invalid", MANDATE_SCOPE_MISMATCH)
    if amount["currency"] != total.currency:
        raise CpRejection("C4", "currency_mismatch", MANDATE_SCOPE_MISMATCH)
    value = amount["amount"]
    if not isinstance(value, int) or isinstance(value, bool) or value != total.minor:
        raise CpRejection("C4", "amount_mismatch", MANDATE_SCOPE_MISMATCH)

    return VerifiedPayment(
        payment_chain=payment,
        checkout_chain=checkout,
        mode=mode,
        session_hash=session_hash,
        total=total,
        payment_reference=payment.final.digest,
        checkout_reference=checkout.final.digest,
        open_payment_digest=payment.links[0].digest,
        principal=payment.links[0].cnf_thumbprint,
        customer_id=_customer(payment, checkout),
    )
