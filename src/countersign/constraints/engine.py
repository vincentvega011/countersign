"""The constraint engine: evaluates the constraints of an open mandate against its closed values.

Two entry points, both deterministic and fail closed (INV-1, INV-10):

- `CheckoutConstraintEvaluator.evaluate` implements the evaluator interface of the Merchant role
  (structural typing; this package does not import `merchant/`). It evaluates the open Checkout
  Mandate constraints (`checkout.line_items`, `checkout.allowed_merchants`) against the checkout
  the closed Checkout Mandate commits to.
- `PaymentConstraintEvaluator.evaluate_payment` is for the Credential Provider (P2.4). It
  evaluates the open Payment Mandate constraints against the closed Payment Mandate values, the
  Checkout Mandate chain (for `payment.reference`) and an explicit spend view.

Common rules, in this order (AP2 "Verification and Processing Rules", vendored
`agent_authorization.md`):

1. The chain has the shape the caller expects: one link (Human Present, signed by the platform
   after the customer saw the exact checkout; no constraints exist and a `constraints` claim in it is
   refused) or an open link followed by a closed link.
2. The claims of the open mandate are unchanged in the closed mandate: every claim of the open
   content except `vct`, `constraints`, `cnf`, `iat`, `exp`, `nbf` must appear in the closed content
   with an equal value of the same JSON type. A dropped or altered claim fails, so a preset payee or
   amount cannot be changed by the agent.
3. The closed mandate carries no `constraints` or `cnf` of its own (they would be unevaluated).
4. Every constraint is evaluated. An unknown `type`, or a type that belongs to the other mandate,
   is `unresolved_constraint`; it is never skipped. Two constraints of one type are refused
   (ambiguous). A required constraint that is absent fails (`checkout.line_items` for the Checkout
   Mandate, `payment.reference` for the Payment Mandate, as the schemas require).
"""

from __future__ import annotations

from collections.abc import Callable, Mapping
from datetime import UTC, datetime
from typing import Any

from countersign.canonical import JsonValue
from countersign.canonical.models import Checkout
from countersign.constraints import checkout as checkout_constraints
from countersign.constraints import payment as payment_constraints
from countersign.constraints.budget import SpendView
from countersign.constraints.model import (
    SATISFIED,
    UNRESOLVED,
    ConstraintResult,
    json_equal,
    violated,
)
from countersign.mandates import (
    VCT_CHECKOUT,
    VCT_CHECKOUT_OPEN,
    VCT_PAYMENT,
    VCT_PAYMENT_OPEN,
    VerifiedChain,
)

# Claims that describe the delegation itself and legitimately differ between open and closed.
DELEGATION_CLAIMS = frozenset({"vct", "constraints", "cnf", "iat", "exp", "nbf"})
CHECKOUT_TYPES = frozenset(
    {checkout_constraints.LINE_ITEMS, checkout_constraints.ALLOWED_MERCHANTS}
)


def claims_unchanged(
    open_content: Mapping[str, JsonValue], closed: Mapping[str, JsonValue]
) -> bool:
    """AP2 processing rule 2: the closed mandate repeats the open mandate's claims unchanged."""
    for name, value in open_content.items():
        if name in DELEGATION_CLAIMS:
            continue
        if name not in closed or not json_equal(value, closed[name]):
            return False
    return True


def evaluate_all(
    constraints: object,
    handlers: Mapping[str, Callable[[dict[str, Any]], ConstraintResult]],
    required: frozenset[str],
) -> ConstraintResult:
    """Evaluate every constraint of one mandate, first failure wins, nothing is skipped."""
    if not isinstance(constraints, list):
        return violated("constraints", "missing_or_malformed")
    seen: set[str] = set()
    for constraint in constraints:
        if not isinstance(constraint, dict) or not isinstance(constraint.get("type"), str):
            return violated("constraints", "constraint_malformed")
        kind = constraint["type"]
        handler = handlers.get(kind)
        if handler is None:
            return UNRESOLVED
        if kind in seen:
            return violated(kind, "duplicate_constraint")
        seen.add(kind)
        result = handler(constraint)
        if result.satisfied is not True:
            return result
    for kind in sorted(required):
        if kind not in seen:
            return violated(kind, "required_constraint_missing")
    return SATISFIED


def _shape(
    chain: VerifiedChain, open_vct: str, closed_vct: str
) -> ConstraintResult | tuple[Mapping[str, JsonValue] | None, Mapping[str, JsonValue]]:
    """Check rules 1 and 3; return (open content or None for one link, closed content)."""
    links = chain.links
    closed = links[-1]
    if (
        closed.vct != closed_vct
        or "constraints" in closed.content
        or (len(links) == 2 and "cnf" in closed.content)
    ):
        return violated("mandate", "closed_mandate_unexpected")
    if len(links) == 1:
        return None, closed.content
    if len(links) != 2 or links[0].vct != open_vct:
        return violated("mandate", "chain_shape_unexpected")
    return links[0].content, closed.content


class CheckoutConstraintEvaluator:
    """Evaluator for the Merchant role: checkout constraints for one merchant identity."""

    def __init__(self, merchant_id: str) -> None:
        if not merchant_id:
            raise ValueError("a merchant id is required")
        self._merchant_id = merchant_id

    def evaluate(self, *, chain: VerifiedChain, checkout: Checkout, now: float) -> ConstraintResult:
        shaped = _shape(chain, VCT_CHECKOUT_OPEN, VCT_CHECKOUT)
        if isinstance(shaped, ConstraintResult):
            return shaped
        open_content, closed = shaped
        if open_content is None:
            if "constraints" in chain.final.content:
                return violated("mandate", "closed_mandate_unexpected")
            return ConstraintResult(True, "no_open_mandate")
        if not claims_unchanged(open_content, closed):
            return violated("mandate", "open_claims_changed")
        handlers: dict[str, Callable[[dict[str, Any]], ConstraintResult]] = {
            checkout_constraints.LINE_ITEMS: lambda c: checkout_constraints.evaluate_line_items(
                c, checkout
            ),
            checkout_constraints.ALLOWED_MERCHANTS: lambda c: (
                checkout_constraints.evaluate_allowed_merchants(c, self._merchant_id)
            ),
        }
        return evaluate_all(
            open_content.get("constraints"),
            handlers,
            frozenset({checkout_constraints.LINE_ITEMS}),
        )


class PaymentConstraintEvaluator:
    """Evaluator for the Credential Provider: payment constraints against the closed values."""

    def evaluate_payment(
        self,
        *,
        payment_chain: VerifiedChain,
        checkout_chain: VerifiedChain,
        spend: SpendView | None,
        now: float,
    ) -> ConstraintResult:
        """`spend` is the view WITHOUT the presentation being evaluated (the caller reserves it
        atomically afterwards; the gate re-evaluates with its own reservation excluded)."""
        shaped = _shape(payment_chain, VCT_PAYMENT_OPEN, VCT_PAYMENT)
        if isinstance(shaped, ConstraintResult):
            return shaped
        open_content, closed = shaped
        if open_content is None:
            return ConstraintResult(True, "no_open_mandate")
        if not claims_unchanged(open_content, closed):
            return violated("mandate", "open_claims_changed")
        digests = frozenset(
            link.digest for link in checkout_chain.links if link.vct == VCT_CHECKOUT_OPEN
        )
        facts = payment_constraints.closed_facts(
            dict(closed),
            now=datetime.fromtimestamp(now, UTC),
            spend=spend,
            open_checkout_digests=digests,
        )
        if isinstance(facts, ConstraintResult):
            return facts
        handlers: dict[str, Callable[[dict[str, Any]], ConstraintResult]] = {
            kind: (lambda c, fn=fn: fn(c, facts))  # type: ignore[misc]
            for kind, fn in payment_constraints.PAYMENT_HANDLERS.items()
        }
        return evaluate_all(
            open_content.get("constraints"), handlers, frozenset({payment_constraints.REFERENCE})
        )
