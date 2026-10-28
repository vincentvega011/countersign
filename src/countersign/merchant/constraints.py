"""The narrow constraint interface of the Merchant role (implemented in P2.3).

The Merchant role hands the verified chain (with the disclosed constraints of the open mandate and
the content of the closed one) and the current checkout to an evaluator and accepts the mandate
only if the result is exactly `satisfied=True` (INV-1, INV-10). Anything else, including an
evaluator that returns another type, fails closed. The evaluator is deterministic code, receives no
reservation store and cannot reserve or release anything.

`DenyAllConstraints` is the default until P2.3: it denies everything, so a Merchant built without an
evaluator can never accept a mandate. Tests that exercise the other steps use a clearly named
test-only evaluator from tests/.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Protocol

from countersign.canonical.models import Checkout
from countersign.mandates import VerifiedChain


@dataclass(frozen=True)
class ConstraintResult:
    satisfied: bool
    reason: str  # a fixed internal code, for the decision log
    unresolved: bool = False  # True for a constraint type that is not understood


class ConstraintEvaluator(Protocol):
    def evaluate(
        self, *, chain: VerifiedChain, checkout: Checkout, now: float
    ) -> ConstraintResult: ...


class DenyAllConstraints:
    """Fail-closed stand-in: no constraint logic exists yet, so nothing is satisfied."""

    def evaluate(self, *, chain: VerifiedChain, checkout: Checkout, now: float) -> ConstraintResult:
        return ConstraintResult(False, "constraints_not_implemented", unresolved=True)
