"""The principal lock as the gate sees it: a question with a yes or no answer.

The lock itself (who is locked) lives in `countersign.lock` and is wired to this Protocol at the
composition root (`countersign.completion`). The gate must not import it, so it depends on this
Protocol only. The default
policy denies everything: a gate that is not given a lock policy captures nothing (INV-10), and a
policy that raises, or returns anything but a `LockDecision`, counts as a denial.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Protocol

from countersign.canonical.money import Money


@dataclass(frozen=True)
class LockQuery:
    """`principal` is the thumbprint of the agent key named in the open Payment Mandate."""

    checkout_id: str
    principal: str | None  # the agent key thumbprint
    customer_id: str | None = None  # from the platform-signed mandate; None if it names no customer
    amount: Money | None = None  # the checkout total


@dataclass(frozen=True)
class LockDecision:
    allowed: bool
    reason: str


class LockPolicy(Protocol):
    def check(self, query: LockQuery) -> LockDecision: ...


class DenyAllLockPolicy:
    """The fail-closed default."""

    def check(self, query: LockQuery) -> LockDecision:
        return LockDecision(False, "no_lock_policy_configured")
