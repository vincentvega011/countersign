"""The principal lock (N3): one shared policy function every protocol adapter calls (INV-3, INV-5).

Security reasoning. Protection follows the principal, never the protocol or the session. A protocol
adapter (UCP now, ACP in P2.7) turns what it was given into a `Principal` and a `LockRequest` and
calls `PrincipalLock.decide`. All the logic is here, so an adapter cannot decide differently, and
this package imports no protocol adapter and no web framework (import guard test). The gate reaches
the same function through a wrapper built at the composition root (`countersign.completion`), because
the gate itself may not import this package.

`decide` in order:

1. Read the merchant policy. A store or policy that cannot be read, or whose hash does not match,
   denies (INV-10).
2. If the request negotiated AP2 (an operation that shows AP2 is in use) and the principal is known,
   record the principal as locked, once, in a transaction that also appends the log entry (INV-12).
3. A mandate is required when any of these holds: this session negotiated AP2 (the UCP Security
   Lock), the principal is locked, or the merchant policy requires AP2 for this total.
4. Create and update are allowed only if the session negotiated AP2 (so a locked principal cannot
   escape into a session without the capability). Complete and capture are allowed only with a valid
   mandate. When the merchant policy requires AP2, or the matching lock names a customer, the
   principal must also name one: an unknown customer id fails closed (denied), never unlocked.
5. The decision is appended to the hash-chained log before it is returned. If the append fails the
   answer is a denial (INV-12).

`ABL_NO_PRINCIPAL_LOCK` is the baseline: nothing is recorded and a stored lock is ignored, so only the
session that negotiated AP2 is protected. It is refused when `APP_ENV=demo` (`countersign.ablations`).
Everything is deterministic: no model, no network, an injected clock (INV-1).
"""

from __future__ import annotations

import time
from collections.abc import Callable
from dataclasses import dataclass
from typing import Literal

import structlog
from joserfc.jwk import ECKey
from sqlalchemy import Connection, Engine

from countersign.ablations import Ablations
from countersign.canonical.money import Money
from countersign.ledger import store as ledger_store
from countersign.lock.policy import MerchantPolicy
from countersign.lock.principal import Principal, principal_from_delegation
from countersign.lock.store import LockStore, LockStoreError
from countersign.merchant.decision_log import DecisionLogError
from countersign.merchant.policy import policy_hash as ledger_policy_hash

log = structlog.get_logger("countersign.lock")

Operation = Literal["create", "update", "complete", "capture"]
MANDATE_REQUIRED = "mandate_required"

ALLOWED_NOT_REQUIRED = "allowed:not_required"
ALLOWED_MANDATE = "allowed:mandate_valid"
ALLOWED_NEGOTIATED = "allowed:ap2_negotiated"
DENIED_NEGOTIATION = "denied:ap2_negotiation_required"
DENIED_MANDATE = "denied:mandate_required"
DENIED_CUSTOMER = "denied:customer_unknown"
DENIED_STORE = "denied:lock_store_unreadable"
DENIED_LOG = "denied:lock_log_failed"


def now_us() -> int:
    return time.time_ns() // 1000


@dataclass(frozen=True)
class LockRequest:
    """What an adapter tells the lock. Nothing here names a protocol or a session."""

    operation: Operation
    checkout_id: str
    principal: Principal | None
    negotiated_ap2: bool  # this request shows AP2 in use (capability negotiated, or a mandate)
    mandate_valid: bool  # a mandate was presented and verified (complete and capture only)
    amount: Money | None = None


@dataclass(frozen=True)
class LockVerdict:
    allowed: bool
    reason: str
    locked: bool = False
    required: bool = False
    policy_version: int = 0
    ucp_code: str = MANDATE_REQUIRED


class PrincipalLock:
    def __init__(
        self,
        engine: Engine,
        *,
        platform_key: ECKey | None = None,
        clock: Callable[[], float] = time.time,
        clock_us: Callable[[], int] = now_us,
        ablations: Ablations | None = None,
    ) -> None:
        self._engine = engine
        self._platform_key = platform_key
        self._clock = clock
        self._clock_us = clock_us
        self._ablations = ablations or Ablations()
        self._store = LockStore(engine, clock_us)
        self._policy_hash = ledger_policy_hash()

    # ------------------------------------------------------------------ principals

    def principal_from_delegation(self, token: str | None) -> Principal | None:
        return principal_from_delegation(token, self._platform_key, self._clock)

    # ------------------------------------------------------------------ log

    def _append(
        self, conn: Connection, kind: str, checkout_id: str | None, payload: dict[str, object]
    ) -> None:
        ledger_store.append(
            conn, kind=kind, payload=payload, policy_hash=self._policy_hash,
            checkout_id=checkout_id, ts_us=self._clock_us(),
        )  # fmt: skip

    # ------------------------------------------------------------------ the decision

    def decide(self, request: LockRequest) -> LockVerdict:
        try:
            return self._decide(request)
        except Exception as error:  # noqa: BLE001 - INV-10: anything unexpected denies
            log.error("lock_decide_failed", error=type(error).__name__)
            reason = DENIED_LOG if isinstance(error, DecisionLogError) else DENIED_STORE
            return LockVerdict(False, reason)

    def _decide(self, request: LockRequest) -> LockVerdict:
        policy = self._store.current_policy()
        principal = request.principal if request.principal and request.principal.known else None
        session_ap2 = request.negotiated_ap2 or request.mandate_valid
        recorded = False
        if session_ap2 and principal is not None and not self._ablations.no_principal_lock:
            recorded = self._record(principal, policy, request.checkout_id)
        locked, lock_names_customer = (
            self._store.lock_state(principal)
            if principal is not None and not self._ablations.no_principal_lock
            else (False, False)
        )
        policy_requires = policy.requires_ap2(request.amount)
        # The customer must be known when the merchant's policy needs it, or when the lock that
        # matched names a customer (an unknown customer cannot be shown to be that one).
        need_customer = policy_requires or lock_names_customer
        required = session_ap2 or need_customer
        customer_ok = principal is not None and bool(principal.customer_id)
        if not required:
            verdict = LockVerdict(True, ALLOWED_NOT_REQUIRED, locked, False, policy.version)
        elif need_customer and not customer_ok:
            verdict = LockVerdict(False, DENIED_CUSTOMER, locked, True, policy.version)
        elif request.operation in ("create", "update"):
            ok = request.negotiated_ap2
            verdict = LockVerdict(
                ok, ALLOWED_NEGOTIATED if ok else DENIED_NEGOTIATION, locked, True, policy.version
            )
        else:
            ok = request.mandate_valid
            verdict = LockVerdict(
                ok, ALLOWED_MANDATE if ok else DENIED_MANDATE, locked, True, policy.version
            )
        try:
            with self._engine.begin() as conn:
                self._append(
                    conn, "lock.decision", request.checkout_id,
                    {
                        "operation": request.operation, "allowed": verdict.allowed,
                        "reason": verdict.reason, "locked": locked, "required": required,
                        "policy_version": policy.version, "policy_hash": policy.hash(),
                        "customer_known": customer_ok,
                        "agent_known": bool(principal and principal.agent_thumbprint),
                        "recorded": recorded,
                    },
                )  # fmt: skip
        except Exception as error:
            raise DecisionLogError(type(error).__name__) from error
        return verdict

    def _record(self, principal: Principal, policy: MerchantPolicy, checkout_id: str) -> bool:
        try:
            with self._engine.begin() as conn:
                new = self._store.record_lock(conn, principal, policy.version, checkout_id)
                if new:
                    self._append(
                        conn, "lock.recorded", checkout_id,
                        {
                            "customer_known": bool(principal.customer_id),
                            "agent_known": bool(principal.agent_thumbprint),
                            "policy_version": policy.version,
                        },
                    )  # fmt: skip
                return new
        except LockStoreError:
            raise
        except Exception as error:
            raise DecisionLogError(type(error).__name__) from error

    # ------------------------------------------------------------------ merchant policy actions

    def set_policy(
        self, mode: str, *, threshold_minor: int | None = None, currency: str | None = None,
        reason: str,
    ) -> MerchantPolicy:  # fmt: skip
        """A merchant policy change: a new version, its hash, and a log entry, in one transaction.

        Not reachable from any protocol adapter: there is no HTTP route for it.
        """
        wanted = MerchantPolicy(0, mode, threshold_minor, currency)  # type: ignore[arg-type]
        with self._engine.begin() as conn:
            stored = self._store.append_policy(conn, wanted, reason)
            self._append(
                conn, "lock.policy_changed", None,
                {"version": stored.version, "hash": stored.hash(), "mode": stored.mode,
                 "threshold_minor": stored.threshold_minor, "currency": stored.currency,
                 "reason": reason[:200]},
            )  # fmt: skip
        return stored

    def unlock(self, principal: Principal, *, reason: str) -> bool:
        """Remove a lock. Only a merchant action: a new policy version, an unlock event, a log entry."""
        with self._engine.begin() as conn:
            current = self._store.current_policy(conn)
            stored = self._store.append_policy(conn, current, f"unlock: {reason}")
            removed = self._store.record_unlock(conn, principal, stored.version)
            self._append(
                conn, "lock.unlocked", None,
                {"removed": removed, "policy_version": stored.version, "hash": stored.hash(),
                 "customer_known": bool(principal.customer_id),
                 "agent_known": bool(principal.agent_thumbprint), "reason": reason[:200]},
            )  # fmt: skip
        return removed
