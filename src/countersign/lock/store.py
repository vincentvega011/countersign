"""Postgres storage of the lock: policy versions and lock events (migration 0005).

Insert only for the runtime role. `record_lock` is idempotent and race safe: a transaction-level
advisory lock on the principal key serializes concurrent negotiations, and the insert happens only if
the newest event for that exact key is not already a lock, so 20 parallel negotiations leave one
`lock` event. `lock_state` matches on the known parts of a principal: a locked key matches when its
known customer and agent agree with the request's known parts, and at least one known part is equal
(so a request with an unknown customer is still caught by its agent key, and the reverse).
"""

from __future__ import annotations

from collections.abc import Callable

from sqlalchemy import Connection, Engine, and_, false, func, or_, select, text, true

from countersign.lock.policy import MerchantPolicy
from countersign.lock.principal import Principal
from countersign.tables import lock_events, lock_policies


class LockStoreError(Exception):
    """The lock store could not be read or is not consistent."""


def _key(principal: Principal) -> tuple[str, str]:
    return principal.customer_id or "", principal.agent_thumbprint or ""


class LockStore:
    def __init__(self, engine: Engine, clock_us: Callable[[], int]) -> None:
        self._engine = engine
        self._clock = clock_us

    # ------------------------------------------------------------------ policy

    def current_policy(self, conn: Connection | None = None) -> MerchantPolicy:
        def read(c: Connection) -> MerchantPolicy:
            row = c.execute(select(lock_policies).order_by(lock_policies.c.version.desc())).first()
            if row is None:
                return MerchantPolicy(0)
            policy = MerchantPolicy(int(row.version), row.mode, row.threshold_minor, row.currency)
            if policy.hash() != row.policy_hash:
                raise LockStoreError("a stored policy does not match its hash")
            return policy

        try:
            if conn is not None:
                return read(conn)
            with self._engine.connect() as own:
                return read(own)
        except LockStoreError:
            raise
        except Exception as error:
            raise LockStoreError(type(error).__name__) from error

    def append_policy(
        self, conn: Connection, policy: MerchantPolicy, reason: str
    ) -> MerchantPolicy:
        """Insert `policy` as the next version (the caller holds the policy advisory lock)."""
        conn.execute(text("SELECT pg_advisory_xact_lock(hashtext('cs.lock.policy'))"))
        latest = conn.execute(select(func.coalesce(func.max(lock_policies.c.version), 0))).scalar()
        stored = MerchantPolicy(
            int(latest or 0) + 1, policy.mode, policy.threshold_minor, policy.currency
        )
        conn.execute(
            lock_policies.insert().values(
                version=stored.version, mode=stored.mode, threshold_minor=stored.threshold_minor,
                currency=stored.currency, policy_hash=stored.hash(), reason=reason[:200],
                created_us=self._clock(),
            )
        )  # fmt: skip
        return stored

    # ------------------------------------------------------------------ locks

    def lock_state(self, principal: Principal) -> tuple[bool, bool]:
        """(locked, a matching lock names a customer) for the known parts of `principal`."""
        customer, agent = _key(principal)
        if not customer and not agent:
            return False, False
        known_customer = true() if customer else false()
        known_agent = true() if agent else false()
        match = and_(
            or_(
                lock_events.c.customer_id == customer,
                lock_events.c.customer_id == "",
                ~known_customer,
            ),
            or_(
                lock_events.c.agent_thumbprint == agent,
                lock_events.c.agent_thumbprint == "",
                ~known_agent,
            ),
            or_(
                and_(known_customer, lock_events.c.customer_id == customer),
                and_(known_agent, lock_events.c.agent_thumbprint == agent),
            ),
        )
        newest = (
            select(
                lock_events.c.kind,
                lock_events.c.customer_id,
                func.row_number()
                .over(
                    partition_by=[lock_events.c.customer_id, lock_events.c.agent_thumbprint],
                    order_by=lock_events.c.seq.desc(),
                )
                .label("rank"),
            )
            .where(match)
            .subquery()
        )
        try:
            with self._engine.connect() as conn:
                rows = conn.execute(
                    select(newest.c.customer_id).where(newest.c.rank == 1, newest.c.kind == "lock")
                ).all()
        except Exception as error:
            raise LockStoreError(type(error).__name__) from error
        return bool(rows), any(r[0] for r in rows)

    def record_lock(
        self, conn: Connection, principal: Principal, policy_version: int, checkout_id: str | None
    ) -> bool:
        """Record the lock unless the newest event for this exact key is already one. True if new."""
        customer, agent = _key(principal)
        conn.execute(
            text("SELECT pg_advisory_xact_lock(hashtext(:k))"), {"k": f"cs.lock:{customer}|{agent}"}
        )
        newest = conn.execute(
            select(lock_events.c.kind)
            .where(lock_events.c.customer_id == customer, lock_events.c.agent_thumbprint == agent)
            .order_by(lock_events.c.seq.desc())
            .limit(1)
        ).scalar()
        if newest == "lock":
            return False
        self._insert(conn, "lock", customer, agent, policy_version, checkout_id)
        return True

    def record_unlock(self, conn: Connection, principal: Principal, policy_version: int) -> bool:
        customer, agent = _key(principal)
        conn.execute(
            text("SELECT pg_advisory_xact_lock(hashtext(:k))"), {"k": f"cs.lock:{customer}|{agent}"}
        )
        newest = conn.execute(
            select(lock_events.c.kind)
            .where(lock_events.c.customer_id == customer, lock_events.c.agent_thumbprint == agent)
            .order_by(lock_events.c.seq.desc())
            .limit(1)
        ).scalar()
        if newest != "lock":
            return False
        self._insert(conn, "unlock", customer, agent, policy_version, None)
        return True

    def _insert(
        self,
        conn: Connection,
        kind: str,
        customer: str,
        agent: str,
        policy_version: int,
        checkout_id: str | None,
    ) -> None:
        conn.execute(
            lock_events.insert().values(
                kind=kind, customer_id=customer, agent_thumbprint=agent,
                policy_version=policy_version, checkout_id=checkout_id, created_us=self._clock(),
            )
        )  # fmt: skip
