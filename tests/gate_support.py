"""Shared setup for capture gate tests: the real Merchant, Credential Provider and gate on Postgres.

Everything on the verification path is real: the mandates, both chain verifications, the constraint
engine, the Postgres reservations and spend ledger, the decision log, the gate itself. Only PayPal is
the simulator (`tests.paypal_sim`), and the principal lock is the provisional adapter (the real lock
is the next step). Tests that need a lock policy to say something specific pass their own.
"""

from __future__ import annotations

from collections.abc import Callable
from dataclasses import dataclass
from datetime import datetime
from typing import Any

from sqlalchemy import Engine, select

from countersign.ablations import Ablations
from countersign.canonical.models import Checkout
from countersign.completion import GateLockAdapter
from countersign.constraints import CheckoutConstraintEvaluator
from countersign.cp import CpApprovalRequired, CpAuthorized
from countersign.gate import CaptureGate, LockPolicy
from countersign.lock import PrincipalLock
from countersign.merchant.decision_log import LedgerDecisionLog
from countersign.merchant.pg_reservations import PostgresReservationStore
from countersign.merchant.policy import policy_hash
from countersign.merchant.verify import Accepted, CheckoutMandateVerifier, MerchantConfig
from countersign.tables import payment_attempts, reservations, spend_entries
from tests import paypal_sim
from tests.constraint_fixtures import MERCHANT
from tests.cp_support import CpWorld, Mandates, make_world
from tests.mandate_issuer import NOW


class Tick:
    """A settable clock (seconds), so a test can move time between authorize and capture."""

    def __init__(self, now: float = float(NOW)) -> None:
        self.now = now

    def __call__(self) -> float:
        return self.now


@dataclass
class GateWorld:
    base: CpWorld
    gate: CaptureGate
    merchant: CheckoutMandateVerifier
    tick: Tick
    engine: Engine
    lock: PrincipalLock

    @property
    def sim(self) -> paypal_sim.PayPalSim:
        return self.base.sim

    @property
    def checkout(self) -> Checkout:
        return self.base.checkout

    def new_gate(
        self,
        *,
        lock: LockPolicy | None = None,
        ablations: Ablations | None = None,
        claim_stale_us: int = 60_000_000,
        paypal_now: Callable[[], datetime] = lambda: paypal_sim.NOW,
    ) -> CaptureGate:
        config = self.base.config
        if ablations is not None:
            from dataclasses import replace

            config = replace(config, ablations=ablations)
        return CaptureGate(
            config,
            self.engine,
            self.base.client,
            lock if lock is not None else GateLockAdapter(self.lock),
            clock=self.tick,
            paypal_now=paypal_now,
            claim_stale_us=claim_stale_us,
        )

    def authorize(
        self,
        mandates: Mandates | None = None,
        *,
        checkout: Checkout | None = None,
        between: Any = None,
        **mandate_kwargs: Any,
    ) -> tuple[Mandates, CpAuthorized]:
        """Merchant verify, CP start, payer approval, optional `between(order_id)`, CP finish."""
        current = checkout or self.base.checkout
        m = mandates or self.base.mandates(checkout=current, **mandate_kwargs)
        verdict = self.merchant.verify(
            mandate=m.checkout_mandate, issued_checkout=None, current=current
        )
        assert isinstance(verdict, Accepted), verdict
        started = self.base.provider.start(
            payment_token=m.payment_token, checkout_mandate=m.checkout_mandate, current=current
        )
        assert isinstance(started, CpApprovalRequired), started
        self.sim.approve(started.order_id)
        if between is not None:
            between(started.order_id)
        done = self.base.provider.finish(checkout_id=current.id, current=current)
        assert isinstance(done, CpAuthorized), done
        return m, done

    def merchant_release(self, checkout_id: str) -> None:
        """The coordinator releases the Merchant reservation when the Credential Provider rejects."""
        PostgresReservationStore(self.engine, "merchant").release_checkout(checkout_id)

    def row(self, checkout_id: str | None = None) -> Any:
        with self.engine.connect() as conn:
            return conn.execute(
                select(payment_attempts).where(
                    payment_attempts.c.checkout_id == (checkout_id or self.checkout.id)
                )
            ).one()

    def spend(self) -> list[Any]:
        with self.engine.connect() as conn:
            return list(conn.execute(select(spend_entries)).all())

    def reservation_states(self, checkout_id: str | None = None) -> dict[str, str]:
        with self.engine.connect() as conn:
            rows = conn.execute(
                select(reservations.c.role, reservations.c.state).where(
                    reservations.c.checkout_id == (checkout_id or self.checkout.id)
                )
            ).all()
        return {str(r): str(s) for r, s in rows}


def make_gate_world(
    engine: Engine,
    *,
    checkout: Checkout | None = None,
    cp_ablations: Ablations | None = None,
    gate_ablations: Ablations | None = None,
    lock: LockPolicy | None = None,
    lock_ablations: Ablations | None = None,
) -> GateWorld:
    base = make_world(engine, checkout=checkout, ablations=cp_ablations)
    merchant = CheckoutMandateVerifier(
        MerchantConfig(
            issuer="https://merchant.example",
            signing_key=base.merchant_key,
            published_keys=[base.merchant_key.public_jwk],
            platform_key=base.keys.issuer,
        ),
        PostgresReservationStore(engine, "merchant"),
        LedgerDecisionLog(engine, policy_hash(), lambda: 1_800_000_000_000_000),
        lambda: float(NOW),
        CheckoutConstraintEvaluator(MERCHANT["id"]),
    )
    tick = Tick()
    principal_lock = PrincipalLock(
        engine, platform_key=base.keys.issuer, clock=tick, ablations=lock_ablations
    )
    world = GateWorld(base, None, merchant, tick, engine, principal_lock)  # type: ignore[arg-type]
    world.gate = world.new_gate(lock=lock, ablations=gate_ablations)
    return world
