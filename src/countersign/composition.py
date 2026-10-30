"""The composition root: turn the runtime settings into the objects the roles receive.

Mode and ablation logic lives here and nowhere else. The invariant modules (merchant, cp, gate,
lock, constraints, canonical, ledger, evidence) take plain collaborators; this module decides which
ones. In `full` with no ablation every collaborator is the original, and nothing from
`countersign.degraded` is imported or built (`tests/integration/test_modes.py`).

What each mode builds (docs/PROTOCOL.md Decision 59 has the justified list):

| piece                         | full                  | baseline / ablation                              |
| ----------------------------- | --------------------- | ------------------------------------------------ |
| capture stage                 | `CaptureGate`         | `ImmediateCapture` (baseline), naive gate (`ABL_NO_GATE`) |
| pre-authorize check           | on                    | off (baseline, `ABL_NO_PREAUTH_CHECK`)           |
| principal lock                | all principals        | this session only (baseline, `ABL_NO_PRINCIPAL_LOCK`) |
| ACP complete without mandate  | denied                | authorized and captured (baseline)               |
| single use memory             | global                | per session (baseline, `ABL_NO_GLOBAL_NONCE`)    |
| budget counter                | PayPal reconciled (webhooks) | local counter only, no webhooks (baseline, `ABL_NO_BUDGET_RECON`) |
| request body parser           | strict                | Python's (baseline, `ABL_NO_STRICT_JSON`)        |
"""

from __future__ import annotations

import time
from collections.abc import Callable, Mapping
from dataclasses import dataclass
from datetime import UTC, datetime

from fastapi import FastAPI
from joserfc.jwk import ECKey
from sqlalchemy import Engine

from countersign.ablations import Ablations
from countersign.api.app import create_app
from countersign.canonical.jsonstrict import loads_strict
from countersign.completion import CaptureStage, CompleteCoordinator, GateLockAdapter
from countersign.constraints import CheckoutConstraintEvaluator, PaymentConstraintEvaluator
from countersign.cp import CpConfig, CredentialProvider, SpendLedger
from countersign.gate import CaptureGate
from countersign.gate.store import GateStore
from countersign.lock import PrincipalLock
from countersign.merchant.decision_log import LedgerDecisionLog
from countersign.merchant.keys import MerchantKey
from countersign.merchant.pg_reservations import PostgresReservationStore
from countersign.merchant.policy import policy_hash
from countersign.merchant.verify import CheckoutMandateVerifier, MerchantConfig
from countersign.paypal.client import PayPalClient
from countersign.protocols.acp.service import UnmandatedCompletion
from countersign.protocols.ucp.requests import JsonLoader
from countersign.runtime import Mode, RuntimeSettings
from countersign.webhooks import WebhookService


@dataclass(frozen=True)
class Wiring:
    """What the deployment supplies. None of it depends on the mode."""

    engine: Engine
    merchant_key: MerchantKey
    platform_key: ECKey | None
    paypal: PayPalClient
    public_base_url: str
    payee: Mapping[str, str]
    paypal_payee_merchant_id: str
    merchant_constraint_id: str
    webhook_id: str | None = None
    issuer: str | None = None
    clock: Callable[[], float] = time.time
    clock_us: Callable[[], int] | None = None
    paypal_now: Callable[[], datetime] | None = None


def effective_ablations(settings: RuntimeSettings) -> Ablations:
    """Baseline is the configuration with the pre-authorize check and the principal lock off."""
    if settings.mode is Mode.BASELINE:
        return Ablations(no_preauth_check=True, no_principal_lock=True)
    return settings.ablations


def build_app(settings: RuntimeSettings, wiring: Wiring) -> FastAPI:
    baseline = settings.mode is Mode.BASELINE
    flags = settings.ablations
    ablations = effective_ablations(settings)
    session_scoped = baseline or flags.no_global_nonce
    reconciled = not (baseline or flags.no_budget_recon)
    lenient_json = baseline or flags.no_strict_json

    engine, key = wiring.engine, wiring.merchant_key
    issuer = wiring.issuer or wiring.public_base_url
    clock_us = wiring.clock_us or _now_us
    paypal_now = wiring.paypal_now or (lambda: datetime.now(UTC))
    base = wiring.public_base_url
    config = CpConfig(
        issuer=issuer,
        signing_key=key,
        platform_key=wiring.platform_key,
        payee=wiring.payee,
        paypal_payee_merchant_id=wiring.paypal_payee_merchant_id,
        return_url=base.rstrip("/") + "/return",
        cancel_url=base.rstrip("/") + "/cancel",
        ablations=ablations,
    )

    merchant_store = PostgresReservationStore(
        engine, "merchant", clock_us, session_scoped=session_scoped
    )
    ledger = SpendLedger(clock_us)
    cp_store = PostgresReservationStore(engine, "cp", clock_us, session_scoped=session_scoped)
    merchant = CheckoutMandateVerifier(
        MerchantConfig(
            issuer=issuer,
            signing_key=key,
            published_keys=[key.public_jwk],
            platform_key=wiring.platform_key,
        ),
        merchant_store,
        LedgerDecisionLog(engine, policy_hash(), clock_us),
        wiring.clock,
        CheckoutConstraintEvaluator(wiring.merchant_constraint_id),
    )
    cp = CredentialProvider(
        config, engine, wiring.paypal, clock=wiring.clock, clock_us=clock_us,
        evaluator=PaymentConstraintEvaluator(), store=cp_store, ledger=ledger,
    )  # fmt: skip
    lock = PrincipalLock(
        engine, platform_key=wiring.platform_key, clock=wiring.clock, clock_us=clock_us,
        ablations=ablations,
    )  # fmt: skip
    gate_store = GateStore(engine, clock_us, ledger=ledger, session_scoped=session_scoped)
    stage: CaptureStage
    if baseline:
        from countersign.degraded.immediate_capture import ImmediateCapture

        stage = ImmediateCapture(
            config, engine, wiring.paypal, GateLockAdapter(lock), clock=wiring.clock,
            clock_us=clock_us, paypal_now=paypal_now, store=gate_store,
        )  # fmt: skip
    else:
        stage = CaptureGate(
            config, engine, wiring.paypal, GateLockAdapter(lock), clock=wiring.clock,
            clock_us=clock_us, paypal_now=paypal_now, store=gate_store,
        )  # fmt: skip
    coordinator = CompleteCoordinator(merchant, merchant_store, cp, stage, lock)

    unmandated: UnmandatedCompletion | None = None
    if baseline:
        from countersign.degraded.unmandated import NaiveUnmandatedCompletion

        unmandated = NaiveUnmandatedCompletion(config, engine, wiring.paypal, clock_us=clock_us)
    json_loader: JsonLoader = loads_strict
    if lenient_json:
        from countersign.degraded.lenient_json import loads_lenient

        json_loader = loads_lenient

    webhooks: WebhookService | None = None
    if reconciled and wiring.webhook_id and isinstance(stage, CaptureGate):
        webhooks = WebhookService(
            engine, wiring.paypal, wiring.webhook_id, settler=stage, clock_us=clock_us
        )

    return create_app(
        key=key, public_base_url=base, engine=engine, completion=coordinator, lock=lock,
        webhooks=webhooks, runtime=settings, unmandated=unmandated, json_loader=json_loader,
        clock_us=clock_us,
    )  # fmt: skip


def _now_us() -> int:
    return time.time_ns() // 1000
