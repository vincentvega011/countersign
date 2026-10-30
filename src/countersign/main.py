"""The process entry point: `uvicorn countersign.main:create --factory`.

The mode and the ablations are read and checked FIRST, before a key file, the database or PayPal is
touched, so a refused configuration (an ablation with `APP_ENV=demo`, an unknown `CS_MODE`, an
ablation together with baseline) stops the process with a clear message and no side effect
(INV-10). A start in `baseline` is logged at warning level with a line that cannot be mistaken for
the real thing; the same mode is on `GET /health` and in the `X-Countersign-Mode` response header.

Environment, besides the mode variables in `countersign.runtime`: `DATABASE_URL`,
`MERCHANT_KEY_PATH`, `PLATFORM_KEY_PATH` (the public JWK of the trusted platform provider, Decision
5; without it no mandate verifies), `PUBLIC_BASE_URL`, `MERCHANT_ID`, `MERCHANT_NAME`,
`PAYPAL_MERCHANT_ID` and the PayPal sandbox variables of `countersign.paypal.config`.
"""

from __future__ import annotations

import json
import os
from collections.abc import Mapping
from pathlib import Path

import structlog
from fastapi import FastAPI
from joserfc.jwk import ECKey
from sqlalchemy import create_engine

from countersign.api.app import DEFAULT_BASE_URL, DEFAULT_DATABASE_URL, DEFAULT_KEY_PATH
from countersign.composition import Wiring, build_app
from countersign.merchant.keys import load_merchant_key
from countersign.paypal.client import PayPalClient
from countersign.paypal.config import PayPalConfig
from countersign.runtime import Mode, RuntimeSettings

log = structlog.get_logger("countersign.startup")


def announce(settings: RuntimeSettings) -> None:
    if settings.mode is Mode.BASELINE:
        log.warning(
            "BASELINE MODE: the capture gate, principal lock, pre-authorize check, global single "
            "use, reconciled budgets and strict JSON are OFF on purpose. Evaluation only.",
            mode=settings.mode.value,
            app_env=settings.app_env,
        )
    elif settings.ablations.any:
        log.warning(
            "ABLATION ACTIVE: full mode with protections switched off. Evaluation only.",
            mode=settings.mode.value,
            ablations=list(settings.active_ablations),
        )
    else:
        log.info("startup", mode=settings.mode.value, app_env=settings.app_env)


def wiring_from_env(env: Mapping[str, str]) -> Wiring:
    platform_path = env.get("PLATFORM_KEY_PATH")
    platform_key = (
        ECKey.import_key(json.loads(Path(platform_path).read_text())) if platform_path else None
    )
    paypal_config = PayPalConfig.from_env(env)
    merchant_id = env.get("MERCHANT_ID", "merchant-1")
    return Wiring(
        engine=create_engine(env.get("DATABASE_URL", DEFAULT_DATABASE_URL), pool_size=10),
        merchant_key=load_merchant_key(env.get("MERCHANT_KEY_PATH", DEFAULT_KEY_PATH)),
        platform_key=platform_key,
        paypal=PayPalClient(paypal_config),
        public_base_url=env.get("PUBLIC_BASE_URL", DEFAULT_BASE_URL),
        payee={"id": merchant_id, "name": env.get("MERCHANT_NAME", "Countersign demo store")},
        paypal_payee_merchant_id=env.get("PAYPAL_MERCHANT_ID", ""),
        merchant_constraint_id=merchant_id,
        webhook_id=paypal_config.webhook_id or None,
    )


def create(env: Mapping[str, str] | None = None) -> FastAPI:
    source = os.environ if env is None else env
    settings = RuntimeSettings.from_env(source)  # raises ModeRefused before anything else runs
    announce(settings)
    return build_app(settings, wiring_from_env(source))
