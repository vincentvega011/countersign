"""The process entry point: `uvicorn countersign.main:create --factory`.

The mode and the ablations are read and checked FIRST, before a key file, the database or PayPal is
touched, so a refused configuration (an ablation with `APP_ENV=demo`, an unknown `CS_MODE`, an
ablation together with baseline) stops the process with a clear message and no side effect
(INV-10). A start in `baseline` is logged at warning level with a line that cannot be mistaken for
the real thing; the same mode is on `GET /health` and in the `X-Countersign-Mode` response header.

Environment, besides the mode variables in `countersign.runtime`: `DATABASE_URL`,
`MERCHANT_KEY_JSON` or `MERCHANT_KEY_PATH`, `PLATFORM_KEY_JSON` or `PLATFORM_KEY_PATH` (the ES256 JWK of the trusted platform provider, Decision
5, private half included: it signs mandates after consent, the public half verifies them; without
it no mandate verifies and no consent is accepted), `PUBLIC_BASE_URL`, `MERCHANT_ID`, `MERCHANT_NAME`,
`PAYPAL_MERCHANT_ID` and the PayPal sandbox variables of `countersign.paypal.config`.
"""

from __future__ import annotations

import importlib
import json
import os
from collections.abc import Mapping
from pathlib import Path
from typing import cast

import structlog
from fastapi import FastAPI
from joserfc.jwk import ECKey
from sqlalchemy import create_engine

from countersign import selfcheck
from countersign.api import ratelimit
from countersign.api.app import DEFAULT_BASE_URL, DEFAULT_KEY_PATH, seed_counts
from countersign.canonical.jsonstrict import loads_strict
from countersign.composition import Wiring, build_app
from countersign.dburl import database_url
from countersign.merchant.keys import MerchantKey, load_merchant_key, validate_jwk
from countersign.paypal.client import PayPalClient
from countersign.paypal.config import PayPalConfig
from countersign.runtime import PUBLIC_ENVS, Mode, RuntimeSettings

log = structlog.get_logger("countersign.startup")

# `scripts/demo.sh` starts the app with this placeholder so the PayPal-free local demo runs. It is not a
# credential: the app treats it as "no PayPal credentials" (selfcheck says so) and never sends it anywhere
# useful, since PayPal rejects it and every purchase then fails closed (INV-10).
NO_CREDENTIALS = "local-demo-no-credentials"


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


def _platform_key(env: Mapping[str, str]) -> ECKey | None:
    """The platform key from `PLATFORM_KEY_JSON` (a host with no secret files, such as Render) or from
    the file named by `PLATFORM_KEY_PATH`. The JSON form is parsed with the strict loader."""
    inline = env.get("PLATFORM_KEY_JSON")
    if inline:
        parsed = loads_strict(inline.encode())
        if not isinstance(parsed, dict):
            raise ValueError("PLATFORM_KEY_JSON must hold one JSON object")
        return ECKey.import_key(cast(dict[str, str | list[str]], parsed))
    path = env.get("PLATFORM_KEY_PATH")
    return ECKey.import_key(json.loads(Path(path).read_text())) if path else None


def _merchant_key(env: Mapping[str, str]) -> MerchantKey:
    """The merchant key from `MERCHANT_KEY_JSON` or from the file at `MERCHANT_KEY_PATH`. Either way it
    goes through the same validation (`validate_jwk`): curve, algorithm, thumbprint `kid`."""
    inline = env.get("MERCHANT_KEY_JSON")
    if inline:
        return validate_jwk(loads_strict(inline.encode()))
    return load_merchant_key(env.get("MERCHANT_KEY_PATH", DEFAULT_KEY_PATH))


def wiring_from_env(env: Mapping[str, str]) -> Wiring:
    platform_key = _platform_key(env)
    paypal_config = PayPalConfig.from_env(env)
    merchant_id = env.get("MERCHANT_ID", "merchant-1")
    return Wiring(
        engine=create_engine(database_url(env), pool_size=10),
        merchant_key=_merchant_key(env),
        platform_key=platform_key,
        paypal=PayPalClient(paypal_config),
        public_base_url=env.get("PUBLIC_BASE_URL")
        or env.get("RENDER_EXTERNAL_URL")
        or DEFAULT_BASE_URL,
        payee={"id": merchant_id, "name": env.get("MERCHANT_NAME", "Countersign demo store")},
        paypal_payee_merchant_id=env.get("PAYPAL_MERCHANT_ID", ""),
        merchant_constraint_id=merchant_id,
        webhook_id=paypal_config.webhook_id or None,
        data_source="simulator" if paypal_config.allow_non_sandbox else "live_sandbox",
        paypal_configured=bool(
            paypal_config.client_id
            and paypal_config.client_secret
            and NO_CREDENTIALS not in (paypal_config.client_id, paypal_config.client_secret)
        ),
    )


def install_attack_runs(app: FastAPI, settings: RuntimeSettings, env: Mapping[str, str]) -> None:
    """The dashboard's "Run attack" launcher (Decision 131): dev and eval by default, demo only when an
    administrator database is named, never elsewhere. Missing evaluation code means no launcher."""
    from countersign.dashboard.service import ATTACK_RUN_ENVS

    if settings.app_env not in ATTACK_RUN_ENVS or env.get("ATTACK_RUNS") == "0":
        return
    if settings.app_env == "demo" and not env.get("EVAL_DATABASE_ADMIN_URL"):
        return
    dashboard = getattr(app.state, "dashboard", None)
    if dashboard is None:
        return
    try:  # imported by name so the server's type check never follows into the evaluation code
        launcher = importlib.import_module("eval.launch").AttackLauncher()
    except ImportError:
        log.info("attack_runs_unavailable", reason="evaluation code not installed")
        return
    dashboard.attack_launcher = launcher


def install_rate_limit(app: FastAPI, settings: RuntimeSettings, env: Mapping[str, str]) -> None:
    """On in public environments always; in dev and eval only with `RATE_LIMIT=1` (the evaluation hammers
    the app on purpose). No variable turns it off in a public environment."""
    wanted = settings.app_env in PUBLIC_ENVS or env.get("RATE_LIMIT") == "1"
    if wanted:
        ratelimit.install(app, ratelimit.RateLimiter(trust_proxy=env.get("TRUST_PROXY") == "1"))


def create(env: Mapping[str, str] | None = None) -> FastAPI:
    source = os.environ if env is None else env
    settings = RuntimeSettings.from_env(source)  # raises ModeRefused before anything else runs
    announce(settings)
    app = build_app(settings, wiring_from_env(source))
    install_attack_runs(app, settings, source)
    install_rate_limit(app, settings, source)
    report = selfcheck.report(
        settings,
        source,
        dashboard=getattr(app.state, "dashboard", None),
        webhook_configured=bool(getattr(app.state, "webhook_configured", False)),
        rate_limited=hasattr(app.state, "rate_limiter"),
        seed=seed_counts(settings, app.state.engine),
    )
    log.info("selfcheck", **report)
    return app
