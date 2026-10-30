"""Application factory. The service refuses to start without a valid merchant key."""

from __future__ import annotations

import os
from collections.abc import Callable
from typing import Any

from fastapi import FastAPI
from fastapi.responses import JSONResponse
from sqlalchemy import Engine, create_engine

from countersign.api.ucp_routes import install as install_ucp
from countersign.catalog.catalog import Catalog, load_catalog
from countersign.merchant.keys import MerchantKey, load_merchant_key
from countersign.merchant.policy import policy_hash
from countersign.protocols.ucp.profile import REST_BASE_PATH, build_profile
from countersign.protocols.ucp.service import CompletionPort, LockPort, UcpService, now_us

DEFAULT_KEY_PATH = "secrets/merchant_es256.jwk.json"
DEFAULT_BASE_URL = "http://localhost:8000"
DEFAULT_DATABASE_URL = "postgresql+psycopg://countersign:countersign@localhost:5432/countersign"


def create_app(
    *,
    key: MerchantKey | None = None,
    public_base_url: str | None = None,
    engine: Engine | None = None,
    catalog: Catalog | None = None,
    clock_us: Callable[[], int] | None = None,
    completion: CompletionPort | None = None,
    lock: LockPort | None = None,
) -> FastAPI:
    """Create the app. Without an explicit `key`, load `MERCHANT_KEY_PATH` or fail.

    The profile is built once at start, so a bad key or base URL stops the process here instead of
    surfacing on the first request. The engine is created from `DATABASE_URL` when not given; it
    does not connect until the first checkout request. `completion` is the Merchant and Credential
    Provider wiring (`countersign.completion`); without it `complete` never succeeds (fail closed).
    `lock` is the shared principal lock; the composition root passes the same one to the completion
    coordinator and to the capture gate.
    """
    if key is None:
        key = load_merchant_key(os.environ.get("MERCHANT_KEY_PATH", DEFAULT_KEY_PATH))
    base = public_base_url or os.environ.get("PUBLIC_BASE_URL", DEFAULT_BASE_URL)
    profile = build_profile(public_base_url=base, key=key)
    if engine is None:
        engine = create_engine(os.environ.get("DATABASE_URL", DEFAULT_DATABASE_URL))

    app = FastAPI(title="Countersign", docs_url=None, redoc_url=None, openapi_url=None)
    app.state.merchant_key = key
    app.state.engine = engine

    @app.get("/.well-known/ucp")
    def well_known_ucp() -> JSONResponse:
        body: dict[str, Any] = profile
        return JSONResponse(body, headers={"Cache-Control": "public, max-age=300"})

    service = UcpService(
        engine,
        catalog or load_catalog(),
        policy_hash=policy_hash(),
        clock_us=clock_us or now_us,
        completion=completion,
        lock=lock,
        order_base_url=f"{base.rstrip('/')}{REST_BASE_PATH}/checkout-sessions",
    )
    install_ucp(app, service, REST_BASE_PATH, key)
    return app
