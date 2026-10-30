"""Application factory. The service refuses to start without a valid merchant key."""

from __future__ import annotations

import inspect
import os
from collections.abc import Callable
from typing import Any

from fastapi import FastAPI, Request, Response
from fastapi.responses import JSONResponse
from sqlalchemy import Engine, create_engine

from countersign.api.acp_routes import install as install_acp
from countersign.api.ucp_routes import install as install_ucp
from countersign.api.webhook_routes import install as install_webhooks
from countersign.canonical.jsonstrict import loads_strict
from countersign.catalog.catalog import Catalog, load_catalog
from countersign.lock import LockPort
from countersign.merchant.keys import MerchantKey, load_merchant_key
from countersign.merchant.policy import policy_hash
from countersign.protocols.acp.service import AcpService, UnmandatedCompletion
from countersign.protocols.ucp.profile import REST_BASE_PATH, build_profile
from countersign.protocols.ucp.requests import JsonLoader
from countersign.protocols.ucp.service import CompletionPort, UcpService, now_us
from countersign.runtime import ABLATIONS_HEADER, MODE_HEADER, RuntimeSettings
from countersign.webhooks import WebhookService

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
    webhooks: WebhookService | None = None,
    runtime: RuntimeSettings | None = None,
    unmandated: UnmandatedCompletion | None = None,
    json_loader: JsonLoader = loads_strict,
) -> FastAPI:
    """Create the app. Without an explicit `key`, load `MERCHANT_KEY_PATH` or fail.

    The profile is built once at start, so a bad key or base URL stops the process here instead of
    surfacing on the first request. The engine is created from `DATABASE_URL` when not given; it
    does not connect until the first checkout request. `completion` is the Merchant and Credential
    Provider wiring (`countersign.completion`); without it `complete` never succeeds (fail closed).
    `lock` is the shared principal lock; the composition root passes the same one to the completion
    coordinator and to the capture gate. `runtime` is the mode and the ablations chosen at start: they
    are reported by `GET /health` and by a header on every response, and they change nothing here.
    `unmandated` and `json_loader` are the composition root's injection points for the evaluation
    modes; the defaults are the `full` behaviour (deny, strict).
    """
    runtime = runtime or RuntimeSettings()
    labels = {MODE_HEADER: runtime.mode.value}
    if runtime.active_ablations:
        labels[ABLATIONS_HEADER] = ",".join(runtime.active_ablations)
    if key is None:
        key = load_merchant_key(os.environ.get("MERCHANT_KEY_PATH", DEFAULT_KEY_PATH))
    base = public_base_url or os.environ.get("PUBLIC_BASE_URL", DEFAULT_BASE_URL)
    profile = build_profile(public_base_url=base, key=key)
    if engine is None:
        engine = create_engine(os.environ.get("DATABASE_URL", DEFAULT_DATABASE_URL))

    app = FastAPI(title="Countersign", docs_url=None, redoc_url=None, openapi_url=None)
    app.state.merchant_key = key
    app.state.engine = engine
    app.state.runtime = runtime

    @app.middleware("http")
    async def label_mode(request: Request, call_next: Callable[[Request], Any]) -> Response:
        response: Response = await call_next(request)
        response.headers.update(labels)
        return response

    @app.get("/health")
    def health() -> JSONResponse:
        body = {
            "status": "ok",
            "mode": runtime.mode.value,
            "app_env": runtime.app_env,
            "ablations": list(runtime.active_ablations),
        }
        return JSONResponse(body, headers={"Cache-Control": "no-store"})

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
    app.state.ucp = service
    install_ucp(app, service, REST_BASE_PATH, key, json_loader)
    _label_server_errors(app, labels)
    if webhooks is not None:
        install_webhooks(app, webhooks)
    if lock is not None:
        # ACP needs the shared lock to decide anything; without one it is not served (fail closed).
        acp = AcpService(
            engine,
            catalog or load_catalog(),
            policy_hash=policy_hash(),
            lock=lock,
            unmandated=unmandated,
            clock_us=clock_us or now_us,
            order_base_url=f"{base.rstrip('/')}/checkout_sessions",
        )
        app.state.acp = acp
        install_acp(app, acp, json_loader)
    return app


def _label_server_errors(app: FastAPI, labels: dict[str, str]) -> None:
    """The catch-all 500 handler runs outside the middleware stack, so it adds the labels itself."""
    handler = app.exception_handlers.get(Exception)
    if handler is None:
        return

    async def labelled(request: Request, exc: Exception) -> Response:
        produced = handler(request, exc)
        response: Response = await produced if inspect.isawaitable(produced) else produced
        response.headers.update(labels)
        return response

    app.add_exception_handler(Exception, labelled)
