"""Application factory. The service refuses to start without a valid merchant key."""

from __future__ import annotations

import os
from typing import Any

from fastapi import FastAPI
from fastapi.responses import JSONResponse

from countersign.merchant.keys import MerchantKey, load_merchant_key
from countersign.protocols.ucp.profile import build_profile

DEFAULT_KEY_PATH = "secrets/merchant_es256.jwk.json"
DEFAULT_BASE_URL = "http://localhost:8000"


def create_app(*, key: MerchantKey | None = None, public_base_url: str | None = None) -> FastAPI:
    """Create the app. Without an explicit `key`, load `MERCHANT_KEY_PATH` or fail.

    The profile is built once at start, so a bad key or base URL stops the process here instead of
    surfacing on the first request.
    """
    if key is None:
        key = load_merchant_key(os.environ.get("MERCHANT_KEY_PATH", DEFAULT_KEY_PATH))
    base = public_base_url or os.environ.get("PUBLIC_BASE_URL", DEFAULT_BASE_URL)
    profile = build_profile(public_base_url=base, key=key)

    app = FastAPI(title="Countersign", docs_url=None, redoc_url=None)
    app.state.merchant_key = key

    @app.get("/.well-known/ucp")
    def well_known_ucp() -> JSONResponse:
        body: dict[str, Any] = profile
        return JSONResponse(body, headers={"Cache-Control": "public, max-age=300"})

    return app
