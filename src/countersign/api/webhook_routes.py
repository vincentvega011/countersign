"""`POST /webhooks/paypal`.

The route reads the raw body with a size limit and hands headers and bytes to `WebhookService`, which
does everything else. Answers: 200 accepted (verified, including a duplicate or an event Countersign
does not act on), 400 malformed, 401 unverified, 503 try again, 500 internal. Bodies of the answers are
fixed short JSON; nothing from the request is echoed. The route is the only thing outside `webhooks/`
that knows about HTTP.
"""

from __future__ import annotations

from fastapi import APIRouter, FastAPI, Request
from fastapi.responses import JSONResponse
from starlette.concurrency import run_in_threadpool

from countersign.webhooks import WebhookService
from countersign.webhooks.events import MAX_BODY_BYTES


async def _read(request: Request) -> bytes | None:
    chunks: list[bytes] = []
    size = 0
    async for chunk in request.stream():
        size += len(chunk)
        if size > MAX_BODY_BYTES:
            return None
        chunks.append(chunk)
    return b"".join(chunks)


def install(app: FastAPI, service: WebhookService) -> None:
    router = APIRouter()

    @router.post("/webhooks/paypal")
    async def paypal_webhook(request: Request) -> JSONResponse:
        raw = await _read(request)
        if raw is None:
            result = await run_in_threadpool(service.too_large)
        else:
            result = await run_in_threadpool(service.handle, dict(request.headers), raw)
        return JSONResponse(
            {"status": "ok" if result.status == 200 else "not_accepted", "outcome": result.outcome},
            status_code=result.status,
            headers={"Cache-Control": "no-store"},
        )

    app.include_router(router)
