"""The ACP checkout REST binding, at the paths the vendored OpenAPI defines.

`POST /checkout_sessions`, `GET` and `POST /checkout_sessions/{id}` (update), `POST .../complete` and
`POST .../cancel`, plus a rejecting `POST /agentic_commerce/delegate_payment`. Every POST needs an
`Idempotency-Key` (the spec returns 400 `idempotency_key_required` without one). Replays are not
cached (docs/LIMITATIONS.md L24), so a repeated create makes a second session.

Principal. The agent identity is the `Countersign-Delegation` header and its negotiated capabilities
the `Countersign-Capabilities` header, the same two headers the UCP adapter reads, so both protocols
resolve to the same `Principal` (docs/PROTOCOL.md Decision 51). This module reads headers and calls
the service; it holds no lock logic.

Every failure is an ACP `Error`. An unexpected exception answers 500 `processing_error` with no
detail (INV-10); it is caught here so the UCP-shaped global handler never speaks for ACP.
"""

from __future__ import annotations

from collections.abc import Awaitable, Callable
from typing import Any

import structlog
from fastapi import APIRouter, FastAPI, Request
from fastapi.responses import JSONResponse
from starlette.concurrency import run_in_threadpool

from countersign.canonical.jsonstrict import loads_strict
from countersign.mandates import MAX_MANDATE_CHARS
from countersign.protocols.acp import errors as e
from countersign.protocols.acp.requests import (
    SUPPORTED_VERSION,
    JsonLoader,
    parse_cancel,
    parse_complete,
    parse_create,
    parse_json_object,
    parse_update,
    read_body,
)
from countersign.protocols.acp.service import AcpContext, AcpService, Session

log = structlog.get_logger()

DELEGATION_HEADER = "Countersign-Delegation"
CAPABILITIES_HEADER = "Countersign-Capabilities"
_NO_STORE = {"Cache-Control": "no-store"}


def context(request: Request) -> AcpContext:
    value = request.headers.get(DELEGATION_HEADER)
    raw = request.headers.get(CAPABILITIES_HEADER, "")
    capabilities = tuple(t.strip() for t in raw[:2048].split(",") if t.strip())
    return AcpContext(value if value and len(value) <= MAX_MANDATE_CHARS else None, capabilities)


def _headers(request: Request) -> dict[str, str]:
    out = dict(_NO_STORE)
    for name in ("Request-Id", "Idempotency-Key"):
        value = request.headers.get(name)
        if value and len(value) <= 255 and value.isprintable():
            out[name] = value
    return out


def _error(request: Request, error: e.AcpError) -> JSONResponse:
    return JSONResponse(error.body(), status_code=error.status, headers=_headers(request))


def _checks(request: Request, *, post: bool) -> None:
    version = request.headers.get("API-Version")
    if version is not None and version != SUPPORTED_VERSION:
        raise e.AcpError(400, "unsupported_api_version", "This API version is not supported.")
    if post and not request.headers.get("Idempotency-Key"):
        raise e.AcpError(400, "idempotency_key_required", "Idempotency-Key header is required")


async def _body(
    request: Request, *, allow_empty: bool = False, loader: JsonLoader = loads_strict
) -> dict[str, Any]:
    media = request.headers.get("Content-Type", "").split(";", 1)[0].strip().lower()
    raw = await read_body(request.stream())
    if raw.strip() and media != "application/json":
        raise e.AcpError(400, "invalid_content_type", "Content-Type must be application/json")
    return parse_json_object(raw, allow_empty=allow_empty, loader=loader)


def install(app: FastAPI, service: AcpService, json_loader: JsonLoader = loads_strict) -> None:
    router = APIRouter()

    async def read(request: Request, *, allow_empty: bool = False) -> dict[str, Any]:
        return await _body(request, allow_empty=allow_empty, loader=json_loader)

    async def guarded(
        request: Request, work: Callable[[], Awaitable[Session | e.AcpError]]
    ) -> JSONResponse:
        try:
            outcome = await work()
            if isinstance(outcome, e.AcpError):
                return _error(request, outcome)
            return JSONResponse(
                outcome.body(), status_code=outcome.http_status, headers=_headers(request)
            )
        except e.AcpError as error:
            return _error(request, error)
        except Exception as error:  # noqa: BLE001 - INV-10: nothing escapes as a success
            log.error("acp_internal_error", error=type(error).__name__)
            return _error(request, e.internal())

    @router.post("/checkout_sessions")
    async def create(request: Request) -> JSONResponse:
        async def work() -> Session:
            _checks(request, post=True)
            req = parse_create(await read(request))
            return await run_in_threadpool(service.create, req, context(request))

        return await guarded(request, work)

    @router.get("/checkout_sessions/{session_id}")
    async def get(session_id: str, request: Request) -> JSONResponse:
        async def work() -> Session:
            _checks(request, post=False)
            return await run_in_threadpool(service.get, session_id)

        return await guarded(request, work)

    @router.post("/checkout_sessions/{session_id}")
    async def update(session_id: str, request: Request) -> JSONResponse:
        async def work() -> Session:
            _checks(request, post=True)
            req = parse_update(await read(request))
            return await run_in_threadpool(service.update, session_id, req, context(request))

        return await guarded(request, work)

    @router.post("/checkout_sessions/{session_id}/complete")
    async def complete(session_id: str, request: Request) -> JSONResponse:
        async def work() -> Session:
            _checks(request, post=True)
            parse_complete(await read(request))
            return await run_in_threadpool(service.complete, session_id, context(request))

        return await guarded(request, work)

    @router.post("/checkout_sessions/{session_id}/cancel")
    async def cancel(session_id: str, request: Request) -> JSONResponse:
        async def work() -> Session:
            _checks(request, post=True)
            parse_cancel(await read(request, allow_empty=True))
            return await run_in_threadpool(service.cancel, session_id)

        return await guarded(request, work)

    @router.post("/agentic_commerce/delegate_payment")
    async def delegate_payment(request: Request) -> JSONResponse:
        async def work() -> e.AcpError:
            _checks(request, post=True)
            await read(request)  # read through the strict loader, then rejected whatever it says
            return await run_in_threadpool(service.reject_delegated_payment, context(request))

        return await guarded(request, work)

    app.include_router(router)
