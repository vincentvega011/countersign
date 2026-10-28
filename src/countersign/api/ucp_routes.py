"""The UCP checkout REST binding, served under the endpoint the profile advertises.

Paths (vendored `shopping/checkout/rest.md`, "Operations"), relative to `<base>/ucp/v1`:
`POST /checkout-sessions`, `GET` and `PUT /checkout-sessions/{id}`, `POST .../complete` and
`POST .../cancel`.

Every request must carry a `UCP-Agent` header with a `profile="<url>"` member (the spec marks it
required); a missing or malformed one is `invalid_profile_url` (HTTP 400). The profile is not
fetched yet, so no capability negotiation happens here and AP2 protection is enforced for every
session (docs/PROTOCOL.md Decision 17).

Every response that carries a checkout is signed (`ap2.merchant_authorization`, Decision 18) after
its warnings are attached; error responses with no checkout are not.

Protocol failures answer with an HTTP 4xx or 5xx and a `{code, content}` body. Business outcomes
(including a missing checkout) answer 200 with the UCP envelope. Any unexpected exception answers
500 with no detail (INV-10).
"""

from __future__ import annotations

import re
from collections.abc import Callable
from typing import Any

import structlog
from fastapi import APIRouter, FastAPI, Request
from fastapi.responses import JSONResponse
from starlette.concurrency import run_in_threadpool

from countersign.merchant.authorization import sign_checkout
from countersign.merchant.keys import MerchantKey
from countersign.protocols.ucp import messages as m
from countersign.protocols.ucp.requests import (
    check_content_type,
    ignored_members,
    parse_checkout_request,
    parse_complete_request,
    parse_json_object,
    read_body,
)
from countersign.protocols.ucp.service import Result, UcpService

log = structlog.get_logger()

_PROFILE_MEMBER = re.compile(r'(?:^|,)\s*profile\s*=\s*"([^"\\]{1,2048})"')
_NO_STORE = {"Cache-Control": "no-store"}


def check_agent_header(value: str | None) -> None:
    """Require `UCP-Agent: profile="https://..."`. The profile is not fetched (see module doc)."""
    found = _PROFILE_MEMBER.search(value or "")
    if found is None or not found.group(1).startswith(("https://", "http://")):
        raise m.ProtocolError(
            400,
            m.INVALID_PROFILE_URL,
            'UCP-Agent must carry profile="<URL of the platform profile>"',
        )


def _json(status: int, body: dict[str, Any]) -> JSONResponse:
    return JSONResponse(body, status_code=status, headers=_NO_STORE)


def _respond(
    result: Result, key: MerchantKey, request_body: dict[str, Any] | None = None
) -> JSONResponse:
    body = result.body()
    if request_body is not None and result.record is not None:
        ignored = ignored_members(request_body, body)
        if ignored:
            extra = [
                m.warning_message(
                    m.FIELD_IGNORED,
                    f"{member} is set by the business; the supplied value was ignored.",
                    path,
                )
                for path, member in ignored
            ]
            body["messages"] = [*body.get("messages", []), *extra]
    if result.record is not None:
        # Signed last: the signature covers every member of the response except `ap2`.
        body = sign_checkout(body, key)
    return _json(result.http_status, body)


def install(app: FastAPI, service: UcpService, base_path: str, key: MerchantKey) -> None:
    """Mount the checkout routes and the error handlers on `app`."""
    router = APIRouter(prefix=base_path)

    async def prepare(request: Request, *, body: str) -> dict[str, Any]:
        """Header and body checks shared by every operation. `body` is `none`, `optional` or `required`."""
        check_agent_header(request.headers.get("UCP-Agent"))
        if body == "none":
            return {}
        raw = await read_body(request.stream())
        if raw.strip():
            check_content_type(request.headers.get("Content-Type"))
        return parse_json_object(raw, allow_empty=body == "optional")

    @router.post("/checkout-sessions")
    async def create(request: Request) -> JSONResponse:
        data = await prepare(request, body="required")
        req = parse_checkout_request(data, update=False)
        return _respond(await run_in_threadpool(service.create, req), key, data)

    @router.get("/checkout-sessions/{checkout_id}")
    async def get(checkout_id: str, request: Request) -> JSONResponse:
        await prepare(request, body="none")
        return _respond(await run_in_threadpool(service.get, checkout_id), key)

    @router.put("/checkout-sessions/{checkout_id}")
    async def update(checkout_id: str, request: Request) -> JSONResponse:
        data = await prepare(request, body="required")
        req = parse_checkout_request(data, update=True)
        result = await run_in_threadpool(service.update, checkout_id, req)
        return _respond(result, key, data)

    @router.post("/checkout-sessions/{checkout_id}/complete")
    async def complete(checkout_id: str, request: Request) -> JSONResponse:
        data = await prepare(request, body="required")
        req = parse_complete_request(data)
        return _respond(await run_in_threadpool(service.complete, checkout_id, req), key)

    @router.post("/checkout-sessions/{checkout_id}/cancel")
    async def cancel(checkout_id: str, request: Request) -> JSONResponse:
        await prepare(request, body="optional")
        return _respond(await run_in_threadpool(service.cancel, checkout_id), key)

    app.include_router(router)

    async def protocol_error(_: Request, exc: Exception) -> JSONResponse:
        assert isinstance(exc, m.ProtocolError)
        return _json(exc.status, exc.body())

    async def internal_error(request: Request, exc: Exception) -> JSONResponse:
        # Fail closed (INV-10). The exception type is logged; its message may hold request data.
        log.error("ucp_internal_error", path=request.url.path, error=type(exc).__name__)
        return _json(500, {"code": m.INTERNAL_ERROR, "content": "An internal error occurred."})

    handlers: dict[type[Exception], Callable[..., Any]] = {
        m.ProtocolError: protocol_error,
        Exception: internal_error,
    }
    for exc_type, handler in handlers.items():
        app.add_exception_handler(exc_type, handler)
