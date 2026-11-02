"""`POST /trusted-surface/keys/challenge`, `POST /trusted-surface/keys`, `POST /trusted-surface/keys/revoke`
and `POST /trusted-surface/consent`.

The routes read the raw body with a size limit, parse it with the strict JSON loader (duplicate keys,
NaN and Infinity are refused before anything else, INV-8), check the shape, and hand typed values to
`TrustedSurface`. Answers are fixed short JSON with `Cache-Control: no-store`; a refusal is
`{"code": "<stable code>"}` and nothing from the request is echoed. A body that is not even the right
shape is logged by `reject_request` before the answer, like every other refusal (INV-12).
"""

from __future__ import annotations

from typing import Any

from fastapi import APIRouter, FastAPI, Request
from fastapi.responses import JSONResponse
from starlette.concurrency import run_in_threadpool

from countersign.canonical.jsonstrict import StrictJsonError, loads_strict
from countersign.trusted_surface import Refused, TrustedSurface
from countersign.trusted_surface.service import (
    LOG_KIND_CONSENT_REFUSED,
    LOG_KIND_REFUSED,
    Authorizer,
)

MAX_BODY_BYTES = 16 * 1024
BASE = "/trusted-surface/keys"
_NO_STORE = {"Cache-Control": "no-store"}
_REVOKE_MEMBERS = frozenset(
    {"challenge_id", "customer_id", "target", "signer", "origin", "signature"}
)
_CONSENT_MEMBERS = frozenset({"record", "signature", "agent_jwk"})
_REGISTER_MEMBERS = frozenset(
    {"jwk", "challenge_id", "customer_id", "origin", "signature", "authorizer"}
)


def _refusal(error: Refused) -> JSONResponse:
    return JSONResponse({"code": error.code}, status_code=error.status, headers=_NO_STORE)


async def _read(request: Request) -> bytes | None:
    chunks: list[bytes] = []
    size = 0
    async for chunk in request.stream():
        size += len(chunk)
        if size > MAX_BODY_BYTES:
            return None
        chunks.append(chunk)
    return b"".join(chunks)


def _object(
    service: TrustedSurface, request: Request, raw: bytes | None, kind: str = LOG_KIND_REFUSED
) -> dict[str, Any]:
    """The body as an object, or a logged `Refused`."""
    if raw is None:
        raise service.reject_request("request_too_large", kind)
    media = request.headers.get("content-type", "").split(";")[0].strip().lower()
    if media != "application/json":
        raise service.reject_request("malformed_request", kind)
    try:
        value = loads_strict(raw, max_bytes=MAX_BODY_BYTES)
    except StrictJsonError:
        raise service.reject_request("malformed_request", kind) from None
    if not isinstance(value, dict):
        raise service.reject_request("malformed_request", kind)
    return value


def _authorizer(service: TrustedSurface, value: object) -> Authorizer | None:
    if value is None:
        return None
    if (
        not isinstance(value, dict)
        or set(value) != {"thumbprint", "signature"}
        or not all(isinstance(v, str) and len(v) <= 128 for v in value.values())
    ):
        raise service.reject_request("malformed_request")
    return Authorizer(value["thumbprint"], value["signature"])


def install(app: FastAPI, service: TrustedSurface) -> None:
    router = APIRouter(prefix=BASE)
    consent_get = APIRouter(prefix="/trusted-surface")

    @router.post("/challenge")
    async def challenge(request: Request) -> JSONResponse:
        raw = await _read(request)

        def run() -> JSONResponse:
            try:
                body = _object(service, request, raw)
                if set(body) != {"purpose"}:
                    raise service.reject_request("malformed_request")
                issued = service.issue_challenge(body["purpose"])
            except Refused as error:
                return _refusal(error)
            return JSONResponse(
                {
                    "challenge_id": issued.challenge_id,
                    "nonce": issued.nonce,
                    "purpose": issued.purpose,
                    "issued_at": issued.issued_at,
                    "expires_us": issued.expires_us,
                },
                headers=_NO_STORE,
            )

        return await run_in_threadpool(run)

    @router.post("")
    async def register(request: Request) -> JSONResponse:
        raw = await _read(request)
        origin_header = request.headers.get("origin")

        def run() -> JSONResponse:
            try:
                body = _object(service, request, raw)
                if (
                    not {"jwk", "challenge_id", "origin", "signature"} <= set(body)
                    or not set(body) <= _REGISTER_MEMBERS
                ):
                    raise service.reject_request("malformed_request")
                enrolled = service.register(
                    jwk=body["jwk"],
                    challenge_id=body["challenge_id"],
                    customer_id=body.get("customer_id"),
                    origin=body["origin"],
                    signature=body["signature"],
                    authorizer=_authorizer(service, body.get("authorizer")),
                    origin_header=origin_header,
                )
            except Refused as error:
                return _refusal(error)
            return JSONResponse(
                {
                    "customer_id": enrolled.customer_id,
                    "thumbprint": enrolled.thumbprint,
                    "new_customer": enrolled.new_customer,
                    "new_key": enrolled.new_key,
                },
                status_code=201 if enrolled.new_key else 200,
                headers=_NO_STORE,
            )

        return await run_in_threadpool(run)

    @consent_get.get("/store")
    def store() -> JSONResponse:
        # The store's own name and item titles, so a request's text is never an agent's.
        return JSONResponse(service.store_info(), headers=_NO_STORE)

    @router.post("/revoke")
    async def revoke(request: Request) -> JSONResponse:
        raw = await _read(request)
        origin_header = request.headers.get("origin")

        def run() -> JSONResponse:
            try:
                body = _object(service, request, raw)
                if set(body) != _REVOKE_MEMBERS:
                    raise service.reject_request("malformed_request")
                done = service.revoke(
                    challenge_id=body["challenge_id"],
                    customer_id=body["customer_id"],
                    target=body["target"],
                    signer=body["signer"],
                    origin=body["origin"],
                    signature=body["signature"],
                    origin_header=origin_header,
                )
            except Refused as error:
                return _refusal(error)
            return JSONResponse(
                {
                    "customer_id": done.customer_id,
                    "thumbprint": done.thumbprint,
                    "new_revocation": done.new_revocation,
                },
                status_code=201 if done.new_revocation else 200,
                headers=_NO_STORE,
            )

        return await run_in_threadpool(run)

    app.include_router(router)
    consent_router = APIRouter(prefix="/trusted-surface")

    @consent_router.post("/consent")
    async def consent(request: Request) -> JSONResponse:
        raw = await _read(request)
        origin_header = request.headers.get("origin")

        def run() -> JSONResponse:
            try:
                body = _object(service, request, raw, kind=LOG_KIND_CONSENT_REFUSED)
                if set(body) != _CONSENT_MEMBERS:
                    raise service.reject_request("malformed_request", LOG_KIND_CONSENT_REFUSED)
                done = service.consent(
                    record=body["record"],
                    signature=body["signature"],
                    agent_jwk=body["agent_jwk"],
                    origin_header=origin_header,
                )
            except Refused as error:
                return _refusal(error)
            return JSONResponse(
                {
                    "consent_id": done.consent_id,
                    "customer_id": done.customer_id,
                    "agent_thumbprint": done.agent_thumbprint,
                    "expires_at": done.expires_at,
                    "checkout_mandate": done.checkout_mandate,
                    "payment_mandate": done.payment_mandate,
                },
                status_code=201,
                headers=_NO_STORE,
            )

        return await run_in_threadpool(run)

    app.include_router(consent_router)
    app.include_router(consent_get)
