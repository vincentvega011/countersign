"""`GET /evidence/{capture_id}`: the stored evidence bundle of a captured payment, in every mode.

Security reasoning (Decision 107, L46). A bundle holds sanitized sandbox data only: PayPal objects pass the
member allowlist of `evidence.observer` (no payer, no email, no name, no address, no shipping, no links),
and the customer is a random `cus_` id. It is served in every `APP_ENV` so the `/verify/` page can load
one by capture id. This route has no listing, but the dashboard API (`/dashboard/api/v1/orders`) lists capture ids and has
no login (L57), so a bundle is readable by anyone who can reach a demo instance; the bundles hold sanitized
sandbox data only. An unknown id and a malformed one get the same answer (status, body, headers), so the endpoint is no oracle
for which ids are well formed. Every fetch writes one process log line (not a decision log entry: a read
decides nothing). Answers are never cached.
"""

from __future__ import annotations

import re

import structlog
from fastapi import FastAPI, Response
from fastapi.responses import JSONResponse

from countersign.evidence import EvidenceService

_CAPTURE_ID = re.compile(r"[A-Za-z0-9_-]{1,64}")
_HEADERS = {"Cache-Control": "no-store", "X-Content-Type-Options": "nosniff"}
log = structlog.get_logger("countersign.evidence")


def install(app: FastAPI, service: EvidenceService) -> None:
    @app.get("/evidence/{capture_id:path}")  # every path below, so none answers differently
    def evidence(capture_id: str) -> Response:
        well_formed = _CAPTURE_ID.fullmatch(capture_id) is not None
        bundle = service.get(capture_id) if well_formed else None
        log.info(
            "evidence_fetch",
            capture_id=capture_id if well_formed else None,
            well_formed=well_formed,
            found=bundle is not None,
        )
        if bundle is None:
            return JSONResponse({"code": "evidence_unknown"}, 404, _HEADERS)
        return Response(bundle, media_type="application/json", headers=_HEADERS)
