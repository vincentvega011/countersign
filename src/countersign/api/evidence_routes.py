"""`GET /evidence/{capture_id}`: the stored evidence bundle of a captured payment.

The bundle names a customer id and PayPal object ids, so it is a merchant document. Until the merchant
dashboard has a login (P4) the route is served only where the shared UI is (`APP_ENV` dev or eval), never
in demo or production (Decision 104, L46). A malformed id is a 400 and an unknown one a 404, both with a
fixed code and no echo.
"""

from __future__ import annotations

import re

from fastapi import FastAPI, Response
from fastapi.responses import JSONResponse

from countersign.evidence import EvidenceService

_CAPTURE_ID = re.compile(r"[A-Za-z0-9_-]{1,64}")


def install(app: FastAPI, service: EvidenceService) -> None:
    @app.get("/evidence/{capture_id}")
    def evidence(capture_id: str) -> Response:
        headers = {"Cache-Control": "no-store"}
        if _CAPTURE_ID.fullmatch(capture_id) is None:
            return JSONResponse({"code": "capture_id_invalid"}, 400, headers)
        bundle = service.get(capture_id)
        if bundle is None:
            return JSONResponse({"code": "evidence_unknown"}, 404, headers)
        return Response(bundle, media_type="application/json", headers=headers)
