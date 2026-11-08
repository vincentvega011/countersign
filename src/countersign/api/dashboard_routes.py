"""The merchant dashboard: its read-only API, its live stream and its built files (Decisions 113 to 115).

Security reasoning.

- **Read only, with one exception.** Every route is GET except `POST attack-runs` (Decision 131), which
  exists only in dev, eval or demo with the launcher installed and creates a run record on a scratch
  database; it cannot change a credential, the mode, a policy, merchant data or a payment. A test checks
  that no other method is routed under `/dashboard/`. There is no merchant login yet (L57): the API is designed so that nothing sensitive is
  reachable (fixed member lists, no secret, no payer data; a test scans every answer). The one place
  mandate text appears is `orders/{id}/detail`, which returns the stored evidence bundle, the same text
  `GET /evidence/{capture_id}` serves (sanitized when stored, public keys only; Decision 118), and
  `samples/{name}`, an exact table of committed synthetic vectors (Decision 120).
- **Versioned and stable.** Paths are under `/dashboard/api/v1/`; every body carries `version`.
- **The live stream** (`/dashboard/api/v1/stream`) is Server-Sent Events. It polls the decision log
  and announces the ids of checkouts named by new entries; the page then asks for those rows. It sends
  ids only, is bounded in time (the browser reconnects) and stops when the client leaves.
- **Static files** come from an exact table built at start from the Vite manifest of
  `web/dashboard/dist`: `index.html` plus the hashed files the manifest names, each with a fixed media
  type. Nothing serves a directory and no path is joined from the request, so traversal cannot match.
  Without a build every dashboard page answers 503 `dashboard_not_built`.
- **CSP**, scoped to `/dashboard/` only: scripts from this origin only, as everywhere. Styles also allow
  `'unsafe-inline'`, because Studio and its grid set `style` attributes and inject `<style>` elements
  at run time (a nonce cannot cover style attributes). Images allow `data:` for Studio's inline icons.
  Nothing else is relaxed, and the phone and verifier pages keep their stricter policy (Decision 76).
"""

from __future__ import annotations

import asyncio
import json
import re
from pathlib import Path
from typing import Any

from fastapi import APIRouter, FastAPI, Request
from fastapi.concurrency import run_in_threadpool
from fastapi.responses import JSONResponse, Response, StreamingResponse

from countersign.dashboard import read, samples
from countersign.dashboard.service import DashboardService

DIST = Path(__file__).resolve().parents[3] / "web" / "dashboard" / "dist"
PREFIX = "/dashboard"
API = "/dashboard/api/v1"
MEDIA = {
    ".js": "text/javascript",
    ".css": "text/css",
    ".woff2": "font/woff2",
    ".svg": "image/svg+xml",
}
ASSET = re.compile(r"assets/[A-Za-z0-9_-]+(?:\.[A-Za-z0-9_-]+)*\.(?:js|css|woff2|svg)")
IDS = re.compile(r"[A-Za-z0-9_-]{1,64}")
RUN_HEADER = "X-Countersign-Dashboard"


CSP = (
    "default-src 'none'; script-src 'self'; style-src 'self' 'unsafe-inline'; font-src 'self'; "
    "connect-src 'self'; img-src 'self' data:; base-uri 'none'; form-action 'none'; "
    "frame-ancestors 'none'"
)


_ASSET_HEADERS = {
    "X-Content-Type-Options": "nosniff",
    "Referrer-Policy": "no-referrer",
    "Cache-Control": "public, max-age=31536000, immutable",
}
_API_HEADERS = {
    "X-Content-Type-Options": "nosniff",
    "Referrer-Policy": "no-referrer",
    "Cache-Control": "no-store",
}


def built_assets(dist: Path = DIST) -> dict[str, tuple[Path, str]]:
    """URL path -> (file, media type) for every file the Vite manifest names. Empty without a build."""
    manifest = dist / ".vite" / "manifest.json"
    if not (dist / "index.html").is_file() or not manifest.is_file():
        return {}
    entries = json.loads(manifest.read_text())
    names: set[str] = set()
    for entry in entries.values():
        names.add(entry.get("file", ""))
        names.update(entry.get("css", []))
        names.update(entry.get("assets", []))
    table: dict[str, tuple[Path, str]] = {}
    for name in sorted(n for n in names if n):
        if ASSET.fullmatch(name) is None:
            raise RuntimeError(f"unexpected dashboard build file name: {name!r}")
        file = dist / name
        if not file.is_file():
            raise RuntimeError(f"the dashboard manifest names a missing file: {name!r}")
        table[f"{PREFIX}/{name}"] = (file, MEDIA[file.suffix])
    return table


def _json(body: dict[str, Any], status: int = 200) -> JSONResponse:
    return JSONResponse(body, status_code=status, headers=_API_HEADERS)


def install(app: FastAPI, service: DashboardService, dist: Path = DIST) -> None:
    router = APIRouter()

    @router.get(f"{API}/status")
    async def status() -> JSONResponse:
        return _json(service.status())

    @router.get(f"{API}/orders")
    async def orders(ids: str | None = None) -> JSONResponse:
        wanted: list[str] | None = None
        if ids is not None:
            wanted = [i for i in ids.split(",") if IDS.fullmatch(i)][: read.MAX_IDS]
        return _json(await run_in_threadpool(service.orders, wanted))

    @router.get(f"{API}/orders/{{checkout_id}}/detail")
    async def order_detail(checkout_id: str) -> JSONResponse:
        if IDS.fullmatch(checkout_id) is None:
            return _json({"code": "order_unknown"}, 404)
        body = await run_in_threadpool(service.detail, checkout_id)
        return _json({"code": "order_unknown"}, 404) if body is None else _json(body)

    @router.get(f"{API}/samples")
    async def sample_list() -> JSONResponse:
        return _json({"version": read.API_VERSION, "samples": samples.listing()})

    @router.get(f"{API}/samples/{{name}}")
    async def sample_one(name: str) -> JSONResponse:
        body = samples.sample(name) if name in samples.SAMPLES else None
        if body is None:
            return _json({"code": "sample_unknown"}, 404)
        return _json({"version": read.API_VERSION, **body})

    @router.get(f"{API}/summary")
    async def summary() -> JSONResponse:
        return _json(await run_in_threadpool(service.summary))

    @router.get(f"{API}/mandates")
    async def mandates() -> JSONResponse:
        return _json(await run_in_threadpool(service.mandates))

    @router.get(f"{API}/events")
    async def events() -> JSONResponse:
        return _json(await run_in_threadpool(service.events))

    @router.get(f"{API}/eval")
    async def evaluation() -> JSONResponse:
        return _json(await run_in_threadpool(service.eval))

    @router.get(f"{API}/attack-runs")
    async def attack_runs() -> JSONResponse:
        if not service.attack_runs_enabled():
            return _json(
                {"version": read.API_VERSION, "enabled": False, "attacks": [], "recent": []}
            )
        launcher = service.attack_launcher
        recent = await run_in_threadpool(launcher.recent)
        return _json(
            {"version": read.API_VERSION, "enabled": True, "attacks": launcher.launchable(),
             "recent": recent}
        )  # fmt: skip

    @router.post(f"{API}/attack-runs")
    async def start_attack_run(request: Request) -> JSONResponse:
        """The one write under `/dashboard/`: it creates a run record and touches no merchant data.

        Gated three ways: the deployment must be dev, eval or demo with a launcher installed; the request
        must carry a custom header (a cross-site form or fetch cannot send it without a CORS preflight,
        which this app never answers); and the body must name an attack from the launcher's own list.
        """
        if not service.attack_runs_enabled():
            return _json({"code": "attack_runs_disabled"}, 403)
        if request.headers.get(RUN_HEADER) != "1":
            return _json({"code": "attack_run_header_required"}, 403)
        raw = await request.body()
        try:
            asked = json.loads(raw) if len(raw) <= 256 else None
        except ValueError:
            asked = None
        attack = (
            asked.get("attack") if isinstance(asked, dict) and set(asked) == {"attack"} else None
        )
        launcher = service.attack_launcher
        known = {a["id"] for a in launcher.launchable()}
        if not isinstance(attack, str) or IDS.fullmatch(attack) is None or attack not in known:
            return _json({"code": "attack_unknown"}, 404)
        try:
            record = await run_in_threadpool(launcher.run, attack)
        except Exception as error:  # noqa: BLE001 - mapped to fixed codes; no message is echoed
            name = type(error).__name__
            if name == "Busy":
                return _json({"code": "attack_run_busy"}, 409)
            return _json({"code": "attack_runs_unavailable"}, 503)
        return _json(record, 201)

    @router.get(f"{API}/policy")
    async def policy() -> JSONResponse:
        return _json(await run_in_threadpool(service.policy))

    @router.get(f"{API}/stream")
    async def stream(request: Request) -> StreamingResponse:
        async def announce() -> Any:
            seq = await run_in_threadpool(read.latest_seq, service.engine)
            yield f"event: hello\ndata: {json.dumps({'version': read.API_VERSION, 'seq': seq})}\n\n"
            waited = 0.0
            quiet = 0.0
            while waited < service.stream_seconds:
                if await request.is_disconnected():
                    return
                await asyncio.sleep(service.poll_seconds)
                waited += service.poll_seconds
                quiet += service.poll_seconds
                seq, ids = await run_in_threadpool(read.changed_since, service.engine, seq)
                if ids:
                    quiet = 0.0
                    body = json.dumps({"version": read.API_VERSION, "seq": seq, "ids": ids})
                    yield f"event: orders\ndata: {body}\n\n"
                elif quiet >= 15:
                    quiet = 0.0
                    yield ": keep-alive\n\n"

        return StreamingResponse(
            announce(), media_type="text/event-stream",
            headers={**_API_HEADERS, "X-Accel-Buffering": "no"},
        )  # fmt: skip

    assets = built_assets(dist)
    index = dist / "index.html"
    html = index.read_text() if assets and index.is_file() else ""

    def page() -> Response:
        if not assets or not index.is_file():
            return _json({"code": "dashboard_not_built"}, 503)
        return Response(
            html, media_type="text/html",
            headers={"Content-Security-Policy": CSP, "X-Content-Type-Options": "nosniff",
                     "Referrer-Policy": "no-referrer", "Cache-Control": "no-store"},
        )  # fmt: skip

    router.add_api_route(f"{PREFIX}/", page, methods=["GET"], name="dashboard:page")

    def make(path: str) -> None:
        file, media = assets[path]
        body = file.read_bytes()

        def handler() -> Response:
            return Response(body, media_type=media, headers=_ASSET_HEADERS)

        router.add_api_route(path, handler, methods=["GET"], name=f"dashboard:{path}")

    for path in assets:
        make(path)

    @router.get(PREFIX)
    def bare() -> Response:
        return Response(status_code=308, headers={"Location": f"{PREFIX}/"})

    app.include_router(router)
    from countersign.api import assistant_routes

    assistant_routes.install(app, service)
