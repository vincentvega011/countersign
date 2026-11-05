"""The Trusted Surface pages, the evidence verifier page and the shared UI files they need, in every mode.

Security reasoning. This is a product page, unlike the component gallery (`/_ui`, dev and eval only,
Decision 75), so it is served in demo too. Nothing here serves a directory: each URL is an entry in a
fixed table that names one file, its media type and nothing else, so a path that is not in the table
is a 404 before the file system is touched, and a traversal attempt (plain or encoded) never matches
an entry. A test fails if a file appears under `web/approve` that is not in the table, or if a table
entry has no file. The page is sent with a strict Content-Security-Policy: scripts, styles, fonts and
connections from its own origin only, no framing, no forms (Decision 76).
"""

from __future__ import annotations

from pathlib import Path

from fastapi import APIRouter, FastAPI
from fastapi.responses import FileResponse, Response

WEB_DIR = Path(__file__).resolve().parents[3] / "web"
APPROVE_DIR = WEB_DIR / "approve"
UI_DIR = WEB_DIR / "ui"
VERIFY_DIR = WEB_DIR / "verify"
EVIDENCE_DIR = UI_DIR / "evidence"

APPROVE_PATH = "/approve/"
VERIFY_PATH = "/verify/"
CSS, JS, HTML, WOFF2 = "text/css", "text/javascript", "text/html", "font/woff2"
FONTS = (
    "instrument-sans-latin-wght-normal.woff2",
    "jetbrains-mono-latin-wght-normal.woff2",
    "newsreader-latin-wght-normal.woff2",
)

# URL path -> (file, media type). The whole of what is served.
PAGE_FILES: dict[str, tuple[Path, str]] = {
    APPROVE_PATH: (APPROVE_DIR / "index.html", HTML),
    "/approve/approve.css": (APPROVE_DIR / "approve.css", CSS),
    "/approve/app.js": (APPROVE_DIR / "app.js", JS),
    "/approve/consent.js": (APPROVE_DIR / "consent.js", JS),
    "/approve/device-key.js": (APPROVE_DIR / "device-key.js", JS),
    "/approve/messages.js": (APPROVE_DIR / "messages.js", JS),
    "/approve/shell.js": (APPROVE_DIR / "shell.js", JS),
    "/approve/purchase.html": (APPROVE_DIR / "purchase.html", HTML),
    "/approve/purchase.js": (APPROVE_DIR / "purchase.js", JS),
    "/approve/purchase-consent.js": (APPROVE_DIR / "purchase-consent.js", JS),
    "/approve/activity.html": (APPROVE_DIR / "activity.html", HTML),
    "/approve/activity.js": (APPROVE_DIR / "activity.js", JS),
    "/approve/activity-records.js": (APPROVE_DIR / "activity-records.js", JS),
}
# The evidence verifier page (Decision 108): every check runs in the browser, from the modules below.
VERIFY_FILES: dict[str, tuple[Path, str]] = {
    VERIFY_PATH: (VERIFY_DIR / "index.html", HTML),
    "/verify/verify.css": (VERIFY_DIR / "verify.css", CSS),
    "/verify/verify.js": (VERIFY_DIR / "verify.js", JS),
    "/verify/verify-text.js": (VERIFY_DIR / "verify-text.js", JS),
}
EVIDENCE_MODULES = (
    "json.js",
    "crypto.js",
    "sdjwt.js",
    "log.js",
    "constraints.js",
    "steps.js",
    "verify.js",
)
UI_FILES: dict[str, tuple[Path, str]] = {
    "/ui/tokens.css": (UI_DIR / "tokens.css", CSS),
    "/ui/components.css": (UI_DIR / "components.css", CSS),
    "/ui/fonts.css": (UI_DIR / "fonts.css", CSS),
    "/ui/ui.js": (UI_DIR / "ui.js", JS),
    **{f"/ui/fonts/{name}": (UI_DIR / "fonts" / name, WOFF2) for name in FONTS},
    **{f"/ui/evidence/{name}": (EVIDENCE_DIR / name, JS) for name in EVIDENCE_MODULES},
}
SERVED: dict[str, tuple[Path, str]] = {**PAGE_FILES, **VERIFY_FILES, **UI_FILES}

CSP = (
    "default-src 'none'; script-src 'self'; style-src 'self'; font-src 'self'; "
    "connect-src 'self'; img-src 'self'; base-uri 'none'; form-action 'none'; "
    "frame-ancestors 'none'"
)
_HEADERS = {
    "Content-Security-Policy": CSP,
    "X-Content-Type-Options": "nosniff",
    "Referrer-Policy": "no-referrer",
    "Cache-Control": "no-cache",
}


def install(app: FastAPI) -> None:
    router = APIRouter()

    def make(path: str) -> None:
        file, media = SERVED[path]

        def handler() -> Response:
            return FileResponse(file, media_type=media, headers=_HEADERS)

        router.add_api_route(path, handler, methods=["GET"], name=f"static:{path}")

    for path in SERVED:
        make(path)
    app.include_router(router)
