"""The Trusted Surface page is served in every mode, from an exact allowlist and nothing else.

Decision 76: no directory is served. A URL is either an entry in `api/static_routes.SERVED` or a 404,
in demo as in dev. Traversal is tried plain (through the ASGI interface, so nothing normalizes the
path first) and percent-encoded.
"""

from __future__ import annotations

import asyncio
from pathlib import Path
from typing import Any

import pytest
from fastapi import FastAPI
from fastapi.testclient import TestClient
from sqlalchemy import create_engine

from countersign.api import static_routes
from countersign.api.app import create_app
from countersign.merchant.keys import generate_jwk, validate_jwk
from countersign.runtime import RuntimeSettings

WEB = Path(__file__).resolve().parents[2] / "web"
ALL_ENVS = ["dev", "eval", "demo", "prod", ""]


def make_app(env: str) -> FastAPI:
    return create_app(
        key=validate_jwk(generate_jwk()),
        engine=create_engine("sqlite://"),
        runtime=RuntimeSettings(app_env=env),
    )


def raw_status(app: FastAPI, raw_path: str) -> int:
    """GET `raw_path` exactly as given (no normalization), straight into the ASGI app."""
    path, _, query = raw_path.partition("?")
    scope = {
        "type": "http", "asgi": {"version": "3.0"}, "http_version": "1.1", "method": "GET",
        "scheme": "http", "path": path.replace("%2e", ".").replace("%2E", "."),
        "raw_path": raw_path.split("?")[0].encode(), "query_string": query.encode(),
        "headers": [(b"host", b"testserver")], "client": ("127.0.0.1", 1),
        "server": ("testserver", 80),
    }  # fmt: skip
    status: list[int] = []

    async def receive() -> dict[str, Any]:
        return {"type": "http.request", "body": b"", "more_body": False}

    async def send(message: dict[str, Any]) -> None:
        if message["type"] == "http.response.start":
            status.append(message["status"])

    asyncio.run(app(scope, receive, send))  # type: ignore[arg-type]
    return status[0]


@pytest.mark.parametrize("env", ALL_ENVS)
def test_the_page_and_its_files_are_served_in_every_mode(env: str) -> None:
    c = TestClient(make_app(env))
    for path in static_routes.SERVED:
        r = c.get(path)
        assert r.status_code == 200, (env, path)
        assert r.headers["content-type"].split(";")[0] in {
            "text/html", "text/css", "text/javascript", "application/javascript", "font/woff2"
        }, path  # fmt: skip
        assert r.headers["x-content-type-options"] == "nosniff"
        assert "default-src 'none'" in r.headers["content-security-policy"]
    assert "This device" in c.get("/approve/").text


def test_the_served_set_is_exactly_what_the_issue_names() -> None:
    assert sorted(static_routes.UI_FILES) == sorted(
        [
            "/ui/tokens.css",
            "/ui/components.css",
            "/ui/fonts.css",
            "/ui/ui.js",
            "/ui/fonts/instrument-sans-latin-wght-normal.woff2",
            "/ui/fonts/jetbrains-mono-latin-wght-normal.woff2",
            "/ui/fonts/newsreader-latin-wght-normal.woff2",
        ]
    )
    assert all(path.startswith("/approve/") for path in static_routes.PAGE_FILES)


def test_every_served_file_exists_and_every_page_file_is_served() -> None:
    for path, (file, _) in static_routes.SERVED.items():
        assert file.is_file(), path
    on_disk = {
        p.name
        for p in (WEB / "approve").iterdir()
        if p.is_file() and p.name not in {"package.json", ".prettierignore"}
    }
    served = {file.name for file, _ in static_routes.PAGE_FILES.values()}
    assert on_disk == served, "a file in web/approve is not in the allowlist, or the reverse"


@pytest.mark.parametrize("env", ALL_ENVS)
@pytest.mark.parametrize(
    "path",
    [
        "/ui/",
        "/ui",
        "/ui/gallery.html",
        "/ui/gallery.js",
        "/ui/gallery.css",
        "/ui/package.json",
        "/ui/.prettierignore",
        "/ui/test/format.test.mjs",
        "/ui/test/screenshots.mjs",
        "/ui/test/",
        "/ui/node_modules/playwright/package.json",
        "/ui/.artifacts/review-light-375.png",
        "/ui/.artifacts/",
        "/ui/fonts/",
        "/ui/fonts/LICENSE-newsreader.txt",
        "/ui/fonts/newsreader-latin-wght-normal.woff",
        "/approve/package.json",
        "/approve/.prettierignore",
        "/approve/test/",
        "/approve/test/enrol.test.mjs",
        "/approve/node_modules/",
        "/approve/node_modules/playwright/package.json",
        "/approve/.artifacts/x.png",
        "/approve/index.html",
        "/approve/missing.js",
        "/approve/APP.JS",
        "/approve//app.js",
        "/approve/app.js/",
        "/approve/app.js/x",
        "/_ui/",
        "/web/ui/tokens.css",
    ],
)
def test_nothing_else_is_served_in_any_mode(env: str, path: str) -> None:
    status = TestClient(make_app(env)).get(path, follow_redirects=False).status_code
    if env in {"dev", "eval"} and path == "/_ui/":
        assert status in (404, 307)
        return
    assert status in (404, 307, 308) and status != 200, (env, path, status)
    if status in (307, 308):  # a slash redirect may only lead to an allowlisted URL or to a 404
        r = TestClient(make_app(env)).get(path)
        assert r.status_code == 404 or r.url.path in static_routes.SERVED, (env, path)


def test_the_gallery_stays_off_in_demo_and_unknown_environments() -> None:
    for env in ("demo", "prod", ""):
        c = TestClient(make_app(env))
        assert c.get("/_ui/gallery.html").status_code == 404
        assert c.get("/_ui/tokens.css").status_code == 404


TRAVERSAL = [
    "/approve/../ui/gallery.html",
    "/approve/../../pyproject.toml",
    "/ui/../../pyproject.toml",
    "/ui/fonts/../gallery.html",
    "/approve/./app.js/../../ui/gallery.html",
    "/ui/..%2fgallery.html",
    "/ui/%2e%2e/gallery.html",
    "/ui/%2E%2E/%2E%2E/pyproject.toml",
    "/approve/%2e%2e/%2e%2e/pyproject.toml",
    "/approve/..%2f..%2fpyproject.toml",
    "/approve/%2e%2e%2fui%2fgallery.html",
    "/ui/fonts/..%5cgallery.html",
    "/ui/..%5c..%5cpyproject.toml",
    "/ui/....//gallery.html",
    "/ui/%252e%252e/gallery.html",
    "/ui/tokens.css%00.html",
    "/ui/tokens.css%00",
    "/ui/tokens.css/../gallery.html",
    "/approve/app.js%2f..%2f..%2fui%2fgallery.html",
    "/approve/..;/ui/gallery.html",
]


@pytest.mark.parametrize("env", ["dev", "demo"])
@pytest.mark.parametrize("path", TRAVERSAL)
def test_path_traversal_never_reaches_a_file(env: str, path: str) -> None:
    app = make_app(env)
    assert raw_status(app, path) in (400, 404, 307, 308), (env, path)
    r = TestClient(app).get(path)
    assert r.status_code != 200 or "Component gallery" not in r.text, (env, path)
    assert "[project]" not in r.text


def test_the_page_without_a_trailing_slash_redirects_to_it() -> None:
    r = TestClient(make_app("demo")).get("/approve", follow_redirects=False)
    assert r.status_code in (307, 308) and r.headers["location"].endswith("/approve/")


def test_the_page_names_no_other_origin_and_the_csp_forbids_them() -> None:
    csp = TestClient(make_app("demo")).get("/approve/").headers["content-security-policy"]
    for directive in (
        "default-src 'none'", "script-src 'self'", "style-src 'self'", "font-src 'self'",
        "connect-src 'self'", "frame-ancestors 'none'", "form-action 'none'", "base-uri 'none'",
    ):  # fmt: skip
        assert directive in csp
    assert "unsafe" not in csp and "http" not in csp
