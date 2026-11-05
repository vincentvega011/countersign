"""The dashboard's built files: an exact table from the Vite manifest, a CSP scoped to /dashboard/ only."""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

import pytest
from fastapi import FastAPI
from fastapi.testclient import TestClient

from countersign.api import dashboard_routes as routes
from countersign.api.static_routes import CSP as PHONE_CSP


class _Service:
    engine: Any = None
    poll_seconds = 1.0
    stream_seconds = 1.0


def _dist(tmp: Path, extra: dict[str, Any] | None = None) -> Path:
    dist = tmp / "dist"
    (dist / "assets").mkdir(parents=True)
    (dist / ".vite").mkdir()
    (dist / "index.html").write_text("<!doctype html><title>x</title>")
    (dist / "assets" / "index-AbC123xy.js").write_text("console.log(1)")
    (dist / "assets" / "index-Zz9_Yy-8.css").write_text("body{}")
    (dist / "assets" / "font-Q1w2E3r4.woff2").write_bytes(b"wOF2")
    (dist / "secret.txt").write_text("not served")
    manifest = {
        "index.html": {"file": "assets/index-AbC123xy.js", "css": ["assets/index-Zz9_Yy-8.css"],
                       "assets": ["assets/font-Q1w2E3r4.woff2"]},
        **(extra or {}),
    }  # fmt: skip
    (dist / ".vite" / "manifest.json").write_text(json.dumps(manifest))
    return dist


def _client(dist: Path) -> TestClient:
    app = FastAPI()
    routes.install(app, _Service(), dist)  # type: ignore[arg-type]
    return TestClient(app)


def test_the_page_and_the_manifest_files_are_served_with_fixed_types(tmp_path: Path) -> None:
    client = _client(_dist(tmp_path))
    page = client.get("/dashboard/")
    assert page.status_code == 200 and page.headers["content-type"].startswith("text/html")
    assert page.headers["content-security-policy"] == routes.CSP
    assert page.headers["x-content-type-options"] == "nosniff"
    js = client.get("/dashboard/assets/index-AbC123xy.js")
    assert js.status_code == 200 and js.headers["content-type"].startswith("text/javascript")
    assert (
        client.get("/dashboard/assets/index-Zz9_Yy-8.css")
        .headers["content-type"]
        .startswith("text/css")
    )
    assert (
        client.get("/dashboard/assets/font-Q1w2E3r4.woff2").headers["content-type"] == "font/woff2"
    )
    bare = client.get("/dashboard", follow_redirects=False)
    assert bare.status_code == 308 and bare.headers["location"] == "/dashboard/"


@pytest.mark.parametrize(
    "path",
    [
        "/dashboard/secret.txt", "/dashboard/index.html", "/dashboard/assets/",
        "/dashboard/assets", "/dashboard/.vite/manifest.json", "/dashboard/assets/other-AbC123xy.js",
        "/dashboard/assets/../secret.txt", "/dashboard/assets/%2e%2e/secret.txt",
        "/dashboard/assets/..%2fsecret.txt", "/dashboard/assets/index-AbC123xy.js%00",
        "/dashboard/assets\\..\\secret.txt", "/dashboard/%2e%2e/%2e%2e/pyproject.toml",
    ],
)  # fmt: skip
def test_anything_not_in_the_table_is_a_404(tmp_path: Path, path: str) -> None:
    assert _client(_dist(tmp_path)).get(path).status_code == 404


def test_the_relaxed_policy_is_only_on_the_dashboard() -> None:
    assert "script-src 'self';" in routes.CSP and "unsafe-eval" not in routes.CSP
    assert "style-src 'self' 'unsafe-inline'" in routes.CSP
    assert "unsafe-inline" not in PHONE_CSP
    relaxed = {d.split()[0] for d in routes.CSP.split("; ")} - {
        d.split()[0] for d in routes.CSP.split("; ") if d in PHONE_CSP.split("; ")
    }
    assert relaxed == {"style-src", "img-src"}


def test_without_a_build_the_page_says_so(tmp_path: Path) -> None:
    r = _client(tmp_path / "missing").get("/dashboard/")
    assert r.status_code == 503 and r.json() == {"code": "dashboard_not_built"}


def test_a_manifest_naming_an_unexpected_file_stops_the_start(tmp_path: Path) -> None:
    dist = _dist(tmp_path, {"x": {"file": "../pyproject.toml"}})
    with pytest.raises(RuntimeError, match="unexpected dashboard build file name"):
        routes.built_assets(dist)
