"""The evidence verifier page (`/verify/`) and its modules are served in every mode from the exact allowlist.

Decision 108 extends Decision 76: the page and the six verifier modules under `/ui/evidence/` are table
entries; nothing else under `web/verify` or `web/ui/evidence` (tests, the Node runner) is reachable.
"""

from __future__ import annotations

from pathlib import Path

import pytest
from fastapi.testclient import TestClient

from countersign.api import static_routes
from tests.unit.test_approve_static import ALL_ENVS, make_app, raw_status

WEB = Path(__file__).resolve().parents[2] / "web"


def test_every_file_of_the_page_and_the_verifier_is_in_the_table_and_nothing_else() -> None:
    on_disk = {
        p.name
        for p in (WEB / "verify").iterdir()
        if p.is_file() and p.name not in {"package.json", ".prettierignore"}
    }
    # The two try-it samples are the committed test vectors, served from their own place (test_landing_static).
    served = {f.name for f, _ in static_routes.VERIFY_FILES.values() if f.parent == WEB / "verify"}
    assert on_disk == served
    modules = {p.name for p in (WEB / "ui" / "evidence").iterdir() if p.is_file()}
    assert modules == set(static_routes.EVIDENCE_MODULES)


@pytest.mark.parametrize("env", ALL_ENVS)
def test_the_page_is_served_with_the_csp_in_every_mode(env: str) -> None:
    c = TestClient(make_app(env))
    for path in [
        *static_routes.VERIFY_FILES,
        *(f"/ui/evidence/{m}" for m in static_routes.EVIDENCE_MODULES),
    ]:
        r = c.get(path)
        assert r.status_code == 200, (env, path)
        assert r.headers["content-security-policy"] == static_routes.CSP
        assert r.headers["x-content-type-options"] == "nosniff"
    assert c.get("/verify", follow_redirects=False).headers["location"].endswith("/verify/")


@pytest.mark.parametrize("env", ["dev", "demo"])
@pytest.mark.parametrize(
    "path",
    [
        "/verify/index.html",
        "/verify/package.json",
        "/verify/.prettierignore",
        "/verify/x.js",
        "/verify//verify.js",
        "/ui/evidence/",
        "/ui/evidence",
        "/ui/evidence/test.mjs",
        "/ui/evidence/../test/evidence.test.mjs",
        "/ui/test/verify-runner.mjs",
        "/ui/test/evidence.test.mjs",
        "/verify/%2e%2e/approve/app.js",
        "/ui/evidence/..%2f..%2f..%2fpyproject.toml",
    ],
)
def test_nothing_else_is_served(env: str, path: str) -> None:
    assert raw_status(make_app(env), path) in (404, 307, 308), path
    r = TestClient(make_app(env)).get(path)
    assert r.status_code == 404 or r.url.path in static_routes.SERVED, path
