"""The landing page at `/` is served in every mode from the exact allowlist (Decision 142).

It is two files from `web/landing`; it links the product surfaces, labels itself a sandbox demo, and is
sent with the same strict Content-Security-Policy as the other static pages. The try-it samples of the
verifier page are the committed test vectors, byte for byte.
"""

from __future__ import annotations

import re
from pathlib import Path

import pytest
from fastapi.testclient import TestClient

from countersign.api import static_routes
from tests.unit.test_approve_static import ALL_ENVS, make_app, raw_status

ROOT = Path(__file__).resolve().parents[2]
WEB = ROOT / "web"
LINKS = ("/dashboard/", "/verify/", "/.well-known/ucp", "/health", "github.com")


def test_every_file_of_the_landing_page_is_in_the_table_and_nothing_else() -> None:
    on_disk = {p.name for p in (WEB / "landing").iterdir() if p.is_file()}
    assert on_disk == {f.name for f, _ in static_routes.LANDING_FILES.values()}
    assert all(f.is_file() for f, _ in static_routes.LANDING_FILES.values())


@pytest.mark.parametrize("env", ALL_ENVS)
def test_the_root_is_html_with_the_links_and_the_csp(env: str) -> None:
    r = TestClient(make_app(env)).get("/")
    assert r.status_code == 200
    assert r.headers["content-type"].startswith("text/html")
    assert r.headers["content-security-policy"] == static_routes.CSP
    assert r.headers["x-content-type-options"] == "nosniff"
    for link in LINKS:
        assert f'href="{link}' in r.text or link in r.text, link
    assert "Sandbox demo" in r.text


def test_the_page_needs_nothing_the_csp_forbids() -> None:
    html = (WEB / "landing" / "index.html").read_text()
    assert "<script" not in html and "style=" not in html and "<style" not in html
    assert "onclick" not in html.lower()
    # Every local file the page loads is itself in the served table.
    for ref in re.findall(r'(?:href|src)="(/[^"]*)"', html):
        path = ref.split("?")[0]
        if path.startswith(("/dashboard/", "/verify/", "/.well-known/", "/health")):
            continue
        assert path in static_routes.SERVED, path
    # No external resource is loaded, only the repository link is external.
    assert re.findall(r'(?:src|href)="(https?://[^"]*)"', html) == [
        "https://github.com/vincentvega011/countersign"
    ]


@pytest.mark.parametrize("env", ["dev", "demo"])
@pytest.mark.parametrize(
    "path",
    ["/index.html", "/landing/", "/landing/index.html", "/landing/x.css", "/landing/%2e%2e/health"],
)
def test_nothing_else_is_served_for_the_landing_page(env: str, path: str) -> None:
    assert raw_status(make_app(env), path) in (404, 307, 308), path


def test_the_try_it_samples_are_the_committed_vectors() -> None:
    c = TestClient(make_app("demo"))
    for url, rel in (
        ("/verify/samples/synthetic.json", "tests/vectors/evidence/valid.json"),
        ("/verify/samples/recorded.json", "tests/vectors/recorded/p3_capture_bundle.json"),
    ):
        r = c.get(url)
        assert r.status_code == 200 and r.headers["content-type"].startswith("application/json")
        assert r.content == (ROOT / rel).read_bytes()
        assert r.headers["content-security-policy"] == static_routes.CSP
    assert c.get("/verify/samples/").status_code == 404
    assert c.get("/verify/samples/keys.json").status_code == 404
