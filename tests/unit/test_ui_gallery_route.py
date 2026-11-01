"""The component gallery is served in dev and eval only; nothing is served in demo or an unknown env."""

from __future__ import annotations

import pytest
from fastapi.testclient import TestClient
from sqlalchemy import create_engine

from countersign.api.app import create_app
from countersign.merchant.keys import generate_jwk, validate_jwk
from countersign.runtime import RuntimeSettings


def client(app_env: str) -> TestClient:
    app = create_app(
        key=validate_jwk(generate_jwk()),
        engine=create_engine("sqlite://"),
        runtime=RuntimeSettings(app_env=app_env),
    )
    return TestClient(app)


@pytest.mark.parametrize("env", ["dev", "eval"])
def test_the_gallery_and_its_assets_are_served_in_dev_and_eval(env: str) -> None:
    c = client(env)
    page = c.get("/_ui/gallery.html")
    assert page.status_code == 200 and "Component gallery" in page.text
    for asset in (
        "tokens.css",
        "components.css",
        "ui.js",
        "fonts/newsreader-latin-wght-normal.woff2",
    ):
        assert c.get(f"/_ui/{asset}").status_code == 200, asset


@pytest.mark.parametrize("env", ["demo", "prod", "", "DEV"])
def test_nothing_is_served_in_demo_or_an_unknown_environment(env: str) -> None:
    c = client(env)
    assert c.get("/_ui/gallery.html").status_code == 404
    assert c.get("/_ui/tokens.css").status_code == 404


def test_the_static_mount_cannot_read_outside_the_ui_directory() -> None:
    c = client("dev")
    assert c.get("/_ui/../../pyproject.toml").status_code in (404, 400)
    assert c.get("/_ui/%2e%2e/%2e%2e/pyproject.toml").status_code == 404
