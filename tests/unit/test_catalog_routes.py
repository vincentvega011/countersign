"""`GET /catalog`: the agent's read-only search, with exact filters and fixed refusals."""

from __future__ import annotations

from fastapi import FastAPI
from fastapi.testclient import TestClient

from countersign.api.catalog_routes import install
from countersign.catalog.catalog import load_catalog


def client() -> TestClient:
    app = FastAPI()
    install(app, load_catalog())
    return TestClient(app)


def test_the_whole_catalog_and_the_filters() -> None:
    c = client()
    everything = c.get("/catalog").json()
    assert everything["currency"] == "USD" and len(everything["items"]) == len(load_catalog().items)
    cheap = c.get("/catalog", params={"category": "headphones", "max_price_minor": 5000}).json()
    assert cheap["items"] and all(
        i["category"] == "headphones" and i["price_minor"] <= 5000 for i in cheap["items"]
    )
    named = c.get("/catalog", params={"q": "ORBIT"}).json()["items"]
    assert named and all("orbit" in i["title"].lower() for i in named)


def test_bad_queries_are_refused_without_an_echo() -> None:
    c = client()
    for params in (
        {"category": "<script>"}, {"max_price_minor": "-1"}, {"max_price_minor": "1.5"},
        {"q": "x" * 65}, {"q": ""}, {"other": "1"},
    ):  # fmt: skip
        r = c.get("/catalog", params=params)
        assert r.status_code == 400 and r.json() == {"code": "catalog_query_invalid"}
