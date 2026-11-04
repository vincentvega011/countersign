"""`GET /catalog`: the public, read-only product list the shopping agent searches over HTTP.

The catalog is the price authority for the demo store (`countersign.catalog`), and what it lists is
public. Filters are exact and deterministic: `category` (a declared category id), `q` (a
case-insensitive substring of the title, brand or description) and `max_price_minor` (an integer).
An unknown category, a malformed integer or an over-long query is HTTP 400 with a fixed code, never
an echo of the value. No model is involved (INV-1).
"""

from __future__ import annotations

from fastapi import FastAPI, Request
from fastapi.responses import JSONResponse

from countersign.catalog.catalog import Catalog

MAX_QUERY = 64
_NO_STORE = {"Cache-Control": "no-store"}


def _bad(code: str) -> JSONResponse:
    return JSONResponse({"code": code}, status_code=400, headers=_NO_STORE)


def install(app: FastAPI, catalog: Catalog) -> None:
    categories = {c.id for c in catalog.categories}

    @app.get("/catalog")
    def list_catalog(request: Request) -> JSONResponse:
        params = request.query_params
        if not set(params) <= {"category", "q", "max_price_minor"}:
            return _bad("catalog_query_invalid")
        category, query = params.get("category"), params.get("q")
        if category is not None and category not in categories:
            return _bad("catalog_query_invalid")
        if query is not None and not 1 <= len(query) <= MAX_QUERY:
            return _bad("catalog_query_invalid")
        ceiling: int | None = None
        if "max_price_minor" in params:
            text = params["max_price_minor"]
            if not text.isascii() or not text.isdigit() or len(text) > 9:
                return _bad("catalog_query_invalid")
            ceiling = int(text)
        found = []
        for item in catalog.items:
            if category is not None and item.category != category:
                continue
            if ceiling is not None and item.price.minor > ceiling:
                continue
            if (
                query is not None
                and query.lower() not in f"{item.title} {item.brand} {item.description}".lower()
            ):
                continue
            found.append(item.to_dict())
        body = {
            "currency": catalog.currency,
            "categories": [{"id": c.id, "title": c.title} for c in catalog.categories],
            "items": found,
        }
        return JSONResponse(body, headers=_NO_STORE)
