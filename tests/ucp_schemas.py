"""Helpers that validate against the vendored UCP JSON Schemas.

Responses are validated against the schemas as published. Requests are validated against the
schema *resolved for the operation*: UCP marks each member with `ucp_request` (`omit`, `optional`
or `required`, per `create`, `update` or `complete`), and a request schema is the published one
with every `omit` member removed and `required` adjusted. `request_schema` does that resolution,
inlining every `$ref`, so the result needs no registry.
"""

from __future__ import annotations

import copy
import json
from pathlib import Path
from typing import Any
from urllib.parse import urldefrag, urljoin

from jsonschema import Draft202012Validator, FormatChecker
from referencing import Registry, Resource

SCHEMAS = Path(__file__).resolve().parents[1] / "spec/vendor/ucp/source/schemas"
BASE = "https://ucp.dev/schemas/"
CHECKOUT = BASE + "shopping/checkout.json"
ERROR_RESPONSE = BASE + "common/types/error_response.json"

_DOCS: dict[str, Any] = {}
for _f in SCHEMAS.rglob("*.json"):
    _doc = json.loads(_f.read_text())
    _DOCS[_doc["$id"]] = _doc


def registry() -> Registry:
    reg: Registry = Registry()
    for url, doc in _DOCS.items():
        reg = reg.with_resource(url, Resource.from_contents(doc))
    return reg


def validator(url: str) -> Draft202012Validator:
    return Draft202012Validator({"$ref": url}, registry=registry(), format_checker=FormatChecker())


def _pointer(doc: Any, fragment: str) -> Any:
    node = doc
    for part in [p for p in fragment.split("/") if p]:
        node = node[part.replace("~1", "/").replace("~0", "~")]
    return node


def _mode(schema: Any, op: str) -> str | None:
    if not isinstance(schema, dict):
        return None
    value = schema.get("ucp_request")
    if isinstance(value, dict):
        return value.get(op)  # type: ignore[no-any-return]
    return value  # type: ignore[no-any-return]


def _resolve(node: Any, base: str, op: str, depth: int = 0) -> Any:
    if depth > 60:
        raise RuntimeError("schema nesting too deep")
    if isinstance(node, list):
        return [_resolve(x, base, op, depth + 1) for x in node]
    if not isinstance(node, dict):
        return node
    out: dict[str, Any] = {}
    if "$ref" in node:
        target, fragment = urldefrag(urljoin(base, node["$ref"]))
        sub = _pointer(_DOCS[target], fragment)
        out.update(_resolve(sub, target, op, depth + 1))
    for key, value in node.items():
        if key in ("$ref", "$id", "$schema", "ucp_request", "$defs"):
            continue
        if key == "properties" and isinstance(value, dict):
            props: dict[str, Any] = {}
            required = set(node.get("required", out.get("required", [])))
            for name, sub_schema in value.items():
                mode = _mode(sub_schema, op)
                if mode == "omit":
                    required.discard(name)
                    continue
                if mode == "required":
                    required.add(name)
                elif mode == "optional":
                    required.discard(name)
                props[name] = _resolve(sub_schema, base, op, depth + 1)
            out["properties"] = {**out.get("properties", {}), **props}
            if required:
                out["required"] = sorted(required)
            else:
                out.pop("required", None)
        elif key == "required":
            if "properties" not in node:
                out["required"] = value
        else:
            out[key] = _resolve(value, base, op, depth + 1)
    return out


def request_schema(url: str, op: str) -> dict[str, Any]:
    """The request schema of `url` for `op` (`create`, `update` or `complete`)."""
    return copy.deepcopy(_resolve({"$ref": url}, BASE, op))  # type: ignore[no-any-return]


def request_validator(op: str, url: str = CHECKOUT) -> Draft202012Validator:
    return Draft202012Validator(request_schema(url, op), format_checker=FormatChecker())
