"""Validators for the vendored ACP 2026-04-17 JSON Schema (`schema.agentic_checkout.json`).

Responses are validated against the schema as published. A definition is addressed by name, for
example `CheckoutSession`, `CheckoutSessionWithOrder` or `Error`; `$defs` stay in the document, so
every internal `$ref` resolves.
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

from jsonschema import Draft202012Validator, FormatChecker

SCHEMA = (
    Path(__file__).resolve().parents[1]
    / "spec/vendor/acp/spec/2026-04-17/json-schema/schema.agentic_checkout.json"
)
_DOC: dict[str, Any] = json.loads(SCHEMA.read_text())


def validator(definition: str) -> Draft202012Validator:
    assert definition in _DOC["$defs"], definition
    schema = {"$ref": f"#/$defs/{definition}", "$defs": _DOC["$defs"]}
    return Draft202012Validator(schema, format_checker=FormatChecker())


SESSION = validator("CheckoutSession")
SESSION_WITH_ORDER = validator("CheckoutSessionWithOrder")
ERROR = validator("Error")
CREATE_REQUEST = validator("CheckoutSessionCreateRequest")
UPDATE_REQUEST = validator("CheckoutSessionUpdateRequest")
COMPLETE_REQUEST = validator("CheckoutSessionCompleteRequest")
