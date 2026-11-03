"""A small JSON Schema validator for model output (a deterministic subset, no dependency).

Model output is untrusted data. This checks it against the schema the caller gave: `type`, `enum`,
`const`, `properties`, `required`, `additionalProperties` (boolean or schema), `items`, `minItems`,
`maxItems`, `minLength`, `maxLength`, `pattern`, `minimum`, `maximum`, `anyOf`. A keyword outside the
subset is an error in the SCHEMA (raised as ValueError when the request is built), not silently ignored.
Errors name the path and the rule only, never the offending value, so an error message can be fed back to
the model without echoing untrusted text. Booleans are not numbers. Deterministic, no model, no I/O.
"""

from __future__ import annotations

import math
import re
from typing import Any

SUPPORTED = frozenset(
    {
        "type", "enum", "const", "properties", "required", "additionalProperties", "items",
        "minItems", "maxItems", "minLength", "maxLength", "pattern", "minimum", "maximum", "anyOf",
        "description", "title", "$schema", "default",
    }
)  # fmt: skip
_TYPES = {"object", "array", "string", "integer", "number", "boolean", "null"}


def check_schema(schema: Any, path: str = "$") -> None:
    """Raise ValueError (TypeError for a non-object) if the schema uses anything this validator does not implement."""
    if isinstance(schema, bool):
        return
    if not isinstance(schema, dict):
        raise TypeError(f"{path}: a schema is an object")
    unknown = set(schema) - SUPPORTED
    if unknown:
        raise ValueError(f"{path}: unsupported keyword {min(unknown)!r}")
    kind = schema.get("type")
    kinds = [kind] if isinstance(kind, str) else kind
    if kinds is not None and not (isinstance(kinds, list) and all(k in _TYPES for k in kinds)):
        raise ValueError(f"{path}: bad type")
    for name, sub in (schema.get("properties") or {}).items():
        check_schema(sub, f"{path}.{name}")
    if "items" in schema:
        check_schema(schema["items"], f"{path}[]")
    if isinstance(schema.get("additionalProperties"), dict):
        check_schema(schema["additionalProperties"], f"{path}.*")
    for index, sub in enumerate(schema.get("anyOf") or []):
        check_schema(sub, f"{path}.anyOf[{index}]")


def _is(value: Any, kind: str) -> bool:
    if kind == "object":
        return isinstance(value, dict)
    if kind == "array":
        return isinstance(value, list)
    if kind == "string":
        return isinstance(value, str)
    if kind == "boolean":
        return isinstance(value, bool)
    if kind == "null":
        return value is None
    if kind == "integer":
        return isinstance(value, int) and not isinstance(value, bool)
    if kind == "number":
        return (
            isinstance(value, int | float)
            and not isinstance(value, bool)
            and math.isfinite(float(value))
        )
    return False


def validate(value: Any, schema: Any, path: str = "$") -> list[str]:
    """Every violation as `path: rule`; an empty list means valid."""
    if schema is True:
        return []
    if schema is False:
        return [f"{path}: not allowed"]
    errors: list[str] = []
    kind = schema.get("type")
    if kind is not None:
        kinds = [kind] if isinstance(kind, str) else kind
        if not any(_is(value, k) for k in kinds):
            return [f"{path}: wrong type"]
    if "const" in schema and (value != schema["const"] or type(value) is not type(schema["const"])):
        errors.append(f"{path}: not the constant")
    if "enum" in schema and not any(
        value == option and type(value) is type(option) for option in schema["enum"]
    ):
        errors.append(f"{path}: not one of the allowed values")
    if "anyOf" in schema and not any(not validate(value, sub, path) for sub in schema["anyOf"]):
        errors.append(f"{path}: matches none of the allowed shapes")
    if isinstance(value, str):
        if "minLength" in schema and len(value) < schema["minLength"]:
            errors.append(f"{path}: too short")
        if "maxLength" in schema and len(value) > schema["maxLength"]:
            errors.append(f"{path}: too long")
        if "pattern" in schema and re.search(schema["pattern"], value) is None:
            errors.append(f"{path}: does not match the pattern")
    if _is(value, "integer") or _is(value, "number"):
        if "minimum" in schema and value < schema["minimum"]:
            errors.append(f"{path}: below the minimum")
        if "maximum" in schema and value > schema["maximum"]:
            errors.append(f"{path}: above the maximum")
    if isinstance(value, list):
        if "minItems" in schema and len(value) < schema["minItems"]:
            errors.append(f"{path}: too few items")
        if "maxItems" in schema and len(value) > schema["maxItems"]:
            errors.append(f"{path}: too many items")
        if "items" in schema:
            for index, item in enumerate(value):
                errors.extend(validate(item, schema["items"], f"{path}[{index}]"))
    if isinstance(value, dict):
        props = schema.get("properties") or {}
        for name in schema.get("required") or []:
            if name not in value:
                errors.append(f"{path}.{name}: missing")
        extra = schema.get("additionalProperties", True)
        for name, item in value.items():
            if name in props:
                errors.extend(validate(item, props[name], f"{path}.{name}"))
            elif extra is False:
                errors.append(f"{path}.{name}: not allowed")
            elif isinstance(extra, dict):
                errors.extend(validate(item, extra, f"{path}.{name}"))
    return errors
