"""Evidence bundles that test the JSON number rules, the nesting cap and type-exact checks (Decision 106).

Each case is the valid bundle written as text with one value replaced by raw JSON text (some of these,
such as `9007199254740993` or `0.1000000000000000055`, cannot be produced by a JSON encoder). They are
written to `tests/vectors/evidence/strict/` and listed in `index.json` under `strict` with the first
failing step and its code, so the Python and the browser verifier are held to the same answer.
"""

from __future__ import annotations

import copy
import json
from collections.abc import Callable
from typing import Any

from countersign_verify.crypto import MAX_DEPTH

Bundle = dict[str, Any]
MARK = "__RAW_JSON_VALUE__"


def _at(path: tuple[Any, ...], raw: str) -> Callable[[Bundle], tuple[Bundle, str]]:
    def make(valid: Bundle) -> tuple[Bundle, str]:
        b = copy.deepcopy(valid)
        node: Any = b
        for key in path[:-1]:
            node = node[key]
        node[path[-1]] = MARK
        return b, raw

    return make


CATEGORY = ("paypal", "order", 0, "purchase_units", 0, "items", 0, "category")
SEQ = ("log", "entries", 0, "seq")
TS = ("log", "entries", 0, "ts_us")
CATEGORY_DEPTH = 8  # containers around the category member


def _nested(total_depth: int) -> str:
    inner = total_depth - CATEGORY_DEPTH
    return "[" * inner + "]" * inner


# name: (maker, first failing step or None for a bundle that passes, code or None)
STRICT: dict[str, tuple[Callable[[Bundle], tuple[Bundle, str]], str | None, str | None]] = {
    "big_integer": (_at(SEQ, "9007199254740993"), "bundle_structure", "json_unsafe_integer"),
    "big_float": (_at(TS, "1e20"), "bundle_structure", "json_unsafe_integer"),
    "excess_precision": (
        _at(CATEGORY, "0.1000000000000000055"),
        "bundle_structure",
        "json_excess_precision",
    ),
    "infinity_literal": (_at(CATEGORY, "Infinity"), "bundle_structure", "json_non_finite"),
    "overflowing_float": (_at(CATEGORY, "1e999"), "bundle_structure", "json_non_finite"),
    "lone_surrogate": (_at(CATEGORY, '"\\ud800"'), "bundle_structure", "json_lone_surrogate"),
    "too_deep": (_at(CATEGORY, _nested(MAX_DEPTH + 1)), "bundle_structure", "json_too_deep"),
    "deep_at_the_limit": (_at(CATEGORY, _nested(MAX_DEPTH)), None, None),
    "harmless_float": (_at(CATEGORY, "1.50"), None, None),
    "float_for_version": (_at(("v",), "1.0"), "bundle_structure", "bundle_version"),
    "true_for_version": (_at(("v",), "true"), "bundle_structure", "bundle_version"),
    "true_for_proof_version": (
        _at(("log", "proofs", 0, "v"), "true"),
        "decision_log",
        "proof_shape",
    ),
    "float_for_proof_version": (
        _at(("log", "proofs", 0, "v"), "1.0"),
        "decision_log",
        "proof_shape",
    ),
    "float_for_log_size": (_at(("log", "size"), "41.0"), "decision_log", "log_truncated"),
    "infinity_amount": (
        _at(("paypal", "capture", 0, "amount", "value"), '"Infinity"'),
        "paypal_objects",
        "paypal_amount_malformed",
    ),
    "exponent_amount": (
        _at(("paypal", "capture", 0, "amount", "value"), '"4.5E1"'),
        "paypal_objects",
        "paypal_amount_malformed",
    ),
    "negative_seq": (_at(SEQ, "-1"), "decision_log", "log_entry_number"),
    "float_seq": (_at(SEQ, "5.0"), "decision_log", "log_entry_number"),
    "negative_ts": (_at(TS, "-1"), "decision_log", "log_entry_number"),
    "float_ts": (_at(TS, "1800000000000011.0"), "decision_log", "log_entry_number"),
}


def strict_text(valid: Bundle, name: str) -> str:
    bundle, raw = STRICT[name][0](valid)
    text = json.dumps(bundle, indent=1, sort_keys=True) + "\n"
    assert text.count(f'"{MARK}"') == 1
    return text.replace(f'"{MARK}"', raw)


def write_strict_vectors(valid: Bundle, directory: Any) -> list[dict[str, Any]]:
    """Write every case under `directory/strict/` and return the `index.json` entries."""
    out = directory / "strict"
    out.mkdir(parents=True, exist_ok=True)
    index = []
    for name, (_, step, code) in sorted(STRICT.items()):
        (out / f"{name}.json").write_text(strict_text(valid, name))
        index.append({"file": f"strict/{name}.json", "first_failure": step, "code": code})
    return index
