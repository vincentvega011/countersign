"""The verifier's JSON number rules, nesting cap and type-exact checks (Decision 106), in Python.

The browser verifier is held to the same files in `web/ui/test/evidence.test.mjs`, and the two are compared
directly in `tests/unit/test_verifier_agreement.py`.
"""

from __future__ import annotations

import base64
import json
from pathlib import Path
from typing import Any

import pytest

from countersign_verify import verify, verify_text
from countersign_verify.crypto import MAX_DEPTH, Float, Invalid, loads, same
from tests.evidence_strict import STRICT, strict_text

ROOT = Path(__file__).resolve().parents[2]
VECTORS = ROOT / "tests" / "vectors" / "evidence"
VALID: dict[str, Any] = json.loads((VECTORS / "valid.json").read_text())
INDEX = json.loads((VECTORS / "index.json").read_text())
RULES = json.loads((VECTORS / "json_rules.json").read_text())
PINNED = {k: loads((VECTORS / f"{k}.key.json").read_bytes()) for k in ("merchant", "platform")}


def kind_of(value: Any) -> str:
    if isinstance(value, Float):
        return "float"
    return "int" if type(value) is int else type(value).__name__


@pytest.mark.parametrize(
    "case", RULES["cases"], ids=lambda c: repr(c.get("text", c.get("note")))[:30]
)
def test_each_json_rule_case(case: dict[str, Any]) -> None:
    data = case["text"].encode() if "text" in case else base64.b64decode(case["bytes_b64"])
    try:
        got = {"ok": True, "kind": kind_of(loads(data))}
    except Invalid as error:
        got = {"ok": False, "code": error.code}
    want = {"ok": True, "kind": case["kind"]} if case["ok"] else {"ok": False, "code": case["code"]}
    assert got == want


def test_the_rule_table_states_the_cap_and_covers_both_sides_of_it() -> None:
    assert RULES["max_depth"] == MAX_DEPTH == 64
    texts = {c.get("text") for c in RULES["cases"]}
    assert "[" * 64 + "]" * 64 in texts and "[" * 65 + "]" * 65 in texts


@pytest.mark.parametrize("name", sorted(STRICT))
def test_each_strict_vector_is_current_and_fails_where_the_index_says(name: str) -> None:
    path = VECTORS / "strict" / f"{name}.json"
    assert path.read_text() == strict_text(VALID, name)
    entry = next(e for e in INDEX["strict"] if e["file"] == f"strict/{name}.json")
    _, step, code = STRICT[name]
    assert (entry["first_failure"], entry["code"]) == (step, code)
    first = next((r for r in verify_text(path.read_bytes(), PINNED) if not r.ok), None)
    assert (first.name if first else None, first.code if first else None) == (step, code)


def test_type_exact_equality() -> None:
    assert not same(True, 1) and not same(Float(1.0), 1) and same(Float(1.0), Float(1.0))
    assert same({"a": [1, "x"]}, {"a": [1, "x"]}) and not same({"a": 1}, {"a": True})


def test_pinning_only_one_key_is_not_pinning() -> None:
    failed = [r for r in verify(json.loads(json.dumps(VALID)), {"merchant": PINNED["merchant"]})]
    assert [(r.name, r.code) for r in failed if not r.ok] == [
        ("trusted_keys", "keys_partly_pinned")
    ]


def test_every_failure_has_a_stable_code_and_nothing_crashes() -> None:
    for entry in INDEX["tampered"] + INDEX["strict"]:
        for r in verify_text((VECTORS / entry["file"]).read_bytes(), PINNED):
            assert r.ok == (r.code is None), (entry, r)
