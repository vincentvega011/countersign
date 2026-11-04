"""The offline evidence verifier: a valid bundle passes, every tampering fails at the right step.

The valid bundle is `tests/vectors/evidence/valid.json`, produced by the service itself over the PayPal
simulator (synthetic ids and throwaway keys). The tampered cases are `tests/evidence_tamper.py`; the same
cases are written as files under `tests/vectors/evidence/tampered/` for the browser verifier.
"""

from __future__ import annotations

import copy
import json
import subprocess
import sys
from pathlib import Path
from typing import Any

import pytest

from countersign_verify import verify, verify_text
from tests.evidence_tamper import TAMPERS, flip

ROOT = Path(__file__).resolve().parents[2]
VECTORS = ROOT / "tests" / "vectors" / "evidence"
VALID: dict[str, Any] = json.loads((VECTORS / "valid.json").read_text())
PINNED = {"merchant": VALID["keys"]["merchant"], "platform": VALID["keys"]["platform"]}
STEPS = [
    "bundle_structure",
    "checkout_mandate",
    "checkout_jwt_hash",
    "checkout_receipt",
    "payment_mandate",
    "payment_receipt",
    "consent_signature",
    "paypal_objects",
    "paypal_custom_id",
    "gate_result",
    "decision_log",
    "trusted_keys",
]


def first_failure(raw: Any, pinned: Any = PINNED) -> str | None:
    for result in verify(raw, pinned):
        if not result.ok:
            return result.name
    return None


def test_the_valid_bundle_passes_every_step_in_order() -> None:
    results = verify(copy.deepcopy(VALID), PINNED)
    assert [r.name for r in results] == STEPS
    assert all(r.ok for r in results), [r for r in results if not r.ok]


def test_without_pinned_keys_only_the_pinning_step_fails() -> None:
    results = verify(copy.deepcopy(VALID))
    failed = [r for r in results if not r.ok]
    assert [r.name for r in failed] == ["trusted_keys"] and "pin them" in failed[0].message


def test_a_pinned_key_that_differs_from_the_bundles_fails() -> None:
    other = {"merchant": VALID["keys"]["platform"], "platform": VALID["keys"]["platform"]}
    assert first_failure(copy.deepcopy(VALID), other) not in (None,)


@pytest.mark.parametrize("name", sorted(TAMPERS))
def test_each_tampering_fails_at_the_right_step_with_a_message(name: str) -> None:
    tamper, step = TAMPERS[name]
    bundle = copy.deepcopy(VALID)
    tamper(bundle)
    results = verify(bundle, PINNED)
    failed = [r for r in results if not r.ok]
    assert failed, f"{name} was accepted"
    assert failed[0].name == step, (name, [(r.name, r.message) for r in failed])
    assert failed[0].message and len(failed[0].message) > 10


def _strings(node: Any, path: tuple[Any, ...] = ()) -> list[tuple[Any, ...]]:
    if isinstance(node, dict):
        return [p for k, v in node.items() for p in _strings(v, (*path, k))]
    if isinstance(node, list):
        return [p for i, v in enumerate(node) for p in _strings(v, (*path, i))]
    return [path] if isinstance(node, str) else []


def _set(root: Any, path: tuple[Any, ...], value: str) -> None:
    for step in path[:-1]:
        root = root[step]
    root[path[-1]] = value


def _get(root: Any, path: tuple[Any, ...]) -> str:
    for step in path:
        root = root[step]
    return str(root)


IGNORED = {
    ("kind",),
    ("keys", "merchant", "kid"),
    ("keys", "merchant", "alg"),
    ("keys", "merchant", "use"),
}


def test_changing_any_character_of_any_component_is_caught() -> None:
    """A one character change at three positions of every string in the bundle never passes."""
    missed: list[tuple[Any, ...]] = []
    for path in _strings(VALID):
        if (
            path in IGNORED
            or path[0] in ("log",)
            and path[1] == "entries"
            and path[-1] in ("ts_us",)
        ):
            continue
        text = _get(VALID, path)
        if not text:
            continue
        for at in (0, len(text) // 2, len(text) - 1):
            bundle = copy.deepcopy(VALID)
            _set(bundle, path, flip(text, at))
            if first_failure(bundle) is None:
                missed.append((*path, at))
    # Not compared by design (L45): PayPal timestamps, the status of earlier reads (an order is
    # CREATED, then APPROVED, then COMPLETED; only the last read of each kind is judged), the item
    # category, `reference_id`, the payee's identity (only that it stays the same), and a nested
    # authorization's status and times.
    names = {
        "create_time",
        "expiration_time",
        "update_time",
        "reference_id",
        "category",
        "status",
        "currency_code",
        "merchant_id",
    }
    allowed = [m for m in missed if m[0] == "paypal" and (m[-2] in names or (m[-3] == "breakdown"))]
    assert [m for m in missed if m not in allowed] == [], missed


def test_garbage_is_a_structure_failure_not_a_crash() -> None:
    for text in ("", "[]", "{}", '{"v": 1}', "not json", '{"a": 1, "a": 2}', "NaN"):
        results = verify_text(text)
        assert results and results[0].name == "bundle_structure" and not results[0].ok


def test_the_command_line_exit_codes() -> None:
    def run(*args: str) -> subprocess.CompletedProcess[str]:
        return subprocess.run(
            [sys.executable, "-m", "countersign_verify", *args],
            capture_output=True,
            text=True,
            cwd=ROOT,
            check=False,
        )

    keys = [
        "--merchant-key",
        str(VECTORS / "merchant.key.json"),
        "--platform-key",
        str(VECTORS / "platform.key.json"),
    ]
    ok = run(str(VECTORS / "valid.json"), *keys)
    assert ok.returncode == 0 and ok.stdout.count("PASS") == 12
    bad = run(str(VECTORS / "tampered" / "paypal_capture_amount.json"), *keys)
    assert bad.returncode == 1 and "FAIL  paypal_objects" in bad.stdout
    assert run(str(VECTORS / "missing.json")).returncode == 2
    assert json.loads(run(str(VECTORS / "valid.json"), "--json", *keys).stdout)[0]["ok"] is True


def test_the_committed_tampered_vectors_are_current_and_synthetic() -> None:
    index = json.loads((VECTORS / "index.json").read_text())
    assert {e["file"] for e in index["tampered"]} == {f"tampered/{n}.json" for n in TAMPERS}
    for name, (tamper, step) in TAMPERS.items():
        expected = copy.deepcopy(VALID)
        tamper(expected)
        assert json.loads((VECTORS / "tampered" / f"{name}.json").read_text()) == expected
        assert {"file": f"tampered/{name}.json", "first_failure": step} in index["tampered"]


def test_no_vector_holds_an_email_a_name_a_token_or_a_private_key() -> None:
    """Every committed evidence fixture is synthetic: PayPal members are the allowlisted ones only."""
    import re

    from countersign.evidence.observer import SPECS

    forbidden_keys = re.compile(
        r"(?i)payer|email|given_name|surname|phone|address|access_token|client_secret|api_?key|^d$"
    )
    text_pattern = re.compile(r"@|(?i:bearer )|PRIVATE KEY|SCRUBBED_")

    def walk(node: Any, where: str) -> None:
        if isinstance(node, dict):
            for key, value in node.items():
                assert not forbidden_keys.search(key), f"{where}: member {key}"
                walk(value, where)
        elif isinstance(node, list):
            for value in node:
                walk(value, where)
        elif isinstance(node, str):
            assert not text_pattern.search(node), f"{where}: {node[:30]}"

    for path in sorted(VECTORS.rglob("*.json")):
        walk(json.loads(path.read_text()), path.name)

    def allowed(node: Any, spec: Any) -> bool:
        if isinstance(spec, list):
            return all(allowed(x, spec[0]) for x in node)
        if isinstance(spec, dict):
            return (
                isinstance(node, dict)
                and set(node) <= set(spec)
                and all(allowed(v, spec[k]) for k, v in node.items())
            )
        return not isinstance(node, (dict, list))

    for kind, spec in SPECS.items():
        assert all(allowed(body, spec) for body in VALID["paypal"][kind]), kind


def test_a_swapped_platform_key_fails_the_mandate_step_when_nothing_is_pinned() -> None:
    bundle = copy.deepcopy(VALID)
    TAMPERS["platform_key_swapped"][0](bundle)
    failed = [r.name for r in verify(bundle) if not r.ok]
    assert failed[0] == "checkout_mandate"


# ------------------------------------------------------------------------------------ signed but wrong
# Bundles in which every signature is valid and two signed things disagree (tests/evidence_forge.py).


def forged(**kw: Any) -> dict[str, Any]:
    from tests.evidence_forge import Defects, build

    return build(Defects(**kw))


def first(bundle: dict[str, Any]) -> tuple[str, str]:
    pinned = {"merchant": bundle["keys"]["merchant"], "platform": bundle["keys"]["platform"]}
    failed = [r for r in verify(bundle, pinned) if not r.ok]
    assert failed, "the bundle was accepted"
    return failed[0].name, failed[0].message


def test_the_forger_builds_a_bundle_that_verifies() -> None:
    bundle = forged()
    pinned = {"merchant": bundle["keys"]["merchant"], "platform": bundle["keys"]["platform"]}
    assert all(r.ok for r in verify(bundle, pinned))


def _second_checkout(c: dict[str, Any]) -> None:
    c["id"] = "chk_anotheranotheranother"


def _device_thumb(r: dict[str, Any]) -> None:
    r["device_thumbprint"] = "x" * 43


def _checkout_exp(r: dict[str, Any]) -> None:
    r["mandate"]["checkout"]["exp"] += 1


def _payment_budget(r: dict[str, Any]) -> None:
    r["mandate"]["payment"]["constraints"][2]["max"] += 1


def _second_payee(paypal: dict[str, Any]) -> None:
    older = copy.deepcopy(paypal["order"][0])
    older["purchase_units"][0]["payee"]["merchant_id"] = "SOMEONEELSE"
    paypal["order"].insert(0, older)


def _wrong_nested_capture(paypal: dict[str, Any]) -> None:
    paypal["order"][0]["purchase_units"][0]["payments"]["captures"][0]["id"] = "CAP9"


def _wrong_item_total(paypal: dict[str, Any]) -> None:
    paypal["order"][0]["purchase_units"][0]["amount"]["breakdown"]["item_total"]["value"] = "44.00"


def _wrong_intent(paypal: dict[str, Any]) -> None:
    paypal["order"][0]["intent"] = "CAPTURE"


def _auth_not_captured(paypal: dict[str, Any]) -> None:
    paypal["authorization"][0]["status"] = "CREATED"


def _not_final(paypal: dict[str, Any]) -> None:
    paypal["capture"][0]["final_capture"] = False


CASES: dict[str, tuple[dict[str, Any], str, str]] = {
    "key binding for another open mandate": (
        {"kb_sd_hash": lambda s: s[:-5] + "AAAA~"},
        "checkout_mandate",
        "not bound",
    ),
    "key binding audience": ({"kb_aud_checkout": "somebody"}, "checkout_mandate", "audience"),
    "closed after the open mandate expired": (
        {"closed_iat": 1_800_000_000 + 7200},
        "checkout_mandate",
        "expired",
    ),
    "checkout_hash not the hash of the checkout_jwt": (
        {"checkout_hash": "A" * 43},
        "checkout_mandate",
        "not the hash",
    ),
    "a disclosure nothing refers to": (
        {"extra_closed_disclosure": True},
        "checkout_mandate",
        "nothing refers",
    ),
    "checkout receipt for another mandate": (
        {"receipt_reference_checkout": "B" * 43},
        "checkout_receipt",
        "reference",
    ),
    "an error receipt": ({"receipt_status": "Error"}, "checkout_receipt", "Success"),
    "checkout receipt of the wrong typ": (
        {"receipt_typ_checkout": "payment-receipt+jwt"},
        "checkout_receipt",
        "typ",
    ),
    "checkout receipt for another checkout": (
        {"checkout_receipt_order": "chk_other"},
        "checkout_receipt",
        "another checkout",
    ),
    "payment named another checkout": (
        {"payment_checkout_edit": _second_checkout},
        "payment_mandate",
        "another checkout",
    ),
    "payment amount is not the total": ({"payment_amount": 4000}, "payment_mandate", "amount"),
    "a payee the customer did not allow": (
        {"payee": {"id": "m-other", "name": "Other", "website": "https://o.example.test"}},
        "payment_mandate",
        "payee",
    ),
    "total over the approved budget": ({"budget": 4000}, "payment_mandate", "budget"),
    "payment reference to another checkout mandate": (
        {"reference_constraint": "C" * 43},
        "payment_mandate",
        "not bound",
    ),
    "payment receipt for another capture": (
        {"payment_receipt_capture": "CAP9"},
        "payment_receipt",
        "another capture",
    ),
    "payment receipt reference": (
        {"receipt_reference_payment": "D" * 43},
        "payment_receipt",
        "reference",
    ),
    "consent names another device key": (
        {"consent_edit": _device_thumb},
        "consent_signature",
        "another device key",
    ),
    "consent signed terms differ from the checkout mandate": (
        {"consent_edit": _checkout_exp},
        "consent_signature",
        "Checkout Mandate",
    ),
    "consent signed terms differ from the payment mandate": (
        {"consent_edit": _payment_budget},
        "consent_signature",
        "Payment Mandate",
    ),
    "order payee changes between reads": (
        {"paypal_edit": _second_payee},
        "paypal_objects",
        "payee",
    ),
    "nested capture of another id": (
        {"paypal_edit": _wrong_nested_capture},
        "paypal_objects",
        "does not name",
    ),
    "order item_total": ({"paypal_edit": _wrong_item_total}, "paypal_objects", "item_total"),
    "order is not an authorization": (
        {"paypal_edit": _wrong_intent},
        "paypal_objects",
        "authorization order",
    ),
    "authorization not captured": (
        {"paypal_edit": _auth_not_captured},
        "paypal_objects",
        "not captured",
    ),
    "capture not final": ({"paypal_edit": _not_final}, "paypal_objects", "final capture"),
    "gate step skipped": ({"skip_gate_step": "G-BUDGET"}, "gate_result", "G-BUDGET"),
    "gate step twice": ({"double_gate_step": "G-LOCK"}, "gate_result", "G-LOCK"),
    "captured entry disagrees with the receipt": (
        {"captured_reference": "E" * 43},
        "gate_result",
        "disagree",
    ),
    "captured entry amount": ({"captured_amount": "USD:1"}, "gate_result", "another capture"),
}


@pytest.mark.parametrize("name", sorted(CASES))
def test_signed_but_inconsistent_bundles_fail_at_the_named_step(name: str) -> None:
    kw, step, word = CASES[name]
    got, message = first(forged(**kw))
    assert got == step and word in message, (name, got, message)


def test_a_checkout_header_with_another_algorithm_is_refused() -> None:
    got, message = first(forged(jwt_alg="ES384"))
    assert got == "checkout_jwt_hash" and "ES256" in message


def test_the_bundled_open_mandate_must_be_the_one_the_closed_mandate_extends() -> None:
    bundle = forged()
    bundle["mandates"]["checkout_open"] = forged()["mandates"]["checkout_open"]
    got, message = first(bundle)
    assert got == "checkout_mandate" and "does not extend" in message


def test_a_duplicate_json_key_is_refused_before_anything_else() -> None:
    text = json.dumps(VALID, sort_keys=True)
    results = verify_text(text[:1] + '"v": 1, ' + text[1:])
    assert results[0].name == "bundle_structure" and "duplicate" in results[0].message
