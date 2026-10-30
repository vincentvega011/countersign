"""The attack suite in both modes: outcomes against each case's declared expectation.

Ground truth is the PayPal simulator state and the decision log (`eval.judge`). The suite is run once
for the module and the assertions read its rows; determinism runs it a second time.
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

import pytest
from sqlalchemy import Engine

from countersign.ablations import Ablations
from countersign.runtime import Mode, RuntimeSettings
from eval.harness import Databases, run_case
from eval.report import build, markdown, row, write
from eval.run import load_cases

CASES = load_cases()
BY_ID = {c.id: c for c in CASES}

REQUIRED_CATEGORIES = {
    "protocol_downgrade_acp", "new_session_escape", "order_changed_after_approval", "nonce_replay",
    "open_mandate_double_spend", "checkout_swap", "budget_split", "category_escape",
    "consent_missing", "mandate_forged", "alg_confusion", "duplicate_json_keys", "webhook_spoof",
    "double_complete_retry", "mandate_expired", "mandate_revoked", "price_change_before_complete",
    "custom_id_tamper", "merchant_authorization_strip", "decimal_ambiguity",
}  # fmt: skip
BASELINE_MUST_FALL = {
    "protocol_downgrade_acp",
    "order_raised_after_approval",
    "nonce_replay_new_session",
}


@pytest.fixture(scope="module")
def dbs(admin_engine: Engine, app_engine: Engine) -> Databases:
    return Databases(admin_engine, app_engine)


def run_all(dbs: Databases) -> list[dict[str, Any]]:
    return [row(c, m, run_case(c, m, dbs)) for c in CASES for m in ("full", "baseline")]


@pytest.fixture(scope="module")
def rows(dbs: Databases) -> list[dict[str, Any]]:
    return run_all(dbs)


def test_there_are_twenty_five_cases_covering_the_required_categories() -> None:
    assert len(CASES) >= 25 and len({c.id for c in CASES}) == len(CASES)
    assert REQUIRED_CATEGORIES <= {c.category for c in CASES}
    for case in CASES:
        assert case.description and case.steps and case.success_condition, case.id


@pytest.mark.parametrize("mode", ["full", "baseline"])
def test_every_case_does_what_it_declares(rows: list[dict[str, Any]], mode: str) -> None:
    wrong = [
        (r["case"], r["outcome"], r["expected"], r["error"])
        for r in rows
        if r["mode"] == mode and (r["matches_expectation"] is not True or r["error"])
    ]
    assert wrong == []
    for r in rows:
        expected = BY_ID[r["case"]].expected[r["mode"]].reason
        if r["mode"] == mode and expected is not None:
            assert r["reason_code"] == expected, r["case"]


def test_in_full_mode_every_attack_fails_with_no_unauthorized_capture_or_duplicate_object(
    rows: list[dict[str, Any]],
) -> None:
    full = [r for r in rows if r["mode"] == "full"]
    assert len(full) == len(CASES)
    assert [r["case"] for r in full if r["outcome"] != "blocked"] == []
    assert sum(r["unauthorized_captures"] for r in full) == 0
    assert sum(r["duplicate_paypal_objects"] for r in full) == 0
    assert all(r["log_chain_ok"] and r["captures_without_log"] == 0 for r in full)


def test_in_baseline_the_three_headline_attacks_succeed_and_the_rest_are_reported(
    rows: list[dict[str, Any]],
) -> None:
    baseline = {r["case"]: r for r in rows if r["mode"] == "baseline"}
    for case_id in BASELINE_MUST_FALL:
        assert baseline[case_id]["outcome"] == "success", case_id
        assert baseline[case_id]["unauthorized_captures"] >= 1
    assert all(r["duplicate_paypal_objects"] == 0 for r in baseline.values())
    assert all(r["log_chain_ok"] for r in baseline.values())


def test_the_suite_is_deterministic(dbs: Databases, rows: list[dict[str, Any]]) -> None:
    assert run_all(dbs) == rows


def test_the_report_files_are_well_formed(rows: list[dict[str, Any]], tmp_path: Path) -> None:
    report = build(rows, "attacks")
    target = write(report, tmp_path / "run")
    loaded = json.loads((target / "report.json").read_text())
    assert loaded["suite"] == "attacks" and len(loaded["cases"]) == 2 * len(CASES)
    assert loaded["summary"]["full"]["attacks_succeeded"] == 0
    for key in (
        "case",
        "category",
        "mode",
        "outcome",
        "reason_code",
        "captured_minor",
        "paypal_calls",
    ):
        assert all(key in c for c in loaded["cases"])
    text = (target / "report.md").read_text()
    assert text == markdown(report) and text.count("\n| ") > 2 * len(CASES)
    assert "em dash" not in text and "—" not in text


# ------------------------------------------------------------------ case level mutation checks

NO_GATE = RuntimeSettings(Mode.FULL, "dev", Ablations(no_gate=True))
NO_GATE_NO_PREAUTH = RuntimeSettings(
    Mode.FULL, "dev", Ablations(no_gate=True, no_preauth_check=True)
)
NO_GLOBAL_NONCE = RuntimeSettings(Mode.FULL, "dev", Ablations(no_global_nonce=True))
NO_LOCK = RuntimeSettings(Mode.FULL, "dev", Ablations(no_principal_lock=True))
NO_JSON = RuntimeSettings(Mode.FULL, "dev", Ablations(no_strict_json=True))

# (defense weakened, the configuration that weakens it, the attack that must flip to success)
FLIPS = [
    ("capture gate and pre-authorize check", NO_GATE_NO_PREAUTH, "order_raised_after_approval"),
    ("capture gate and pre-authorize check", NO_GATE_NO_PREAUTH, "order_items_changed_after_approval"),
    ("capture gate and pre-authorize check", NO_GATE_NO_PREAUTH, "custom_id_tamper"),
    ("capture gate (G-MANDATE)", NO_GATE, "mandate_revoked"),
    ("global single use of nonces", NO_GLOBAL_NONCE, "nonce_replay_new_session"),
    ("global single use of the open mandate", NO_GLOBAL_NONCE, "open_mandate_double_spend"),
]  # fmt: skip


@pytest.mark.parametrize(("defense", "settings", "case_id"), FLIPS)
def test_weakening_a_defense_flips_the_attack_it_stops(
    dbs: Databases, defense: str, settings: RuntimeSettings, case_id: str
) -> None:
    assert BY_ID[case_id].expected["full"].outcome == "blocked"
    weakened = run_case(BY_ID[case_id], settings, dbs)
    assert weakened.error is None
    assert weakened.verdict.outcome == "success", f"{defense}: {case_id} still blocked"
    assert weakened.verdict.unauthorized_captures + weakened.verdict.duplicate_objects >= 1


def test_the_principal_lock_alone_is_backed_up_by_the_unmandated_policy(dbs: Databases) -> None:
    """Honest layering: with the lock off the downgrade is still refused, by the merchant policy."""
    case = BY_ID["protocol_downgrade_acp"]
    run = run_case(case, NO_LOCK, dbs)
    assert run.verdict.outcome == "blocked" and run.reason == "unmandated_checkout_not_allowed"
    assert run_case(case, "baseline", dbs).verdict.outcome == "success"  # lock and policy both gone


def test_strict_json_off_shows_up_as_a_side_effect_not_as_money(dbs: Databases) -> None:
    run = run_case(BY_ID["duplicate_json_keys"], NO_JSON, dbs)
    assert run.verdict.outcome == "blocked" and "ambiguous_body_accepted" in run.side_effects
