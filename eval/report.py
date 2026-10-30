"""The attack report: report.json, report.md and latest.json. Every figure comes from the judge."""

from __future__ import annotations

import json
from dataclasses import asdict
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

from eval.core import AttackCase
from eval.harness import CaseRun

REPORTS = Path(__file__).resolve().parent / "reports"


def row(case: AttackCase, mode: str, run: CaseRun) -> dict[str, Any]:
    v = run.verdict
    expected = case.expected.get(mode)
    return {
        "case": case.id,
        "category": case.category,
        "actor": case.actor.value,
        "mode": mode,
        "outcome": v.outcome,
        "expected": None if expected is None else expected.outcome,
        "matches_expectation": None if expected is None else expected.outcome == v.outcome,
        "reason_code": run.reason,
        "expected_reason": None if expected is None else expected.reason,
        "captured_minor": v.captured_minor,
        "unauthorized_captures": v.unauthorized_captures,
        "duplicate_paypal_objects": v.duplicate_objects,
        "paypal_calls": v.paypal_calls,
        "paypal_orders": v.orders,
        "paypal_authorizations": v.authorizations,
        "paypal_captures": v.captures,
        "violations": v.violations,
        "side_effects": run.side_effects,
        "log_chain_ok": v.log_ok,
        "captures_without_log": v.captures_without_log,
        "error": run.error,
    }


def summarize(rows: list[dict[str, Any]]) -> dict[str, Any]:
    by_mode: dict[str, dict[str, int]] = {}
    for r in rows:
        m = by_mode.setdefault(
            r["mode"],
            {"cases": 0, "attacks_succeeded": 0, "unauthorized_captures": 0,
             "duplicate_paypal_objects": 0, "mismatches": 0, "errors": 0},
        )  # fmt: skip
        m["cases"] += 1
        m["attacks_succeeded"] += r["outcome"] == "success"
        m["unauthorized_captures"] += r["unauthorized_captures"]
        m["duplicate_paypal_objects"] += r["duplicate_paypal_objects"]
        m["mismatches"] += r["matches_expectation"] is False
        m["errors"] += r["error"] is not None
    return by_mode


def markdown(report: dict[str, Any]) -> str:
    lines = [
        "# Attack report",
        "",
        (
            f"Suite: `{report['suite']}`. Generated {report['generated_at']}. "
            "Ground truth: PayPal simulator state and the hash-chained decision log."
        ),
        "",
        "## Totals",
        "",
        (
            "| mode | cases | attacks succeeded | unauthorized captures | duplicate PayPal objects "
            "| mismatches | errors |"
        ),
        "| --- | --- | --- | --- | --- | --- | --- |",
    ]
    for mode, m in report["summary"].items():
        lines.append(
            f"| {mode} | {m['cases']} | {m['attacks_succeeded']} | {m['unauthorized_captures']} | "
            f"{m['duplicate_paypal_objects']} | {m['mismatches']} | {m['errors']} |"
        )
    lines += [
        "",
        "## Cases",
        "",
        (
            "| case | category | mode | outcome | reason code | captured (minor) | PayPal calls "
            "| violations |"
        ),
        "| --- | --- | --- | --- | --- | --- | --- | --- |",
    ]
    for r in report["cases"]:
        lines.append(
            f"| {r['case']} | {r['category']} | {r['mode']} | {r['outcome']} | "
            f"{r['reason_code'] or '-'} | {r['captured_minor']} | {r['paypal_calls']} | "
            f"{', '.join(r['violations']) or '-'} |"
        )
    return "\n".join(lines) + "\n"


def write(report: dict[str, Any], out_dir: Path | None = None) -> Path:
    stamp = datetime.now(UTC).strftime("%Y%m%dT%H%M%SZ")
    target = out_dir or REPORTS / stamp
    target.mkdir(parents=True, exist_ok=True)
    (target / "report.json").write_text(json.dumps(report, indent=1, sort_keys=True) + "\n")
    (target / "report.md").write_text(markdown(report))
    if out_dir is None:
        latest = {"report": f"{target.name}/report.json", **report}
        (REPORTS / "latest.json").write_text(json.dumps(latest, indent=1, sort_keys=True) + "\n")
    return target


def build(rows: list[dict[str, Any]], suite: str) -> dict[str, Any]:
    return {
        "suite": suite,
        "generated_at": datetime.now(UTC).strftime("%Y-%m-%dT%H:%M:%SZ"),
        "summary": summarize(rows),
        "cases": rows,
    }


_ = asdict
