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
        "paypal_calls": None if case.racy else v.paypal_calls,
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


def _percentile(values: list[float], q: float) -> float:
    ordered = sorted(values)
    return round(ordered[min(len(ordered) - 1, int(q * len(ordered)))], 1) if ordered else 0.0


def summarize_tasks(rows: list[dict[str, Any]]) -> dict[str, Any]:
    out: dict[str, dict[str, Any]] = {}
    for mode in sorted({r["mode"] for r in rows}):
        mine = [r for r in rows if r["mode"] == mode]
        done = sum(r["completed"] for r in mine)
        blocked = len(mine) - done
        lat = [r["latency_ms"] for r in mine]
        out[mode] = {
            "tasks": len(mine), "completed": done, "completion_rate": round(done / len(mine), 4),
            "false_blocks": blocked, "false_block_rate": round(blocked / len(mine), 4),
            "unauthorized_captures": sum(r["unauthorized_captures"] for r in mine),
            "duplicate_paypal_objects": sum(r["duplicate_paypal_objects"] for r in mine),
            "latency_p50_ms": _percentile(lat, 0.5), "latency_p95_ms": _percentile(lat, 0.95),
        }  # fmt: skip
    return out


def summarize_pytest(rows: list[dict[str, Any]]) -> dict[str, Any]:
    return {
        "passed": sum(r["passed"] for r in rows), "failed": sum(r["failed"] for r in rows),
        "errors": sum(r["errors"] for r in rows), "seed": rows[0]["seed"] if rows else None,
    }  # fmt: skip


def build_section(rows: list[dict[str, Any]]) -> dict[str, Any]:
    """One suite's rows with its own summary and time stamp (every suite is dated on its own)."""
    if rows and "completed" in rows[0]:
        summary = summarize_tasks(rows)
    elif rows and "exit_status" in rows[0]:
        summary = summarize_pytest(rows)
    else:
        summary = summarize(rows)
    return {
        "generated_at": datetime.now(UTC).strftime("%Y-%m-%dT%H:%M:%SZ"),
        "summary": summary, "cases": rows,
    }  # fmt: skip


def build_all(
    attack_rows: list[dict[str, Any]], sections: dict[str, dict[str, Any]]
) -> dict[str, Any]:
    return {**build(attack_rows, "all"), "sections": sections}


def section_markdown(name: str, section: dict[str, Any]) -> list[str]:
    lines = ["", f"## Suite: {name}", "", f"Generated {section['generated_at']}.", ""]
    summary = section["summary"]
    if name in ("properties", "concurrency"):
        lines.append(f"Seed {summary['seed']}: {summary['passed']} passed, {summary['failed']} "
                     f"failed, {summary['errors']} errors.")  # fmt: skip
        return lines
    if name == "tasks":
        lines += ["| mode | tasks | completed | completion | false blocks | p50 ms | p95 ms |",
                  "| --- | --- | --- | --- | --- | --- | --- |"]  # fmt: skip
        for mode, m in summary.items():
            lines.append(f"| {mode} | {m['tasks']} | {m['completed']} | {m['completion_rate']:.1%} | "
                         f"{m['false_blocks']} | {m['latency_p50_ms']} | {m['latency_p95_ms']} |")  # fmt: skip
        return lines
    lines.append(
        "| mode | goals | succeeded | unauthorized captures | duplicate PayPal objects "
        "| mismatches | errors |"
    )
    lines.append("| --- | --- | --- | --- | --- | --- | --- |")
    for mode, m in summary.items():
        lines.append(f"| {mode} | {m['cases']} | {m['attacks_succeeded']} | {m['unauthorized_captures']} "
                     f"| {m['duplicate_paypal_objects']} | {m['mismatches']} | {m['errors']} |")  # fmt: skip
    return lines


def merged_latest(target: Path, report: dict[str, Any]) -> dict[str, Any]:
    """Merge this run into `latest.json`: only the sections that ran are replaced, each keeps its own date."""
    try:
        previous = json.loads((REPORTS / "latest.json").read_text())
    except (OSError, ValueError):
        previous = {}
    sections = dict(previous.get("sections", {}))
    suite = report["suite"]
    if suite in ("attacks", "all"):
        base = {k: report[k] for k in ("generated_at", "summary", "cases")}
        sections.update(report.get("sections", {}))
    else:
        base = {k: previous[k] for k in ("generated_at", "summary", "cases") if k in previous}
        sections[suite] = {k: report[k] for k in ("generated_at", "summary", "cases")}
    return {
        "suite": "attacks",
        "report": f"{target.name}/report.json",
        **base,
        "sections": sections,
    }


def write(report: dict[str, Any], out_dir: Path | None = None) -> Path:
    stamp = datetime.now(UTC).strftime("%Y%m%dT%H%M%SZ")
    target = out_dir or REPORTS / stamp
    target.mkdir(parents=True, exist_ok=True)
    (target / "report.json").write_text(json.dumps(report, indent=1, sort_keys=True) + "\n")
    text = markdown(report) if report["suite"] in ("attacks", "all") else "# Report\n"
    for name, section in sorted(report.get("sections", {}).items()):
        text += "\n".join(section_markdown(name, section)) + "\n"
    if report["suite"] not in ("attacks", "all"):
        text += "\n".join(section_markdown(report["suite"], report)) + "\n"
    (target / "report.md").write_text(text)
    if out_dir is None:
        latest = merged_latest(target, report)
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
