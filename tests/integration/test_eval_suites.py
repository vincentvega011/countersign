"""The legitimate task suite and the report merge (Decision 133)."""

from __future__ import annotations

import json
from dataclasses import replace
from pathlib import Path

import pytest
from sqlalchemy import Engine

import eval.report as report_module
from eval.harness import Databases
from eval.report import build_section, merged_latest, summarize_tasks
from eval.tasks import build_tasks
from eval.tasks.runner import run_task


@pytest.fixture
def dbs(admin_engine: Engine, app_engine: Engine) -> Databases:
    return Databases(admin_engine, app_engine)


def test_the_task_set_is_fixed_varied_and_has_one_human_present_purchase() -> None:
    tasks = build_tasks()
    assert len(tasks) >= 25 and [t.id for t in tasks] == [t.id for t in build_tasks()]
    assert len({t.id for t in tasks}) == len(tasks)
    assert sum(t.kind == "human_present" for t in tasks) == 1
    assert len({line[0] for t in tasks for line in t.lines}) >= 15  # varied items
    assert any(len(t.lines) > 1 for t in tasks) and any(q > 1 for t in tasks for _, q in t.lines)
    assert any(t.budget is None for t in tasks) and any(t.budget for t in tasks)


@pytest.mark.parametrize("mode", ["full", "baseline"])
def test_every_legitimate_task_completes_exactly_once_for_the_signed_total(
    dbs: Databases, mode: str
) -> None:
    runs = [run_task(t, mode, dbs) for t in build_tasks()]
    assert [(r.task.id, r.error, r.verdict.violations) for r in runs if not r.completed] == []
    for r in runs:
        assert r.verdict.captures == 1 and r.captured_minor == r.expected_minor > 0
        assert r.verdict.unauthorized_captures == 0 and r.verdict.duplicate_objects == 0


def test_a_purchase_the_budget_cannot_cover_is_counted_as_a_false_block(dbs: Databases) -> None:
    task = replace(build_tasks()[0], budget=1)  # the customer signed a budget below the price
    run = run_task(task, "full", dbs)
    assert not run.completed and run.false_block and run.verdict.captures == 0


def test_task_figures_are_computed_from_rows() -> None:
    rows = [
        {"mode": "full", "completed": True, "latency_ms": 10.0, "unauthorized_captures": 0,
         "duplicate_paypal_objects": 0},
        {"mode": "full", "completed": False, "latency_ms": 30.0, "unauthorized_captures": 0,
         "duplicate_paypal_objects": 0},
    ]  # fmt: skip
    m = summarize_tasks(rows)["full"]
    assert (m["tasks"], m["completed"], m["false_blocks"]) == (2, 1, 1)
    assert m["completion_rate"] == 0.5 and m["false_block_rate"] == 0.5
    assert m["latency_p50_ms"] == 30.0 and m["latency_p95_ms"] == 30.0
    assert build_section(rows)["summary"] == summarize_tasks(rows)


def test_a_partial_run_replaces_only_its_own_section(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setattr(report_module, "REPORTS", tmp_path)
    old = {"generated_at": "2026-11-01T00:00:00Z", "summary": {"s": 1}, "cases": []}
    (tmp_path / "latest.json").write_text(
        json.dumps({"generated_at": "A", "summary": {"full": {}}, "cases": [1],
                    "sections": {"tasks": old, "adversary": old}})
    )  # fmt: skip
    new = {"generated_at": "B", "summary": {"s": 2}, "cases": []}
    merged = merged_latest(tmp_path / "r1", {"suite": "adversary", **new})
    assert merged["sections"]["adversary"] == new and merged["sections"]["tasks"] == old
    assert merged["generated_at"] == "A" and merged["cases"] == [1]  # attack figures kept
    attacks = {"generated_at": "C", "summary": {"full": {"cases": 2}}, "cases": [2]}
    merged = merged_latest(tmp_path / "r2", {"suite": "attacks", **attacks})
    assert merged["cases"] == [2] and merged["sections"]["tasks"] == old
