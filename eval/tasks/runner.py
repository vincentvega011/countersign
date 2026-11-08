"""Run one legitimate task in one mode and judge it from PayPal state and the decision log."""

from __future__ import annotations

import time
from collections.abc import Iterator
from contextlib import contextmanager
from dataclasses import dataclass, field
from typing import Any

from countersign.catalog.catalog import load_catalog
from eval.core import Ctx
from eval.harness import BundleJob, Databases, collect_bundles, reset
from eval.judge import Verdict, judge
from eval.tasks import Task
from tests.mode_support import (
    UCP_AGENT,
    UCP_ROOT,
    make_world,
    purchase,
    settings_for,
    total_of,
)


@dataclass
class TaskRun:
    task: Task
    mode: str
    completed: bool
    latency_ms: float
    verdict: Verdict
    captured_minor: int
    expected_minor: int
    error: str | None = None
    gate_ms: list[float] = field(default_factory=list)  # time in the capture stage, per call
    bundles: list[BundleJob] = field(default_factory=list)

    @property
    def false_block(self) -> bool:
        return not self.completed


def _create(ctx: Ctx, task: Task) -> dict[str, Any]:
    response = ctx.world.client.post(
        UCP_ROOT,
        json={"line_items": [{"item": {"id": i}, "quantity": q} for i, q in task.lines]},
        headers=UCP_AGENT,
    )
    assert response.status_code == 201, response.text
    body: dict[str, Any] = response.json()
    return body


def _autonomous(ctx: Ctx, task: Task) -> int:
    body = _create(ctx, task)
    items = {i.id: i for i in load_catalog().items}
    lines = [(i, items[i].title, q) for i, q in task.lines]
    pair = ctx.mandates(
        body, lines=lines, **({} if task.budget is None else {"budget": task.budget})
    )
    ctx.register(body, pair, budget=task.budget)
    ctx.note(purchase(ctx.world, body, pair))
    return total_of(body)


def _human_present(ctx: Ctx, task: Task) -> int:
    from tests.human_present import human_present_purchase

    return human_present_purchase(ctx, _create(ctx, task))


@contextmanager
def timed_capture_stage() -> Iterator[list[float]]:
    """Time every call of the capture stage (the gate in full, immediate capture in baseline).

    `ImmediateCapture` inherits `run` from `CaptureGate`, so one wrapper covers both. It only
    measures: arguments and results pass through untouched.
    """
    from countersign.gate.gate import CaptureGate

    samples: list[float] = []
    original = CaptureGate.run

    def run(self: Any, *args: Any, **kwargs: Any) -> Any:
        started = time.perf_counter()
        try:
            return original(self, *args, **kwargs)
        finally:
            samples.append((time.perf_counter() - started) * 1000)

    CaptureGate.run = run  # type: ignore[method-assign]
    try:
        yield samples
    finally:
        CaptureGate.run = original  # type: ignore[method-assign]


def run_task(task: Task, mode: str, dbs: Databases) -> TaskRun:
    reset(dbs.admin)
    settings = settings_for(mode)
    world = make_world(dbs.app, settings)
    ctx = Ctx(world, dbs.admin, settings.mode.value)
    error = None
    expected = 0
    started = time.perf_counter()
    with world.client, timed_capture_stage() as gate_samples:
        try:
            expected = (_human_present if task.kind == "human_present" else _autonomous)(ctx, task)
        except Exception as exc:  # noqa: BLE001 - a crashed task is a failed task, reported
            error = f"{type(exc).__name__}: {exc}"[:200]
    latency = (time.perf_counter() - started) * 1000
    verdict = judge(ctx, dbs.app)
    captured = verdict.captured_minor
    completed = (
        error is None and verdict.captures == 1 and captured == expected
        and not verdict.violations and verdict.outcome == "blocked"
    )  # fmt: skip
    return TaskRun(
        task,
        mode,
        completed,
        latency,
        verdict,
        captured,
        expected,
        error,
        list(gate_samples),
        collect_bundles(world, dbs.admin),
    )
