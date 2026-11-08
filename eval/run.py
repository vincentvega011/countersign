"""Eval runner: `uv run python -m eval.run --suite all --mode both`.

Suites: `attacks` (every case under `eval/attacks/`, judged from PayPal state and the decision log),
`adversary` (the scripted goals of `agents/adversary`, judged the same way), `tasks` (legitimate
purchases: completion, latency, false blocks), `properties` and `concurrency` (the Hypothesis and the
parallel tests, run with a fixed seed). `all` runs every suite. Reports go to
`eval/reports/<timestamp>/report.{json,md}` and merge into `eval/reports/latest.json`.

Exit status 1 when an outcome differs from its declared expectation, a case crashed, a task did not
complete or a pytest suite failed, 0 otherwise.
"""

from __future__ import annotations

import argparse
import importlib
import logging
import pkgutil
import sys
from typing import Any

import structlog

import eval.attacks as attacks_package
from eval.core import AttackCase
from eval.harness import BundleJob, run_case, scratch_databases
from eval.report import build, build_all, build_section, row, write
from eval.suites import run_pytest_suite, task_rows

SUITES = ("attacks", "adversary", "tasks", "properties", "concurrency", "all")


def load_cases() -> list[AttackCase]:
    cases = []
    for info in pkgutil.iter_modules(attacks_package.__path__):
        module = importlib.import_module(f"eval.attacks.{info.name}")
        case = getattr(module, "CASE", None)
        if isinstance(case, AttackCase):
            cases.append(case)
    ids = [c.id for c in cases]
    if len(ids) != len(set(ids)):
        raise ValueError("duplicate attack case ids")
    return sorted(cases, key=lambda c: c.id)


def run_suite(
    modes: list[str],
    only: list[str] | None = None,
    bundles: list[tuple[str, BundleJob]] | None = None,
) -> list[dict[str, Any]]:
    """The attack cases in each configuration (a mode or an ablation name from `CONFIGS`).

    `bundles`, when given, collects every evidence bundle the runs stored, tagged with the mode.
    """
    cases = [c for c in load_cases() if not only or c.id in only]
    rows = []
    with scratch_databases() as dbs:
        for case in cases:
            for mode in modes:
                done = run_case(case, mode, dbs)
                rows.append(row(case, mode, done))
                if bundles is not None:
                    bundles.extend((mode, b) for b in done.bundles)
    return rows


def run_adversary(modes: list[str], only: list[str] | None = None) -> list[dict[str, Any]]:
    """The scripted adversary goals, each judged against the registry case of the same id."""
    from agents.adversary.scripts import SCRIPTS
    from eval.adversary.runner import run_goal

    registry = {c.id: c for c in load_cases()}
    rows = []
    with scratch_databases() as dbs:
        for goal in sorted(SCRIPTS):
            if only and goal not in only:
                continue
            for mode in modes:
                done = run_goal(goal, mode, dbs)
                rows.append({**row(registry[goal], mode, done.run), "attempts": done.attempts})
    return rows


def _mismatches(rows: list[dict[str, Any]]) -> list[dict[str, Any]]:
    return [r for r in rows if r.get("matches_expectation") is False or r.get("error")]


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(prog="eval.run")
    parser.add_argument("--suite", choices=SUITES, default="attacks")
    parser.add_argument("--mode", choices=["full", "baseline", "both"], default="both")
    parser.add_argument("--case", action="append", help="run only this case id (repeatable)")
    parser.add_argument(
        "--seeds",
        default=None,
        help="comma separated Hypothesis seeds, for example 0,1,2. With --suite all this runs the "
        "whole evaluation once per seed plus every ablation and writes the full report",
    )
    parser.add_argument("--no-write", action="store_true", help="print only; write no report")
    args = parser.parse_args(argv)
    structlog.configure(wrapper_class=structlog.make_filtering_bound_logger(logging.WARNING))
    if args.seeds is not None:
        if args.suite != "all" or args.mode != "both" or args.case:
            parser.error("--seeds needs --suite all --mode both and no --case")
        from eval.release import run_release

        return run_release([int(x) for x in args.seeds.split(",")], write=not args.no_write)
    modes = ["full", "baseline"] if args.mode == "both" else [args.mode]
    wanted = SUITES[:-1] if args.suite == "all" else (args.suite,)
    sections: dict[str, dict[str, Any]] = {}
    attack_rows: list[dict[str, Any]] = []
    failures: list[str] = []
    for suite in wanted:
        if suite == "attacks":
            attack_rows = run_suite(modes, args.case)
            failures += [f"attack {r['case']} [{r['mode']}]" for r in _mismatches(attack_rows)]
        elif suite == "adversary":
            rows = run_adversary(modes, args.case)
            sections[suite] = build_section(rows)
            failures += [f"adversary {r['case']} [{r['mode']}]" for r in _mismatches(rows)]
        elif suite == "tasks":
            rows = task_rows(modes, args.case)
            sections[suite] = build_section(rows)
            failures += [f"task {r['task']} [{r['mode']}]" for r in rows if not r["completed"]]
        else:
            rows = run_pytest_suite(suite)
            sections[suite] = build_section(rows)
            failures += [f"{suite} {r['target']}" for r in rows if r["failed"] or r["errors"]]
    if args.suite == "attacks":
        report = build(attack_rows, "attacks")
    elif args.suite == "all":
        report = build_all(attack_rows, sections)
    else:
        report = {"suite": args.suite, **sections[args.suite]}
    if not args.no_write:
        print(f"report: {write(report)}")
    if attack_rows:
        for mode, m in report["summary"].items():
            print(f"attacks {mode}: {m}")
    for name, section in sections.items():
        print(f"{name}: {section['summary']}")
    for failure in failures:
        print(f"FAILED {failure}", file=sys.stderr)
    return 1 if failures else 0


if __name__ == "__main__":
    raise SystemExit(main())
