"""Eval runner: `uv run python -m eval.run --suite attacks --mode both`.

Runs every attack case under `eval/attacks/` in `full`, `baseline` or both, judges each from PayPal
state and the decision log, and writes `eval/reports/<timestamp>/report.{json,md}` and
`eval/reports/latest.json`. Exit status 1 when a case's outcome differs from its declared
expectation or a case crashed, 0 otherwise.
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
from eval.harness import run_case, scratch_databases
from eval.report import build, row, write


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


def run_suite(modes: list[str], only: list[str] | None = None) -> list[dict[str, Any]]:
    cases = [c for c in load_cases() if not only or c.id in only]
    rows = []
    with scratch_databases() as dbs:
        for case in cases:
            for mode in modes:
                rows.append(row(case, mode, run_case(case, mode, dbs)))
    return rows


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(prog="eval.run")
    parser.add_argument("--suite", choices=["attacks"], default="attacks")
    parser.add_argument("--mode", choices=["full", "baseline", "both"], default="both")
    parser.add_argument("--case", action="append", help="run only this case id (repeatable)")
    parser.add_argument("--no-write", action="store_true", help="print only; write no report")
    args = parser.parse_args(argv)
    structlog.configure(wrapper_class=structlog.make_filtering_bound_logger(logging.WARNING))
    modes = ["full", "baseline"] if args.mode == "both" else [args.mode]
    rows = run_suite(modes, args.case)
    report = build(rows, args.suite)
    if not args.no_write:
        print(f"report: {write(report)}")
    for mode, m in report["summary"].items():
        print(f"{mode}: {m}")
    bad = [r for r in rows if r["matches_expectation"] is False or r["error"]]
    for r in bad:
        print(f"MISMATCH {r['case']} [{r['mode']}] got {r['outcome']} expected {r['expected']} "
              f"error={r['error']}", file=sys.stderr)  # fmt: skip
    return 1 if bad else 0


if __name__ == "__main__":
    raise SystemExit(main())
