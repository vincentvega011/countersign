# ruff: noqa: ISC004  (report prose is written as adjacent string literals inside lists)
"""The full evaluation: every suite per seed, every ablation, evidence verification, charts, report.

`python -m eval.run --suite all --mode both --seeds 0,1,2` calls `run_release`. The attack, adversary
and task suites involve no randomness, so a seed only changes the Hypothesis examples of the property
and concurrency suites; the other suites are repeated per seed to show the results do not move.
Every figure comes from the judge (PayPal simulator state and the decision log) or from running the
verifiers on stored bundles. Nothing here reads a response body or model output.
"""

from __future__ import annotations

import json
import logging
import sys
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

import structlog

from countersign.ablations import Ablations
from countersign.runtime import Mode, RuntimeSettings
from eval import charts
from eval.harness import BundleJob, run_case, scratch_databases
from eval.report import REPORTS, _percentile, build_section, row
from eval.run import load_cases, run_adversary, run_suite
from eval.suites import run_pytest_suite, task_rows
from eval.verify import verify_jobs
from tests.mode_support import FLAGS

MODES = ["full", "baseline"]
CATEGORY_SIGNATURE = ("case", "mode", "outcome", "reason_code", "captured_minor",
                      "unauthorized_captures", "duplicate_paypal_objects")  # fmt: skip
COMBINED = "ABL_NO_GATE+ABL_NO_PREAUTH_CHECK"
WHY = {
    "ABL_NO_GATE": (
        "No attack case reaches the gate with a difference to catch: PayPal rejects every change after authorization (PROTOCOL 4.3), so "
        "checks that run before authorization stop every case first. The combined row shows the cases "
        "the gate alone stops once the pre-authorize check is also off."
    ),
    "ABL_NO_PREAUTH_CHECK": "The gate voids the authorization instead (the cases end blocked with payment_failed).",
    "ABL_NO_PRINCIPAL_LOCK": "Another check still refuses the unmandated completes, with a different reason code.",
    "ABL_NO_BUDGET_RECON": (
        "The only case it touches is the webhook spoof, which is refused because no webhook endpoint is "
        "mounted without reconciliation; no case drives the budget through PayPal-side state."
    ),
    "ABL_NO_STRICT_JSON": "The lenient parser accepts the body, and the field validation downstream still refuses it.",
}
SIMULATOR = "the PayPal simulator (tests/paypal_sim.py), not live PayPal"


def _signature(rows: list[dict[str, Any]], keys: tuple[str, ...]) -> list[tuple[Any, ...]]:
    return sorted(tuple(r.get(k) for k in keys) for r in rows)


def _totals(rows: list[dict[str, Any]]) -> dict[str, dict[str, int]]:
    out: dict[str, dict[str, int]] = {}
    for r in rows:
        m = out.setdefault(
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
    return out


def _categories(rows: list[dict[str, Any]]) -> list[dict[str, Any]]:
    cats: dict[str, dict[str, Any]] = {}
    for r in rows:
        c = cats.setdefault(
            r["category"],
            {"category": r["category"], "cases": 0, "full_succeeded": 0, "baseline_succeeded": 0,
             "full_unauthorized_captures": 0, "baseline_unauthorized_captures": 0},
        )  # fmt: skip
        if r["mode"] == "full":
            c["cases"] += 1
        c[f"{r['mode']}_succeeded"] += r["outcome"] == "success"
        c[f"{r['mode']}_unauthorized_captures"] += r["unauthorized_captures"]
    return sorted(cats.values(), key=lambda c: c["category"])


def _ablations(
    full_rows: list[dict[str, Any]], by_flag: dict[str, list[dict[str, Any]]]
) -> list[dict[str, Any]]:
    base = {r["case"]: r for r in full_rows}
    out = []
    for flag, rows in by_flag.items():
        reopened = sorted(r["case"] for r in rows if r["outcome"] == "success")
        changed = sorted(
            r["case"] for r in rows
            if r["outcome"] != "success" and r["reason_code"] != base[r["case"]]["reason_code"]
        )  # fmt: skip
        reasons = sorted({str(r["reason_code"]) for r in rows if r["case"] in changed})
        entry: dict[str, Any] = {
            "flag": flag, "cases": len(rows), "reopened": reopened,
            "reopened_count": len(reopened),
            "unauthorized_captures": sum(r["unauthorized_captures"] for r in rows),
            "duplicate_paypal_objects": sum(r["duplicate_paypal_objects"] for r in rows),
            "blocked_by_another_defense": changed, "other_reason_codes": reasons,
            "errors": sum(r["error"] is not None for r in rows),
            "mismatches_with_declared_expectation": sum(r["matches_expectation"] is False for r in rows),
        }  # fmt: skip
        out.append(entry)
    return out


def _stats(values: list[float]) -> dict[str, Any]:
    return {
        "n": len(values),
        "p50_ms": _percentile(values, 0.5),
        "p95_ms": _percentile(values, 0.95),
    }


def _task_summary(rows: list[dict[str, Any]]) -> dict[str, Any]:
    out: dict[str, Any] = {}
    for mode in MODES:
        mine = [r for r in rows if r["mode"] == mode]
        done = sum(r["completed"] for r in mine)
        out[mode] = {
            "runs": len(mine),
            "completed": done,
            "completion_rate": round(done / len(mine), 4) if mine else 0.0,
            "false_blocks": len(mine) - done,
            "false_block_rate": round((len(mine) - done) / len(mine), 4) if mine else 0.0,
            "unauthorized_captures": sum(r["unauthorized_captures"] for r in mine),
            "duplicate_paypal_objects": sum(r["duplicate_paypal_objects"] for r in mine),
            "end_to_end": _stats([r["latency_ms"] for r in mine]),
            "capture_stage": _stats([g for r in mine for g in r["gate_ms"]]),
        }
    return out


def _evidence(bundles: list[tuple[str, BundleJob]], captures: dict[str, int]) -> dict[str, Any]:
    """Per mode: captures made, bundles stored, and how many verify in each verifier (all steps)."""
    results = verify_jobs([b for _, b in bundles])
    out: dict[str, Any] = {}
    for mode in MODES:
        mine = [res for (m, _), res in zip(bundles, results, strict=True) if m == mode]
        py, br = sum(r["python"] for r in mine), sum(r["browser"] for r in mine)
        both = sum(r["python"] and r["browser"] for r in mine)
        out[mode] = {
            "captures": captures.get(mode, 0), "bundles": len(mine), "python_pass": py,
            "browser_pass": br, "both_pass": both,
            "captures_without_bundle": captures.get(mode, 0) - len(mine),
            "rate_of_captures_verified_by_both": (
                round(both / captures[mode], 4) if captures.get(mode) else None
            ),
        }  # fmt: skip
    return out


def _replay() -> dict[str, Any]:
    """The one capture with a bundle: the recorded sandbox purchase of the P3 gate, replayed end to end.

    Its two tests run the Python CLI and the browser verifier (Node) over the stored bundle with the
    service keys pinned, twelve steps each (tests/integration/test_p3_gate.py).
    """
    import subprocess

    out: dict[str, Any] = {"capture": "49029167TJ689282S"}
    for name, key in (("python", "python_cli"), ("browser", "browser_verifier")):
        done = subprocess.run(
            [sys.executable, "-m", "pytest", "tests/integration/test_p3_gate.py", "-q", "-p",
             "no:cacheprovider", "--no-header", "-o", "addopts=", "-k", f"verifies_in_the_{key}"],
            cwd=Path(__file__).resolve().parents[1], capture_output=True, text=True, check=False,
        )  # fmt: skip
        out[name] = done.returncode == 0 and "1 passed" in done.stdout
    return out


def _targets(res: dict[str, Any]) -> list[dict[str, str]]:
    full, base = res["attacks"]["full"], res["attacks"]["baseline"]
    tasks, ev = res["tasks"]["full"], res["evidence"]["full"]
    rp = res["evidence"]["replay"]
    zero_full = (
        full["unauthorized_captures"]
        + res["adversary"]["full"]["unauthorized_captures"]
        + tasks["unauthorized_captures"]
    )
    dupes = (
        full["duplicate_paypal_objects"]
        + res["adversary"]["full"]["duplicate_paypal_objects"]
        + tasks["duplicate_paypal_objects"]
    )
    fraction = ev["rate_of_captures_verified_by_both"]
    rows = [
        (
            "Unauthorized captures: 0 (full)",
            zero_full == 0,
            f"{zero_full} across attacks, adversary goals and tasks; baseline attacks: "
            f"{base['unauthorized_captures']}",
        ),
        (
            "Attack success rate: 0% on deterministic cases (full)",
            full["attacks_succeeded"] == 0,
            f"{full['attacks_succeeded']} of {full['cases']} (baseline {base['attacks_succeeded']} of "
            f"{base['cases']})",
        ),
        ("Duplicate PayPal objects: 0", dupes == 0, f"{dupes} in full"),
        (
            "Evidence bundles verifying: 100% of captures",
            fraction == 1.0,
            f"{ev['both_pass']} of {ev['captures']} full-mode captures have a bundle that passes all "
            f"steps in both verifiers; {ev['captures_without_bundle']} captures have no bundle "
            "(bundles are assembled only for an open-then-closed chain backed by a device consent; the test issuer signs no consent and the human-present flow has no open mandate)",
        ),
        (
            "The recorded sandbox capture's bundle verifies in both verifiers",
            bool(rp["python"] and rp["browser"]),
            f"capture {rp['capture']}, replayed through the P3 gate test: Python CLI "
            f"{'pass' if rp['python'] else 'FAIL'}, browser verifier "
            f"{'pass' if rp['browser'] else 'FAIL'}, twelve steps each, keys pinned",
        ),
        (
            "Legitimate task completion: at least 90%",
            tasks["completion_rate"] >= 0.9,
            f"{tasks['completion_rate']:.1%} ({tasks['completed']} of {tasks['runs']} runs)",
        ),
        (
            "False block rate: reported",
            True,
            f"{tasks['false_block_rate']:.1%} ({tasks['false_blocks']} of {tasks['runs']})",
        ),
        (
            "Gate added latency p50 and p95: reported",
            True,
            f"+{res['gate_latency']['added_p50_ms']} ms p50, +{res['gate_latency']['added_p95_ms']} ms p95, "
            "over the simulator",
        ),
        ("Attack suite: at least 40 cases", full["cases"] >= 40, f"{full['cases']} cases"),
        (
            "Agent task suite: at least 25 legitimate purchases",
            tasks["runs"] // len(res["seeds"]) >= 25,
            f"{tasks['runs'] // len(res['seeds'])} tasks per seed through the issuer, not the model-driven shopper",
        ),
        (
            "Concurrency and properties green",
            res["pytest"]["all_green"],
            f"properties {res['pytest']['properties']}, concurrency {res['pytest']['concurrency']}",
        ),
        (
            "Adversary LLM runs: 20 goals x 3 seeds, ASR with a 95% CI",
            False,
            f"missed: {res['adversary']['full']['cases']} scripted goals per seed, no model-planned "
            "adversary (L65), so no ASR or CI is reported",
        ),
        (
            "Spec conformance as a runner suite",
            False,
            "missed: the conformance tests run in make test, not as an eval suite",
        ),
        ("Baseline vs full and per-ablation charts", True, "charts/ in the run directory"),
    ]
    return [{"target": t, "status": "met" if ok else "missed", "evidence": e} for t, ok, e in rows]


def _markdown(res: dict[str, Any]) -> str:
    a, t, ev, g = res["attacks"], res["tasks"], res["evidence"], res["gate_latency"]
    L = [
        f"# Evaluation report {res['run_id']}",
        "",
        f"Generated {res['generated_at']}. Seeds {', '.join(map(str, res['seeds']))}. Ground truth: "
        f"PayPal state as held by {SIMULATOR}, the hash-chained decision log, and the two evidence "
        "verifiers. No model output or response body is an input to any verdict.",
        "",
        "Per-run data: `report.json` in this directory. Charts: `charts/`.",
        "",
        "## Totals per mode",
        "",
        "Attack suite, one seed (the suites below are repeated for every seed and the results are "
        f"identical across seeds: **{res['seed_invariant']}**).",
        "",
        "| mode | cases | attacks succeeded | unauthorized captures | duplicate PayPal objects | mismatches | errors |",
        "| --- | --- | --- | --- | --- | --- | --- |",
    ]
    for mode in MODES:
        m = a[mode]
        L.append(f"| {mode} | {m['cases']} | {m['attacks_succeeded']} | {m['unauthorized_captures']} | "
                 f"{m['duplicate_paypal_objects']} | {m['mismatches']} | {m['errors']} |")  # fmt: skip
    L += ["", "Scripted adversary goals, one seed.", "",
          "| mode | goals | succeeded | unauthorized captures | duplicate PayPal objects |",
          "| --- | --- | --- | --- | --- |"]  # fmt: skip
    for mode in MODES:
        m = res["adversary"][mode]
        L.append(f"| {mode} | {m['cases']} | {m['attacks_succeeded']} | {m['unauthorized_captures']} | "
                 f"{m['duplicate_paypal_objects']} |")  # fmt: skip
    L += ["", "## Per category", "",
          "| category | cases | full: succeeded | baseline: succeeded | baseline: unauthorized captures |",
          "| --- | --- | --- | --- | --- |"]  # fmt: skip
    for c in res["categories"]:
        L.append(f"| {c['category']} | {c['cases']} | {c['full_succeeded']} | {c['baseline_succeeded']} | "
                 f"{c['baseline_unauthorized_captures']} |")  # fmt: skip
    L += ["", f"Cases that succeed in baseline ({len(res['baseline_gap'])}): "
          + ", ".join(f"`{c}`" for c in res["baseline_gap"]) + ".", "",
          "## Per ablation", "",
          "Each ablation turns one protection off in `full` mode and runs all "
          f"{a['full']['cases']} attack cases. \"Reopens\" means the attack succeeded (money captured "
          "outside what was signed or allowed).", "",
          "| ablation | reopens | unauthorized captures | duplicate PayPal objects | still blocked, by a different reason | note |",
          "| --- | --- | --- | --- | --- | --- |"]  # fmt: skip
    for ab in res["ablations"]:
        reopened = ", ".join(f"`{c}`" for c in ab["reopened"]) or "nothing"
        other = ", ".join(f"`{c}`" for c in ab["blocked_by_another_defense"]) or "none"
        L.append(f"| `{ab['flag']}` | {reopened} | {ab['unauthorized_captures']} | "
                 f"{ab['duplicate_paypal_objects']} | {other} | {ab['note']} |")  # fmt: skip
    L += ["", "## Legitimate tasks", "",
          f"{t['full']['runs'] // len(res['seeds'])} tasks per seed, {len(res['seeds'])} seeds, pooled.", "",
          "| mode | runs | completed | completion rate | false blocks | false block rate | unauthorized captures |",
          "| --- | --- | --- | --- | --- | --- | --- |"]  # fmt: skip
    for mode in MODES:
        m = t[mode]
        L.append(f"| {mode} | {m['runs']} | {m['completed']} | {m['completion_rate']:.1%} | "
                 f"{m['false_blocks']} | {m['false_block_rate']:.1%} | {m['unauthorized_captures']} |")  # fmt: skip
    L += ["", "## Gate latency", "",
          f"Measured over {SIMULATOR}: the time spent in the capture stage per call (the gate in full, "
          "immediate capture in baseline). It excludes the HTTP layer and the Credential Provider. It is "
          "simulator latency: real PayPal round trips are slower and are not in these numbers.", "",
          "| mode | calls | p50 ms | p95 ms | end-to-end task p50 ms | end-to-end p95 ms |",
          "| --- | --- | --- | --- | --- | --- |"]  # fmt: skip
    for mode in MODES:
        s, e = t[mode]["capture_stage"], t[mode]["end_to_end"]
        L.append(
            f"| {mode} | {s['n']} | {s['p50_ms']} | {s['p95_ms']} | {e['p50_ms']} | {e['p95_ms']} |"
        )
    L += ["", f"Added by the gate: +{g['added_p50_ms']} ms at p50, +{g['added_p95_ms']} ms at p95 "
          "(full minus baseline).", "",
          "## Evidence bundles", "",
          "Every stored bundle, with the merchant and platform keys pinned, run through the Python CLI "
          "and the browser verifier (Node), twelve steps each. Bundles from seed "
          f"{res['seeds'][0]} (attack and task suites).", "",
          "| mode | captures | bundles | Python verifier passes | browser verifier passes | both pass | captures without a bundle |",
          "| --- | --- | --- | --- | --- | --- | --- |"]  # fmt: skip
    for mode in MODES:
        m = ev[mode]
        L.append(f"| {mode} | {m['captures']} | {m['bundles']} | {m['python_pass']} | {m['browser_pass']} | "
                 f"{m['both_pass']} | {m['captures_without_bundle']} |")  # fmt: skip
    rp = ev["replay"]
    L += [
        "",
        f"Recorded sandbox capture {rp['capture']} (the P3 gate replay, the only capture with a bundle): "
        f"Python CLI {'pass' if rp['python'] else 'FAIL'}, browser verifier {'pass' if rp['browser'] else 'FAIL'}.",
    ]
    p = res["pytest"]
    L += [
        "",
        "## Properties and concurrency",
        "",
        "| seed | properties passed | failed | concurrency passed | failed |",
        "| --- | --- | --- | --- | --- |",
    ]
    for seed in res["seeds"]:
        pr, co = p["by_seed"][str(seed)]["properties"], p["by_seed"][str(seed)]["concurrency"]
        L.append(f"| {seed} | {pr['passed']} | {pr['failed'] + pr['errors']} | {co['passed']} | "
                 f"{co['failed'] + co['errors']} |")  # fmt: skip
    L += ["", "## Targets", "", "| target | status | evidence |", "| --- | --- | --- |"]
    L += [f"| {x['target']} | {x['status']} | {x['evidence']} |" for x in res["targets"]]
    L += ["", "## What these numbers do not show", ""]
    L += [f"- {x}" for x in res["caveats"]]
    return "\n".join(L) + "\n"


def _caveats(res: dict[str, Any]) -> list[str]:
    n = len(res["baseline_gap"])
    return [
        f"The adversary is scripted: {res['adversary']['full']['cases']} fixed goals per seed, each "
        "re-performing one attack case. No model plans an attack, so there is no attack success rate "
        "with a confidence interval, and no claim about an adaptive attacker (L65).",
        f"The baseline gap is {n} of {res['attacks']['baseline']['cases']} cases. The other cases are "
        "blocked in baseline too (defense in depth in the careful baseline), so the cases widen "
        "coverage without widening the gap between the modes (L67).",
        "Latency is simulator latency. The PayPal simulator answers in memory, so the gate's added time "
        "is its own computation and database work, not PayPal round trips.",
        "The legitimate tasks run through the test issuer and the PayPal simulator, not the "
        "model-driven shopper or live PayPal. The completion rate is for those fixed purchases.",
        "Seeds change only the Hypothesis examples. The attack, adversary and task suites have no "
        "randomness, so three seeds are three repetitions, not three samples of a distribution.",
        "Ground truth is simulator state. The simulator is our model of PayPal; agreement with live "
        "PayPal is established by the recorded cassettes and the sandbox smoke script, not by this report.",
        "Nothing here is a claim about PayPal buyer or seller protection or dispute outcomes. The "
        "evidence bundles are verified for internal consistency and signatures, not for how any "
        "dispute would be decided.",
        "Passing counts are counts of passing tests under a seed, not of Hypothesis examples.",
    ]


def _charts(res: dict[str, Any], out: Path) -> None:
    out.mkdir(parents=True, exist_ok=True)
    series = [("baseline", charts.BASELINE), ("full", charts.FULL)]
    (out / "attacks_by_category.svg").write_text(
        charts.grouped_bars(
            "Attacks that succeeded, by category",
            [
                (c["category"], [c["baseline_succeeded"], c["full_succeeded"]])
                for c in res["categories"]
            ],
            series,
        )
    )
    (out / "ablations.svg").write_text(
        charts.grouped_bars(
            "Attack cases reopened by switching one protection off",
            [(a["flag"], [a["reopened_count"]]) for a in res["ablations"]],
            [("reopened", charts.WARN)],
        )
    )
    g = res["gate_latency"]
    (out / "gate_latency.svg").write_text(
        charts.single_bars(
            "Capture stage time over the simulator (ms)",
            [
                ("baseline p50", g["baseline"]["p50_ms"]),
                ("full p50", g["full"]["p50_ms"]),
                ("baseline p95", g["baseline"]["p95_ms"]),
                ("full p95", g["full"]["p95_ms"]),
            ],
            unit=" ms",
        )
    )
    e = res["evidence"]["full"]
    (out / "evidence.svg").write_text(
        charts.grouped_bars(
            "Full-mode captures and bundles that pass all steps",
            [
                ("captures", [e["captures"]]),
                ("Python verifier", [e["python_pass"]]),
                ("browser verifier", [e["browser_pass"]]),
                ("both", [e["both_pass"]]),
            ],
            [("count", charts.FULL)],
        )
    )


def run_release(seeds: list[int], *, write: bool = True) -> int:
    structlog.configure(wrapper_class=structlog.make_filtering_bound_logger(logging.ERROR))
    run_id = datetime.now(UTC).strftime("%Y%m%dT%H%M%SZ")
    registry = {c.id: c for c in load_cases()}
    per_seed: dict[int, dict[str, Any]] = {}
    bundles: list[tuple[str, BundleJob]] = []
    task_pool: list[dict[str, Any]] = []
    failures: list[str] = []
    for seed in seeds:
        print(f"seed {seed}: attacks", flush=True)
        collect = bundles if seed == seeds[0] else None
        attacks = run_suite(MODES, bundles=collect)
        print(f"seed {seed}: adversary", flush=True)
        adversary = run_adversary(MODES)
        print(f"seed {seed}: tasks", flush=True)
        tasks = task_rows(MODES, bundles=collect)
        print(f"seed {seed}: properties and concurrency", flush=True)
        py = {s: run_pytest_suite(s, seed)[0] for s in ("properties", "concurrency")}
        per_seed[seed] = {"attacks": attacks, "adversary": adversary, "tasks": tasks, "pytest": py}
        task_pool += tasks
        failures += [f"attack {r['case']} [{r['mode']}] (seed {seed})"
                     for r in attacks + adversary if r["matches_expectation"] is False or r["error"]]  # fmt: skip
        failures += [
            f"task {r['task']} [{r['mode']}] (seed {seed})" for r in tasks if not r["completed"]
        ]
        failures += [
            f"{k} (seed {seed})"
            for k, v in py.items()
            if v["failed"] or v["errors"] or v["exit_status"]
        ]
    print("ablations", flush=True)
    configs = list(FLAGS)
    by_flag: dict[str, list[dict[str, Any]]] = {}
    with scratch_databases() as dbs:
        for flag in configs:
            by_flag[flag] = [row(c, flag, run_case(c, flag, dbs)) for c in registry.values()]
        # Not an architecture ablation: both layers that stop an order changed after approval off at once.
        both = RuntimeSettings(Mode.FULL, "dev", Ablations(no_gate=True, no_preauth_check=True))
        by_flag[COMBINED] = [row(c, COMBINED, run_case(c, both, dbs)) for c in registry.values()]
    first = per_seed[seeds[0]]
    sig = {
        s: _signature(d["attacks"] + d["adversary"], CATEGORY_SIGNATURE)
        for s, d in per_seed.items()
    }
    invariant = all(v == sig[seeds[0]] for v in sig.values())
    print("evidence verification", flush=True)
    captures = {
        m: sum(r["paypal_captures"] for r in first["attacks"] if r["mode"] == m)
        + sum(1 for r in first["tasks"] if r["mode"] == m and r["captured_minor"] > 0)
        for m in MODES
    }
    ev = _evidence(bundles, captures)
    ev["replay"] = _replay()
    tasks_s = _task_summary(task_pool)
    cs = {m: tasks_s[m]["capture_stage"] for m in MODES}
    gate = {
        "over": SIMULATOR, "full": cs["full"], "baseline": cs["baseline"],
        "added_p50_ms": round(cs["full"]["p50_ms"] - cs["baseline"]["p50_ms"], 1),
        "added_p95_ms": round(cs["full"]["p95_ms"] - cs["baseline"]["p95_ms"], 1),
    }  # fmt: skip
    gap = sorted(
        {
            r["case"]
            for r in first["attacks"]
            if r["mode"] == "baseline" and r["outcome"] == "success"
        }
    )
    pytest_by_seed = {str(s): d["pytest"] for s, d in per_seed.items()}
    ablations = _ablations([r for r in first["attacks"] if r["mode"] == "full"], by_flag)
    for ab in ablations:
        ab["note"] = _note(ab)
    res: dict[str, Any] = {
        "run_id": run_id, "generated_at": datetime.now(UTC).strftime("%Y-%m-%dT%H:%M:%SZ"),
        "seeds": seeds, "seed_invariant": invariant, "simulator": SIMULATOR,
        "attacks": _totals(first["attacks"]), "adversary": _totals(first["adversary"]),
        "categories": _categories(first["attacks"]), "baseline_gap": gap,
        "ablations": ablations, "tasks": tasks_s, "gate_latency": gate, "evidence": ev,
        "pytest": {
            "by_seed": pytest_by_seed,
            "properties": [pytest_by_seed[str(s)]["properties"]["passed"] for s in seeds],
            "concurrency": [pytest_by_seed[str(s)]["concurrency"]["passed"] for s in seeds],
            "all_green": all(
                not (v["failed"] or v["errors"] or v["exit_status"])
                for d in per_seed.values() for v in d["pytest"].values()
            ),
        },
    }  # fmt: skip
    res["targets"] = _targets(res)
    res["caveats"] = _caveats(res)
    failures += [f"ablation {a['flag']}: {a['errors']} errors" for a in ablations if a["errors"]]
    res["failures"] = failures
    if write:
        target = REPORTS / run_id
        target.mkdir(parents=True, exist_ok=True)
        report = {
            "suite": "release",
            "results": res,
            "rows": {
                str(s): {k: v for k, v in d.items() if k != "pytest"} for s, d in per_seed.items()
            },
            "ablation_rows": by_flag,
        }
        (target / "report.json").write_text(json.dumps(report, indent=1, sort_keys=True) + "\n")
        (target / "report.md").write_text(_markdown(res))
        _charts(res, target / "charts")
        _update_latest(target, res, first)
        print(f"report: {target}")
    for t in res["targets"]:
        print(f"{t['status']:6} {t['target']}: {t['evidence']}")
    for f in failures:
        print(f"FAILED {f}", file=sys.stderr)
    return 1 if failures else 0


def _note(ab: dict[str, Any]) -> str:
    if ab["flag"] == COMBINED:
        what = "reopens the listed attacks" if ab["reopened"] else "reopens nothing"
        return f"Both layers off at once (not an architecture ablation): {what}."
    if ab["reopened"]:
        return "Reopens the listed attacks."
    n = len(ab["blocked_by_another_defense"])
    head = "Reopens nothing"
    if n:
        head += f": {n} case(s) change reason code ({', '.join(ab['other_reason_codes'])}) but stay blocked"
    else:
        head += " and changes no case's outcome or reason code in this suite"
    return f"{head}. {WHY.get(ab['flag'], '')}".strip()


def _update_latest(target: Path, res: dict[str, Any], first: dict[str, Any]) -> None:
    """Point `latest.json` at this run: the attack and suite sections of seed 0 plus `results`."""
    stamp = res["generated_at"]
    attacks = build_section(first["attacks"])
    sections = {
        "adversary": build_section(first["adversary"]),
        "tasks": build_section(first["tasks"]),
        **{k: build_section([v]) for k, v in first["pytest"].items()},
    }
    out = {
        "suite": "attacks",
        "report": f"{target.name}/report.json",
        "generated_at": stamp,
        "summary": attacks["summary"],
        "cases": first["attacks"],
        "sections": sections,
        "results": res,
    }
    (REPORTS / "latest.json").write_text(json.dumps(out, indent=1, sort_keys=True) + "\n")


def rerender(run_dir: Path) -> None:
    """Rebuild the notes, markdown and `latest.json` results of a finished run from its `report.json`."""
    report = json.loads((run_dir / "report.json").read_text())
    res = report["results"]
    for ab in res["ablations"]:
        ab["note"] = _note(ab)
    res["targets"] = _targets(res)
    res["caveats"] = _caveats(res)
    (run_dir / "report.json").write_text(json.dumps(report, indent=1, sort_keys=True) + "\n")
    (run_dir / "report.md").write_text(_markdown(res))
    latest = json.loads((REPORTS / "latest.json").read_text())
    if latest.get("report") == f"{run_dir.name}/report.json":
        latest["results"] = res
        (REPORTS / "latest.json").write_text(json.dumps(latest, indent=1, sort_keys=True) + "\n")
