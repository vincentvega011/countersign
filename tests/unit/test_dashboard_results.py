"""`read.eval_results`: the Results view's data is re-typed, bounded and never fails the endpoint."""

from __future__ import annotations

import json
from pathlib import Path

from countersign.dashboard import read

GOOD = {
    "results": {
        "run_id": "r1", "generated_at": "t", "seeds": [0, 1], "seed_invariant": True,
        "attacks": {"full": {"cases": 40, "attacks_succeeded": 0, "unauthorized_captures": 0,
                             "duplicate_paypal_objects": 0}},
        "gate_latency": {"added_p50_ms": 18.3, "added_p95_ms": 22.3},
        "targets": [{"target": "t", "status": "bogus", "evidence": "e" * 900}],
        "ablations": [{"flag": "ABL_X", "reopened": ["a", "b"], "reopened_count": 2}],
    }
}  # fmt: skip


def _write(tmp_path: Path, text: str) -> Path:
    path = tmp_path / "latest.json"
    path.write_text(text)
    return path


def test_a_report_without_results_gives_none(tmp_path: Path) -> None:
    assert read.eval_results(_write(tmp_path, json.dumps({"summary": {}}))) is None
    assert read.eval_results(_write(tmp_path, "not json")) is None
    assert read.eval_results(tmp_path / "missing.json") is None


def test_values_are_retyped_and_bounded(tmp_path: Path) -> None:
    out = read.eval_results(_write(tmp_path, json.dumps(GOOD)))
    assert out is not None
    assert out["attacks"]["full"]["cases"] == 40
    assert out["attacks"]["baseline"]["cases"] == 0  # absent reads as 0, never blank
    assert out["targets"][0]["status"] == "missed"  # anything but "met" is missed
    assert len(out["targets"][0]["evidence"]) == 500
    assert out["ablations"][0]["reopened"] == "a, b"
    assert out["gate_added_p50_ms"] == 18.3


def test_a_non_finite_number_reads_as_zero_so_the_endpoint_cannot_fail(tmp_path: Path) -> None:
    text = json.dumps(GOOD).replace("18.3", "Infinity")
    out = read.eval_results(_write(tmp_path, text))
    assert out is not None and out["gate_added_p50_ms"] == 0.0
    json.dumps(out, allow_nan=False)  # what the JSON response does
