"""The Python CLI and the browser verifier agree on every evidence vector (P3.8).

Both run over the valid bundle (pinned and unpinned), every tampered and strict vector, and a fixed set of
mutated bundles (each leaf of the valid bundle replaced by values of other types, members removed, and
the decision log payloads changed). The browser verifier runs in Node from the same ES modules the
`/verify/` page loads. The test fails if any step name, step outcome, failure code or first failing step
differs. Messages may differ.
"""

from __future__ import annotations

import copy
import json
import random
import shutil
import subprocess
from pathlib import Path
from typing import Any

import pytest

from countersign_verify import verify_text
from countersign_verify.crypto import loads
from tests.evidence_tamper import TAMPERS

ROOT = Path(__file__).resolve().parents[2]
VECTORS = ROOT / "tests" / "vectors" / "evidence"
INDEX = json.loads((VECTORS / "index.json").read_text())
PIN = {k: str(VECTORS / f"{k}.key.json") for k in ("merchant", "platform")}
PINNED = {k: loads(Path(p).read_bytes()) for k, p in PIN.items()}
VARIANTS = ["null", "true", "1", "1.0", "-1", '"x"', "[]", "{}", "0"]
FUZZ_CASES = 400
SEED = 20261105


def node_results(jobs: list[dict[str, Any]], tmp: Path) -> list[list[dict[str, Any]]]:
    node = shutil.which("node")
    assert node, "node is required for the cross-implementation test"
    spec = tmp / "jobs.json"
    spec.write_text(json.dumps(jobs))
    done = subprocess.run(
        [node, "test/verify-runner.mjs", str(spec)], cwd=ROOT / "web" / "ui",
        capture_output=True, text=True, check=False, timeout=600,
    )  # fmt: skip
    assert done.returncode == 0, done.stderr[-3000:]
    out: list[list[dict[str, Any]]] = json.loads(done.stdout)
    return out


def shape(results: list[Any]) -> list[tuple[str, bool, str | None]]:
    return [
        (r["name"], r["ok"], r["code"]) if isinstance(r, dict) else (r.name, r.ok, r.code)
        for r in results
    ]


def _leaves(node: Any, path: tuple[Any, ...] = ()) -> list[tuple[Any, ...]]:
    if isinstance(node, dict):
        return [path] + [p for k, v in node.items() for p in _leaves(v, (*path, k))]
    if isinstance(node, list):
        return [path] + [p for i, v in enumerate(node) for p in _leaves(v, (*path, i))]
    return [path]


def mutations(valid: dict[str, Any]) -> list[str]:
    """Deterministic mutated bundle texts: a value replaced by raw JSON of another type, a member
    removed, or a log payload replaced by JSON with another shape (log payloads are not signed)."""
    rng = random.Random(SEED)
    paths = [p for p in _leaves(valid) if p]
    out = []
    mark = "__MUTATION__"
    for _ in range(FUZZ_CASES):
        b = copy.deepcopy(valid)
        path = rng.choice(paths)
        parent: Any = b
        for key in path[:-1]:
            parent = parent[key]
        roll = rng.random()
        if roll < 0.15 and isinstance(parent, dict):
            del parent[path[-1]]
            out.append(json.dumps(b))
            continue
        if roll < 0.3:
            entry = rng.choice(b["log"]["entries"])
            payload = json.loads(entry["payload"])
            if isinstance(payload, dict) and payload:
                payload[rng.choice(sorted(payload))] = json.loads(rng.choice(VARIANTS[:3] + ["[]"]))
            entry["payload"] = json.dumps(payload, separators=(",", ":"))
            out.append(json.dumps(b))
            continue
        parent[path[-1]] = mark
        out.append(json.dumps(b).replace(f'"{mark}"', rng.choice(VARIANTS)))
    return out


@pytest.fixture(scope="module")
def fuzz(tmp_path_factory: pytest.TempPathFactory) -> list[Path]:
    tmp = tmp_path_factory.mktemp("fuzz")
    texts = mutations(json.loads((VECTORS / "valid.json").read_text()))
    paths = []
    for i, text in enumerate(texts):
        path = tmp / f"m{i:04d}.json"
        path.write_text(text)
        paths.append(path)
    return paths


def test_both_verifiers_agree_on_every_vector(tmp_path: Path) -> None:
    files = ["valid.json"] + [e["file"] for e in INDEX["tampered"] + INDEX["strict"]]
    jobs = [{"path": str(VECTORS / f), "pinned": PIN} for f in files]
    for entry in INDEX["forged"]:  # pinned with the bundle's own throwaway keys
        keys = json.loads((VECTORS / entry["file"]).read_text())["keys"]
        for name in ("merchant", "platform"):
            (tmp_path / f"{Path(entry['file']).stem}.{name}.json").write_text(
                json.dumps(keys[name])
            )
        jobs.append({"path": str(VECTORS / entry["file"]), "pinned": {
            n: str(tmp_path / f"{Path(entry['file']).stem}.{n}.json") for n in ("merchant", "platform")
        }})  # fmt: skip
    jobs.append({"path": str(VECTORS / "valid.json"), "pinned": None})
    jobs.append({"path": str(VECTORS / "valid.json"), "pinned": {"merchant": PIN["merchant"]}})
    browser = node_results(jobs, tmp_path)
    entries = INDEX["tampered"] + INDEX["strict"] + INDEX["forged"]
    expected = {e["file"]: (e["first_failure"], e["code"]) for e in entries}
    expected["valid.json"] = (None, None)
    assert len(files) == 1 + len(TAMPERS) + len(INDEX["strict"]) and len(INDEX["forged"]) >= 30
    for job, js in zip(jobs, browser, strict=True):
        pinned = None
        if job["pinned"]:
            pinned = {k: loads(Path(p).read_bytes()) for k, p in job["pinned"].items()}
        py = verify_text(Path(job["path"]).read_bytes(), pinned)
        assert shape(js) == shape(py), job
        name = str(Path(job["path"]).relative_to(VECTORS))
        if job["pinned"] and set(job["pinned"]) == {"merchant", "platform"}:
            first = next(((r.name, r.code) for r in py if not r.ok), (None, None))
            assert first == expected[name], name


def test_both_verifiers_agree_on_mutated_bundles(fuzz: list[Path], tmp_path: Path) -> None:
    browser = node_results([{"path": str(p), "pinned": PIN} for p in fuzz], tmp_path)
    differ = []
    for path, js in zip(fuzz, browser, strict=True):
        py = verify_text(path.read_bytes(), PINNED)
        if shape(js) != shape(py):
            differ.append((path.name, shape(py), shape(js)))
    assert not differ, differ[:3]
    failing = sum(1 for js in browser if not all(r["ok"] for r in js))
    assert failing > FUZZ_CASES * 0.8  # the mutations reach the checks, not only harmless members


def test_the_browser_verifier_unit_tests_pass() -> None:
    """`web/ui/test/evidence.test.mjs` under Node, so CI runs it with the Python suite."""
    node = shutil.which("node")
    assert node, "node is required"
    done = subprocess.run(
        [node, "--test", "test/evidence.test.mjs"], cwd=ROOT / "web" / "ui",
        capture_output=True, text=True, check=False, timeout=300,
    )  # fmt: skip
    assert done.returncode == 0, done.stdout[-20000:] + done.stderr[-3000:]
    assert "# fail 0" in done.stdout
