"""The scripted adversary and the dashboard's attack-run launcher (Decisions 130 to 132).

Real Postgres, whole apps built by the composition root over the PayPal simulator. The verdict of every
run comes from the judge (PayPal state and the decision log); the adversary's own reading of a response
is only logged.
"""

from __future__ import annotations

import json
from collections.abc import Iterator
from pathlib import Path
from typing import Any

import pytest
from sqlalchemy import Engine

from agents.adversary.scripts import SCRIPTS
from countersign.dashboard.service import ATTACK_RUN_ENVS
from countersign.main import install_attack_runs
from countersign.runtime import Mode, RuntimeSettings
from eval.adversary.runner import run_goal
from eval.harness import Databases
from eval.launch import AttackLauncher, Busy, Unavailable
from eval.run import load_cases
from tests.mode_support import World, make_world, reset

API = "/dashboard/api/v1/attack-runs"
HEADERS = {"X-Countersign-Dashboard": "1"}
BY_ID = {c.id: c for c in load_cases()}


@pytest.fixture
def dbs(admin_engine: Engine, app_engine: Engine) -> Databases:
    return Databases(admin_engine, app_engine)


# ---------------------------------------------------------------- scripted mode


def test_a_known_pair_succeeds_against_baseline_and_is_blocked_by_full(
    dbs: Databases, tmp_path: Path
) -> None:
    base = run_goal("protocol_downgrade_acp", "baseline", dbs, tmp_path / "b.jsonl")
    full = run_goal("protocol_downgrade_acp", "full", dbs, tmp_path / "f.jsonl")
    assert base.run.verdict.outcome == "success" and base.run.verdict.unauthorized_captures >= 1
    assert full.run.verdict.outcome == "blocked" and full.run.verdict.unauthorized_captures == 0
    assert full.run.verdict.captures == 0 and full.run.reason == "mandate_required"


def test_every_scripted_goal_matches_the_registry_expectation_in_both_modes(dbs: Databases) -> None:
    assert len(SCRIPTS) >= 10 and set(SCRIPTS) <= set(BY_ID)
    wrong = []
    for goal in sorted(SCRIPTS):
        for mode in ("full", "baseline"):
            done = run_goal(goal, mode, dbs)
            expected = BY_ID[goal].expected[mode].outcome
            if done.run.error or done.run.verdict.outcome != expected:
                wrong.append((goal, mode, done.run.verdict.outcome, expected, done.run.error))
    assert wrong == []


def test_every_attempt_is_logged_without_a_secret(dbs: Databases, tmp_path: Path) -> None:
    path = tmp_path / "attempts.jsonl"
    done = run_goal("double_spend_across_protocols", "full", dbs, path)
    lines = path.read_text().splitlines()
    assert done.attempts == len(lines) >= 5
    entries = [json.loads(line) for line in lines]
    assert [e["n"] for e in entries] == list(range(1, len(entries) + 1))
    for e in entries:
        assert {"ts", "attack", "target_mode", "step", "method", "path", "status", "observed",
                "code", "request", "header_names"} <= set(e)  # fmt: skip
        assert e["attack"] == "double_spend_across_protocols" and e["target_mode"] == "full"
    text = path.read_text()
    assert "~" not in text and "eyJ" not in text  # no mandate or JWT, whole or in part
    assert any("countersign-delegation" in e["header_names"] for e in entries)  # names only
    assert not any(isinstance(v, str) and len(v) > 120 for e in entries for v in e.values())


# ---------------------------------------------------------------- the launch endpoint


class FakeLauncher:
    def __init__(self, outcome: Any = None) -> None:
        self.calls: list[str] = []
        self.outcome = outcome

    def launchable(self) -> list[dict[str, str]]:
        return [{"id": "protocol_downgrade_acp", "category": "c", "description": "d"}]

    def run(self, attack_id: str) -> dict[str, Any]:
        self.calls.append(attack_id)
        if isinstance(self.outcome, Exception):
            raise self.outcome
        return {"version": 1, "run_id": "r1", "attack": attack_id, "results": {}}

    def recent(self) -> list[dict[str, Any]]:
        return []


def _world(engine: Engine, admin: Engine, env: str, launcher: Any) -> World:
    reset(admin)
    w = make_world(engine, RuntimeSettings(Mode.FULL, env))
    w.client.app.state.dashboard.attack_launcher = launcher  # type: ignore[attr-defined]
    return w


@pytest.fixture
def launched(app_engine: Engine, admin_engine: Engine) -> Iterator[tuple[World, FakeLauncher]]:
    fake = FakeLauncher()
    w = _world(app_engine, admin_engine, "dev", fake)
    with w.client:
        yield w, fake


def post(world: World, body: Any, headers: dict[str, str] | None = HEADERS) -> Any:
    return world.client.post(API, content=json.dumps(body).encode(), headers=headers or {})


def test_runs_are_refused_outside_dev_eval_and_demo(
    app_engine: Engine, admin_engine: Engine
) -> None:
    assert ATTACK_RUN_ENVS == ("dev", "eval", "demo")
    for env in ("prod", "production", "staging", ""):
        fake = FakeLauncher()
        w = _world(app_engine, admin_engine, env, fake)
        with w.client:
            r = post(w, {"attack": "protocol_downgrade_acp"})
            assert r.status_code == 403 and r.json() == {"code": "attack_runs_disabled"}
            assert fake.calls == []
            assert w.client.get(API).json()["enabled"] is False


def test_runs_are_refused_without_a_launcher(app_engine: Engine, admin_engine: Engine) -> None:
    w = _world(app_engine, admin_engine, "dev", None)
    with w.client:
        r = post(w, {"attack": "protocol_downgrade_acp"})
        assert r.status_code == 403 and r.json()["code"] == "attack_runs_disabled"


@pytest.mark.parametrize("env", ["dev", "eval", "demo"])
def test_the_allowed_environments_can_run(
    app_engine: Engine, admin_engine: Engine, env: str
) -> None:
    fake = FakeLauncher()
    w = _world(app_engine, admin_engine, env, fake)
    with w.client:
        r = post(w, {"attack": "protocol_downgrade_acp"})
        assert r.status_code == 201 and fake.calls == ["protocol_downgrade_acp"]
        assert r.headers["cache-control"] == "no-store"


def test_the_request_is_strict(launched: tuple[World, FakeLauncher]) -> None:
    w, fake = launched
    assert post(w, {"attack": "protocol_downgrade_acp"}, headers={}).status_code == 403
    assert post(w, {"attack": "nope"}).status_code == 404
    assert post(w, {"attack": "../../etc/passwd"}).status_code == 404
    assert post(w, {"attack": "protocol_downgrade_acp", "extra": 1}).status_code == 404
    assert post(w, {"attack": 7}).status_code == 404
    assert post(w, ["protocol_downgrade_acp"]).status_code == 404
    assert w.client.post(API, content=b"{not json", headers=HEADERS).status_code == 404
    big = w.client.post(API, content=b'{"attack": "' + b"a" * 400 + b'"}', headers=HEADERS)
    assert big.status_code == 404
    dup = b'{"attack": "nope", "attack": "protocol_downgrade_acp"}'  # strict loader: duplicate keys (INV-8)
    assert w.client.post(API, content=dup, headers=HEADERS).status_code == 404
    nan = b'{"attack": "protocol_downgrade_acp", "x": NaN}'
    assert w.client.post(API, content=nan, headers=HEADERS).status_code == 404
    assert fake.calls == []


def test_busy_and_unavailable_map_to_fixed_codes(app_engine: Engine, admin_engine: Engine) -> None:
    for error, status, code in ((Busy(), 409, "attack_run_busy"),
                                (Unavailable("OperationalError"), 503, "attack_runs_unavailable")):  # fmt: skip
        w = _world(app_engine, admin_engine, "dev", FakeLauncher(error))
        with w.client:
            r = post(w, {"attack": "protocol_downgrade_acp"})
            assert r.status_code == status and r.json() == {"code": code}


def test_only_the_run_route_accepts_a_write_under_the_dashboard(
    launched: tuple[World, FakeLauncher],
) -> None:
    w, _ = launched
    for path in ("orders", "summary", "mandates", "events", "eval", "policy", "status"):
        for method in ("post", "put", "patch", "delete"):
            assert getattr(w.client, method)(f"/dashboard/api/v1/{path}").status_code == 405
    for method in ("put", "patch", "delete"):
        assert getattr(w.client, method)(API).status_code == 405


def test_install_follows_the_environment(
    app_engine: Engine, admin_engine: Engine, monkeypatch: pytest.MonkeyPatch
) -> None:
    def installed(env: str, extra: dict[str, str]) -> bool:
        reset(admin_engine)
        w = make_world(app_engine, RuntimeSettings(Mode.FULL, env))
        with w.client:
            install_attack_runs(w.client.app, RuntimeSettings(Mode.FULL, env), extra)  # type: ignore[arg-type]
            return w.client.app.state.dashboard.attack_launcher is not None  # type: ignore[attr-defined,no-any-return]

    assert installed("dev", {}) and installed("eval", {})
    assert not installed("dev", {"ATTACK_RUNS": "0"})
    assert not installed("demo", {})
    assert installed("demo", {"EVAL_DATABASE_ADMIN_URL": "postgresql://x"})
    assert not installed("prod", {"EVAL_DATABASE_ADMIN_URL": "postgresql://x"})


def test_a_real_run_shows_both_verdicts_and_keeps_only_run_records(
    app_engine: Engine, admin_engine: Engine, tmp_path: Path
) -> None:
    launcher = AttackLauncher(tmp_path)
    w = _world(app_engine, admin_engine, "dev", launcher)
    with w.client:
        before = w.client.get("/dashboard/api/v1/summary").json()
        r = post(w, {"attack": "protocol_downgrade_acp"})
        assert r.status_code == 201, r.text
        record = r.json()
        base, full = record["results"]["baseline"], record["results"]["full"]
        assert base["captured_outside_signed"] is True and base["unauthorized_captures"] >= 1
        assert full["captured_outside_signed"] is False and full["unauthorized_captures"] == 0
        assert base["matches_expectation"] and full["matches_expectation"]
        folder = tmp_path / record["run_id"]
        assert sorted(p.name for p in folder.iterdir()) == [
            "attempts-baseline.jsonl", "attempts-full.jsonl", "record.json",
        ]  # fmt: skip
        assert json.loads((folder / "record.json").read_text()) == record
        assert w.client.get(API).json()["recent"][0]["run_id"] == record["run_id"]
        after = w.client.get("/dashboard/api/v1/summary").json()
        assert after == before  # merchant data is untouched
    assert "~" not in json.dumps(record) and "eyJ" not in json.dumps(record)
