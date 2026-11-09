"""P5a: demo-mode refusals, the rate limit and the self-check (Decisions 136 to 140)."""

from __future__ import annotations

import pytest
from fastapi import FastAPI
from fastapi.testclient import TestClient

from countersign import selfcheck
from countersign.ablations import NAMES
from countersign.api import ratelimit
from countersign.main import create
from countersign.runtime import DEV_ONLY_SWITCHES, Mode, ModeRefused, RuntimeSettings

# ------------------------------------------------------------------------------- environment names


@pytest.mark.parametrize("env", ["", "production", "Demo", "staging", "demo "])
def test_an_unknown_environment_name_does_not_start(env: str) -> None:
    with pytest.raises(ModeRefused, match="APP_ENV"):
        RuntimeSettings.from_env({"APP_ENV": env})


@pytest.mark.parametrize("env", ["demo", "prod"])
@pytest.mark.parametrize("name", NAMES)
def test_ablations_are_refused_in_every_public_environment(env: str, name: str) -> None:
    with pytest.raises(ModeRefused, match=f"APP_ENV={env}"):
        RuntimeSettings.from_env({"APP_ENV": env, name: "1"})


@pytest.mark.parametrize("env", ["dev", "eval"])
def test_ablations_are_allowed_in_dev_and_eval(env: str) -> None:
    got = RuntimeSettings.from_env({"APP_ENV": env, "ABL_NO_GATE": "1"})
    assert got.active_ablations == ("ABL_NO_GATE",)


@pytest.mark.parametrize("env", ["demo", "prod"])
@pytest.mark.parametrize("switch", DEV_ONLY_SWITCHES)
def test_a_dev_only_switch_stops_a_public_start(env: str, switch: str) -> None:
    with pytest.raises(ModeRefused, match=switch):
        RuntimeSettings.from_env({"APP_ENV": env, switch: "1"})
    RuntimeSettings.from_env({"APP_ENV": "dev", switch: "1"})  # fine in dev
    RuntimeSettings.from_env({"APP_ENV": env, switch: "0"})  # an off switch is fine


def test_recording_the_model_is_refused_in_demo() -> None:
    with pytest.raises(ModeRefused, match="LLM_MODE=record"):
        RuntimeSettings.from_env({"APP_ENV": "demo", "LLM_MODE": "record"})


def test_the_entry_point_refuses_before_touching_anything() -> None:
    for env in ({"APP_ENV": "demo", "PAYPAL_ALLOW_NON_SANDBOX": "1"}, {"APP_ENV": "nope"}):
        with pytest.raises(ModeRefused):
            create(env)  # no keys, no database: nothing else may be reached


# --------------------------------------------------------------------------------------- self-check


class _Dash:
    paypal_configured = True
    assistant = type("A", (), {"mode": "replay"})()

    def __init__(self, launcher: bool) -> None:
        self._launcher = launcher

    def attack_runs_enabled(self) -> bool:
        return self._launcher


def test_the_self_check_is_ok_for_a_clean_demo_and_holds_no_value() -> None:
    settings = RuntimeSettings(Mode.FULL, "demo")
    body = selfcheck.report(settings, {"PAYPAL_CLIENT_SECRET": "sekret"}, dashboard=_Dash(False))
    assert body["ok"] is True and body["mode"] == "full" and body["public_environment"] is True
    assert body["ablations"] == [] and body["dev_switches_on"] == []
    assert body["attack_runs_enabled"] is False and body["assistant_mode"] == "replay"
    assert "sekret" not in repr(body)
    assert body["seed"] is None  # counts only when the caller supplies them
    counts = {"orders": 44, "open_mandates": 5, "bundles": 2, "seed_complete": True}
    assert selfcheck.report(settings, {}, seed=counts)["seed"] == counts


def test_the_self_check_fails_when_a_public_launcher_has_no_named_admin_database() -> None:
    settings = RuntimeSettings(Mode.FULL, "demo")
    assert selfcheck.report(settings, {}, dashboard=_Dash(True))["ok"] is False
    named = {"EVAL_DATABASE_ADMIN_URL": "postgresql://x"}
    assert selfcheck.report(settings, named, dashboard=_Dash(True))["ok"] is True


def test_the_self_check_fails_on_a_dev_switch_and_names_it() -> None:
    settings = RuntimeSettings(Mode.FULL, "dev")
    body = selfcheck.report(settings, {"PAYPAL_RECORD_CASSETTES": "1"})
    assert body["ok"] is False and body["dev_switches_on"] == ["PAYPAL_RECORD_CASSETTES"]


# ------------------------------------------------------------------------------------- rate limit


class _Clock:
    now = 1000.0

    def __call__(self) -> float:
        return self.now


def _limited_app(clock: _Clock, trust_proxy: bool = False) -> FastAPI:
    app = FastAPI()

    @app.post("/ucp/v1/checkout-sessions")
    def create_checkout() -> dict[str, int]:
        return {"ok": 1}

    @app.get("/health")
    def health() -> dict[str, int]:
        return {"ok": 1}

    ratelimit.install(app, ratelimit.RateLimiter(trust_proxy=trust_proxy, clock=clock))
    return app


def test_the_31st_create_in_a_minute_is_refused_with_retry_after() -> None:
    clock = _Clock()
    client = TestClient(_limited_app(clock))
    codes = [client.post("/ucp/v1/checkout-sessions").status_code for _ in range(31)]
    assert codes[:30] == [200] * 30 and codes[30] == 429
    r = client.post("/ucp/v1/checkout-sessions")
    assert r.status_code == 429 and r.json()["code"] == "rate_limited"
    assert int(r.headers["retry-after"]) >= 1
    clock.now += 61
    assert client.post("/ucp/v1/checkout-sessions").status_code == 200  # the window slid


def test_unlisted_routes_are_never_limited() -> None:
    client = TestClient(_limited_app(_Clock()))
    assert {client.get("/health").status_code for _ in range(500)} == {200}


def test_the_forwarded_address_is_the_rightmost_entry_only_behind_the_proxy() -> None:
    clock = _Clock()
    behind = TestClient(_limited_app(clock, trust_proxy=True))
    for n in range(30):  # a client that rotates the left-hand entries stays in one bucket
        behind.post(
            "/ucp/v1/checkout-sessions", headers={"X-Forwarded-For": f"10.0.0.{n}, 5.5.5.5"}
        )
    r = behind.post("/ucp/v1/checkout-sessions", headers={"X-Forwarded-For": "10.9.9.9, 5.5.5.5"})
    assert r.status_code == 429
    other = behind.post(
        "/ucp/v1/checkout-sessions", headers={"X-Forwarded-For": "1.1.1.1, 6.6.6.6"}
    )
    assert other.status_code == 200
    direct = TestClient(_limited_app(_Clock(), trust_proxy=False))
    for n in range(30):
        direct.post("/ucp/v1/checkout-sessions", headers={"X-Forwarded-For": f"10.0.0.{n}"})
    assert (
        direct.post("/ucp/v1/checkout-sessions", headers={"X-Forwarded-For": "2.2.2.2"}).status_code
        == 429
    )


@pytest.mark.parametrize(
    ("method", "path", "group"),
    [
        ("POST", "/trusted-surface/keys/challenge", "enrolment"),
        ("POST", "/trusted-surface/keys", "enrolment"),
        ("POST", "/trusted-surface/consent", "consent"),
        ("POST", "/trusted-surface/proposals/abc/mandates", "consent"),
        ("POST", "/trusted-surface/purchases/consent", "consent"),
        ("POST", "/ucp/v1/checkout-sessions", "checkout_create"),
        ("POST", "/checkout_sessions", "checkout_create"),
        ("POST", "/ucp/v1/checkout-sessions/chk_1/complete", "checkout_complete"),
        ("POST", "/checkout_sessions/s1/complete", "checkout_complete"),
        ("GET", "/dashboard/api/v1/assistant/ask", "assistant"),
        ("POST", "/webhooks/paypal", "webhook"),
        ("POST", "/dashboard/api/v1/attack-runs", "attack_run"),
    ],
)
def test_the_public_mutating_routes_are_classified(method: str, path: str, group: str) -> None:
    rule = ratelimit.RateLimiter().rule_for(method, path)
    assert rule is not None and rule.group == group
