"""The P3 gate: an autonomous purchase from phone approval to a captured sandbox order to a verified evidence
bundle, with no server-held customer key.

The run is the recorded one of 4 Nov 2026 (`tests/cassettes/shopper_e2e.json`, capture 49029167TJ689282S,
and the two model cassettes), replayed: no live PayPal or model call. The customer's phone is a headless
Chromium that makes a non-extractable WebCrypto key and signs the consent on the real page. The service is
the real composition root on Postgres. At the end the stored bundle must verify in the Python CLI and in
the browser verifier, with the service's real merchant and platform public keys pinned, and the customer's
private key must be nowhere the server can reach: the database, the configuration, the logs and the
objects alive in this process hold only the public device JWK.
"""

from __future__ import annotations

import ast
import gc
import json
import os
import shutil
import subprocess
import sys
from collections.abc import Iterator
from contextlib import redirect_stderr, redirect_stdout
from pathlib import Path
from typing import Any

import pytest
from cryptography.hazmat.primitives.asymmetric import ec
from joserfc.jwk import ECKey
from sqlalchemy import Engine, text
from structlog.testing import capture_logs

from agents.shopper import ShopperResult, run_shopper
from countersign.composition import Wiring, build_app
from countersign.llm import LlmConfig, LlmGateway
from countersign.merchant.keys import MerchantKey, generate_jwk, validate_jwk
from countersign.paypal.cassette import load_cassette
from countersign.paypal.client import PayPalClient
from countersign.paypal.config import PayPalConfig
from countersign.runtime import Mode, RuntimeSettings
from tests.mode_support import reset
from tests.phone import phone_consent
from tests.shopper_e2e import (
    CASSETTE_NAME,
    MERCHANT_ID,
    MERCHANT_NAME,
    SubstitutingTransport,
    recorded_clock,
    reserve_port,
    serve,
)

ROOT = Path(__file__).resolve().parents[2]
CASSETTE = ROOT / "tests" / "cassettes" / CASSETTE_NAME
RECORDED_CAPTURE = "49029167TJ689282S"
SRC = ROOT / "src" / "countersign"


class Run:
    result: ShopperResult
    merchant: MerchantKey
    platform: ECKey
    bundle_text: str
    bundle: dict[str, Any]
    logs: str
    events: list[dict[str, Any]]


VIDEO = os.environ.get("GATE_VIDEO_DIR")  # optional: record the run for the owner (never committed)


@pytest.fixture(scope="module")
def gate_run(
    app_engine: Engine, admin_engine: Engine, tmp_path_factory: pytest.TempPathFactory
) -> Iterator[Run]:
    recorded = load_cassette(CASSETTE)
    reset(admin_engine)
    with admin_engine.begin() as conn:
        conn.execute(text("TRUNCATE paypal_observations, evidence_bundles CASCADE"))
    run = Run()
    run.merchant = validate_jwk(generate_jwk())
    run.platform = ECKey.generate_key("P-256")
    sock, base = reserve_port()
    now = recorded_clock(recorded)
    paypal = PayPalClient(
        PayPalConfig(client_id="replay-client-id", client_secret="replay-client-secret"),
        transport=SubstitutingTransport(recorded, live_base=base), monotonic=lambda: 0.0, now=now,
        sleep=lambda _: None,
    )  # fmt: skip
    app = build_app(
        RuntimeSettings(Mode.FULL, "demo"),
        Wiring(
            engine=app_engine, merchant_key=run.merchant, platform_key=run.platform, paypal=paypal,
            public_base_url=base, payee={"id": MERCHANT_ID, "name": MERCHANT_NAME},
            paypal_payee_merchant_id="SCRUBBED_MERCHANT_ID", merchant_constraint_id=MERCHANT_ID,
            paypal_now=now,
        ),
    )  # fmt: skip
    gateway = LlmGateway(LlmConfig(mode="replay", model=str(recorded["meta"]["llm_model"])))
    run.events = []
    if VIDEO:
        os.environ["PHONE_VIDEO_DIR"] = str(Path(VIDEO).resolve() / "phone")
    log_file = tmp_path_factory.mktemp("logs") / "process.log"
    with (
        log_file.open("w") as sink, _redirect_fds(sink), redirect_stdout(sink),
        redirect_stderr(sink), capture_logs() as events, serve(app, sock),
    ):  # fmt: skip
        run.result = run_shopper(
            str(recorded["meta"]["goal"]), base_url=base, gateway=gateway,
            on_approve_url=phone_consent, on_payer_approval=lambda _url: None, poll_s=0.5,
            emit=run.events.append,
        )  # fmt: skip
        import httpx

        response = httpx.get(f"{base}/evidence/{run.result.capture_id}", timeout=10)
        assert response.status_code == 200, response.text
        run.bundle_text = response.text
    os.environ.pop("PHONE_VIDEO_DIR", None)
    run.logs = log_file.read_text() + "\n".join(json.dumps(e, default=repr) for e in events)
    run.bundle = json.loads(run.bundle_text)
    yield run


class _redirect_fds:
    """Send this process's stdout and stderr (structlog, uvicorn) to `sink` for the duration."""

    def __init__(self, sink: Any) -> None:
        self.sink = sink

    def __enter__(self) -> None:
        sys.stdout.flush()
        sys.stderr.flush()
        self.saved = (os.dup(1), os.dup(2))
        os.dup2(self.sink.fileno(), 1)
        os.dup2(self.sink.fileno(), 2)

    def __exit__(self, *exc: object) -> None:
        sys.stdout.flush()
        sys.stderr.flush()
        os.dup2(self.saved[0], 1)
        os.dup2(self.saved[1], 2)
        for fd in self.saved:
            os.close(fd)


def _pins(run: Run, tmp: Path) -> dict[str, str]:
    public = run.platform.as_dict(private=False)
    keys = {
        "merchant": dict(run.merchant.public_jwk),
        "platform": {k: public[k] for k in ("kty", "crv", "x", "y")},
    }
    paths = {}
    for name, key in keys.items():
        path = tmp / f"{name}.pinned.json"
        path.write_text(json.dumps(key))
        paths[name] = str(path)
    return paths


# ------------------------------------------------------------------------------- the purchase


def test_the_autonomous_purchase_reached_the_recorded_sandbox_capture(gate_run: Run) -> None:
    assert gate_run.result.outcome == "completed" and gate_run.result.attempts == 1
    assert gate_run.result.capture_id == RECORDED_CAPTURE
    assert gate_run.bundle["capture_id"] == RECORDED_CAPTURE
    assert gate_run.bundle["paypal"]["capture"][-1]["status"] == "COMPLETED"


def test_the_bundle_verifies_in_the_python_cli_with_the_service_keys_pinned(
    gate_run: Run, tmp_path: Path
) -> None:
    path = tmp_path / "bundle.json"
    path.write_text(gate_run.bundle_text)
    pins = _pins(gate_run, tmp_path)
    done = subprocess.run(
        [sys.executable, "-m", "countersign_verify", str(path), "--merchant-key", pins["merchant"],
         "--platform-key", pins["platform"]],
        capture_output=True, text=True, cwd=ROOT, check=False,
    )  # fmt: skip
    assert done.returncode == 0, done.stdout + done.stderr
    assert done.stdout.count("PASS") == 12


def test_the_bundle_verifies_in_the_browser_verifier_with_the_service_keys_pinned(
    gate_run: Run, tmp_path: Path
) -> None:
    node = shutil.which("node")
    assert node
    path = tmp_path / "bundle.json"
    path.write_text(gate_run.bundle_text)
    jobs = tmp_path / "jobs.json"
    jobs.write_text(json.dumps([{"path": str(path), "pinned": _pins(gate_run, tmp_path)}]))
    done = subprocess.run(
        [node, "test/verify-runner.mjs", str(jobs)], cwd=ROOT / "web" / "ui",
        capture_output=True, text=True, check=False, timeout=120,
    )  # fmt: skip
    assert done.returncode == 0, done.stderr
    results = json.loads(done.stdout)[0]
    assert [r["name"] for r in results][-1] == "trusted_keys" and len(results) == 12
    assert all(r["ok"] for r in results), [r for r in results if not r["ok"]]


# ------------------------------------------------------------------------- no server-held customer key


def _device(run: Run) -> dict[str, Any]:
    jwk: dict[str, Any] = run.bundle["consent"]["device_jwk"]
    assert set(jwk) <= {"kty", "crv", "x", "y"} and "d" not in jwk
    return jwk


def _json_objects(value: Any) -> Iterator[dict[str, Any]]:
    if isinstance(value, dict):
        yield value
        for v in value.values():
            yield from _json_objects(v)
    elif isinstance(value, list):
        for v in value:
            yield from _json_objects(v)
    elif isinstance(value, str) and value[:1] in "{[":
        try:
            yield from _json_objects(json.loads(value))
        except ValueError:
            return


def test_the_database_holds_only_the_public_device_key(gate_run: Run, admin_engine: Engine) -> None:
    device = _device(gate_run)
    with admin_engine.connect() as conn:
        tables = [
            r[0]
            for r in conn.execute(
                text("SELECT tablename FROM pg_tables WHERE schemaname = 'public'")
            )
        ]
        rows: list[str] = []
        for table in tables:
            rows += [r[0] for r in conn.execute(text(f'SELECT CAST(t AS text) FROM "{table}" t'))]
        registered = conn.execute(
            text("SELECT jwk FROM customer_keys WHERE customer_id = :c"),
            {"c": gate_run.bundle["consent"]["customer_id"]},
        ).all()
    assert len(registered) == 1
    assert {k: v for k, v in json.loads(registered[0][0]).items() if k in device} == device
    assert "d" not in json.loads(registered[0][0])
    dump = "\n".join(rows)
    assert device["x"] in dump  # the scan sees the public key, so it would see more
    for obj in _json_objects(rows):
        assert not ("d" in obj and "kty" in obj), "a private JWK is stored"
    assert '"d":' not in dump.replace(" ", "") and '\\"d\\":' not in dump.replace(" ", "")


def test_the_logs_and_the_configuration_hold_no_private_key(gate_run: Run) -> None:
    device = _device(gate_run)
    assert gate_run.logs, "the run wrote no process log"
    compact = gate_run.logs.replace(" ", "")
    assert '"d":' not in compact and "'d':" not in compact
    for value in os.environ.values():
        assert device["x"] not in value
        assert '"d":' not in value.replace(" ", "")
    # The only keys the service is configured with are its own two, neither of them the customer's.
    for key in (gate_run.merchant.public_jwk, gate_run.platform.as_dict(private=False)):
        assert key["x"] != device["x"]


def test_no_object_alive_in_this_process_is_the_customer_private_key(gate_run: Run) -> None:
    """The server and the agent ran in this process; no private key object here matches the device."""
    device_x = _device(gate_run)["x"]
    private_seen = 0
    for obj in gc.get_objects():
        try:
            if isinstance(obj, ec.EllipticCurvePrivateKey):
                private_seen += 1
                x = obj.public_key().public_numbers().x.to_bytes(32, "big")
                from countersign_verify.crypto import b64url

                assert b64url(x) != device_x
            elif isinstance(obj, ECKey) and obj.is_private:
                private_seen += 1
                assert obj.as_dict(private=False)["x"] != device_x
            elif isinstance(obj, dict) and "d" in obj and obj.get("x") == device_x:
                pytest.fail("a private JWK of the device is in memory")
        except ReferenceError:
            continue
    assert private_seen >= 2  # the merchant and platform keys are visible to this scan


def test_no_server_code_signs_a_consent_record() -> None:
    """Only three modules sign anything (mandates with the platform key, receipts and checkouts with
    the merchant key), none of them names the consent purpose, and no module calls a raw ECDSA sign."""
    signers = set()
    for path in SRC.rglob("*.py"):
        source = path.read_text()
        tree = ast.parse(source)
        for node in ast.walk(tree):
            if isinstance(node, ast.Call) and isinstance(node.func, ast.Attribute):
                if node.func.attr == "serialize_compact":
                    signers.add(path.relative_to(SRC).as_posix())
                assert node.func.attr != "sign", f"a raw sign call in {path}"
    assert signers == {
        "trusted_surface/issuer.py", "merchant/receipts.py", "merchant/authorization.py"
    }  # fmt: skip
    for name in signers:
        source = (SRC / name).read_text()
        for marker in (
            "countersign.consent.",
            "PURPOSE_CONSENT",
            "consent_records",
            ".consent import",
        ):
            assert marker not in source, (name, marker)


def test_open_mandates_are_issued_only_after_a_verified_device_signature() -> None:
    """The two `issue_open_mandate` calls follow the device signature check in the same function."""
    tree = ast.parse((SRC / "trusted_surface" / "service.py").read_text())
    for fn in ast.walk(tree):
        if not isinstance(fn, ast.FunctionDef):
            continue
        calls = [
            (n.lineno, n.func.id)
            for n in ast.walk(fn)
            if isinstance(n, ast.Call) and isinstance(n.func, ast.Name)
        ]
        issued = [line for line, name in calls if name == "issue_open_mandate"]
        if issued:
            checked = [line for line, name in calls if name == "verify_signature"]
            assert checked and max(checked) < min(issued), fn.name
    for path in SRC.rglob("*.py"):
        if path.name not in {"service.py", "issuer.py"}:
            assert "issue_open_mandate(" not in path.read_text(), path


def test_the_run_issued_its_mandates_from_the_browser_signed_consent(
    gate_run: Run, admin_engine: Engine
) -> None:
    with admin_engine.connect() as conn:
        consent = (
            conn.execute(
                text(
                    "SELECT record, signature, checkout_mandate, payment_mandate, device_jwk "
                    "FROM consent_records WHERE customer_id = :c"
                ),
                {"c": gate_run.bundle["consent"]["customer_id"]},
            )
            .mappings()
            .one()
        )
        kinds = [
            r[0]
            for r in conn.execute(
                text(
                    "SELECT kind FROM decision_log WHERE kind IN "
                    "('ts.key.registered', 'ts.consent.issued') ORDER BY seq"
                )
            )
        ]
    assert kinds == ["ts.key.registered", "ts.consent.issued"]
    mandates = gate_run.bundle["mandates"]
    assert consent["checkout_mandate"] == mandates["checkout_open"]
    assert consent["payment_mandate"] == mandates["payment_open"]
    assert consent["record"] == gate_run.bundle["consent"]["record"]
    assert consent["signature"] == gate_run.bundle["consent"]["signature"]
    # The bundle's consent_signature step (passed above, in both verifiers) checks this signature
    # against the device key and the record against both open mandates.


@pytest.mark.skipif(not VIDEO, reason="recording only: set GATE_VIDEO_DIR (never committed)")
def test_record_the_agent_log_and_the_verifier_page(
    gate_run: Run, app_engine: Engine, tmp_path: Path
) -> None:
    """Not a check: a screen capture of the agent log and the verifier page, for the owner."""
    from countersign.api.app import create_app
    from countersign.evidence import EvidenceService

    assert VIDEO
    out = Path(VIDEO).resolve()
    sock, base = reserve_port()
    service = EvidenceService(
        app_engine, merchant_jwk=dict(gate_run.merchant.public_jwk),
        platform_jwk=gate_run.platform.as_dict(private=False), clock_us=lambda: 1,
        policy_hash=b"\x00" * 32,
    )  # fmt: skip
    app = create_app(
        key=gate_run.merchant, public_base_url=base, engine=app_engine,
        runtime=RuntimeSettings(app_env="demo"), evidence=service,
    )  # fmt: skip
    tampered = json.loads(gate_run.bundle_text)
    tampered["paypal"]["capture"][-1]["amount"]["value"] = "1.00"
    pins = _pins(gate_run, tmp_path)
    spec = tmp_path / "spec.json"
    spec.write_text(
        json.dumps({
            "base": base, "capture_id": gate_run.result.capture_id, "events": gate_run.events,
            "merchant_key": Path(pins["merchant"]).read_text(),
            "platform_key": Path(pins["platform"]).read_text(),
            "tampered": json.dumps(tampered, indent=1), "out": str(out),
        })
    )  # fmt: skip
    node = shutil.which("node")
    assert node
    with serve(app, sock):
        done = subprocess.run(
            [node, "test/record-gate-video.mjs", str(spec)], cwd=ROOT / "web" / "ui",
            capture_output=True, text=True, check=False, timeout=300,
        )  # fmt: skip
    assert done.returncode == 0, done.stderr
    (out / "paths.txt").write_text(done.stdout)
