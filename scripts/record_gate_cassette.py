"""Record the capture gate cassette from the live PayPal sandbox: two orders, two approvals.

Scenario A (a clean flow). Merchant verification, Credential Provider, PayPal order, YOU APPROVE IT,
authorization, then the gate passes and captures. The capture and the authorization are read back.
This captures real sandbox money: one authorization for the checkout total, captured in full.

Scenario B (an order changed after approval). A second order is created and YOU APPROVE IT; the script
then PATCHes the approved order's first item up by 20.00 (the window recorded in docs/PROTOCOL.md 4.3), the
Credential Provider's pre-authorize check is switched off for this one order so PayPal authorizes the
raised amount, and the gate must catch it, void the authorization and confirm the void by GET. Nothing
is captured in B. After B one more call is recorded on purpose: a second void of B's voided
authorization, under a different Request-Id, so the cassette holds a real PayPal 422 error body and
shows whether the specific code is in `name` or in `details[].issue`.

What it does, in order (the same code the replay test runs, tests/gate_flow.py):

1. Creates a scratch Postgres database from DATABASE_URL (the compose default if unset), migrates it
   and connects as a restricted application role, exactly like production.
2. Reads the sandbox business account's merchant id with one throwaway order (not recorded).
3. Signs two checkouts and their mandates (public keys only are kept).
4. Runs A, PRINTS THE APPROVAL LINK AND WAITS; then runs B, PRINTS THE LINK AND WAITS.
5. Saves the scrubbed exchange to tests/cassettes/gate_flow.json and the mandates the replay needs to
   tests/cassettes/gate_flow.mandates.json, then drops the scratch database.

Recording is off unless you opt in:

    PAYPAL_RECORD_CASSETTES=1 uv run python scripts/record_gate_cassette.py

Credentials come from the environment or the git-ignored .env (PAYPAL_API_BASE, PAYPAL_CLIENT_ID,
PAYPAL_CLIENT_SECRET). The sandbox host is enforced. Nothing secret is printed.
"""

from __future__ import annotations

import datetime as dt
import os
import secrets
import sys
from pathlib import Path

import httpx
from sqlalchemy import create_engine

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))  # the flow lives in tests/, never in the package

from countersign.ablations import Ablations
from countersign.gate import GatePassed, GateRejected
from countersign.paypal.cassette import RecordingTransport, recording_enabled
from countersign.paypal.client import PayPalClient
from countersign.paypal.config import PayPalConfig
from countersign.paypal.errors import PayPalError
from scripts.record_cp_cassette import (
    DEFAULT_ADMIN_URL,
    discover_payee_merchant_id,
    drop_database,
    scratch_database,
)
from scripts.record_paypal_cassette import parse_env_file
from tests.cp_flow import authorized
from tests.gate_flow import (
    GateFixtures,
    authorize_flow,
    build_gate_fixture,
    make_stack,
    patch_raise,
    probe_refusal,
    run_gate,
)

CASSETTE = ROOT / "tests" / "cassettes" / "gate_flow.json"
FIXTURE = ROOT / "tests" / "cassettes" / "gate_flow.mandates.json"


def approve(url: str) -> None:
    print()
    print("Approve the order as the sandbox buyer (a US-based sandbox account), then come back.")
    print(f"  {url}")
    input("Press Enter once the order is approved: ")


def main() -> int:
    env = parse_env_file(ROOT / ".env")
    env.update(
        {k: v for k, v in os.environ.items() if k.startswith(("PAYPAL_", "DATABASE_")) and v}
    )
    if not recording_enabled(env):
        print("Recording is off. Run with PAYPAL_RECORD_CASSETTES=1 to record.", file=sys.stderr)
        return 2
    config = PayPalConfig.from_env(env)
    admin_url = env.get("DATABASE_URL", DEFAULT_ADMIN_URL)
    suffix = secrets.token_urlsafe(16)
    clean_id, changed_id = f"chk_{suffix}", f"chk_{secrets.token_urlsafe(16)}"
    meta = {
        "clean_checkout_id": clean_id,
        "changed_checkout_id": changed_id,
        "recorded_at": dt.datetime.now(dt.UTC).strftime("%Y-%m-%dT%H:%M:%SZ"),
        "host": "sandbox",
        "flow": "countersign capture gate: A clean capture, B order raised after approval then voided",
    }
    print("Reading the sandbox merchant id (one throwaway order, not recorded)...")
    try:
        merchant_id = discover_payee_merchant_id(config)
    except (PayPalError, RuntimeError) as exc:
        print(f"Could not read the merchant id: {exc}", file=sys.stderr)
        return 1
    name, app_url, role = scratch_database(admin_url)
    engine = create_engine(app_url)
    transport = RecordingTransport(
        httpx.HTTPTransport(),
        secrets=[config.client_id, config.client_secret, merchant_id],
        meta=meta,
    )
    fixtures = GateFixtures(build_gate_fixture(clean_id), build_gate_fixture(changed_id))
    now = lambda: dt.datetime.now(dt.UTC)
    try:
        with PayPalClient(config, transport=transport) as client:
            print("\n=== Scenario A: a clean flow ends in a capture ===")
            a = make_stack(engine, client, fixtures.clean, payee_merchant_id=merchant_id,
                           paypal_now=now)  # fmt: skip
            _, finished = authorize_flow(a, fixtures.clean, approve)
            authorized(finished)
            outcome_a = run_gate(a, fixtures.clean)
            print(f"  gate: {type(outcome_a).__name__}")

            print("\n=== Scenario B: the order is raised after approval, before authorization ===")
            b = make_stack(engine, client, fixtures.changed, payee_merchant_id=merchant_id,
                           paypal_now=now, cp_ablations=Ablations(no_preauth_check=True))  # fmt: skip

            def raise_order(order_id: str) -> None:
                new_total = patch_raise(client, transport, config.base_url, order_id)
                print(f"  PATCHed the approved order up to {new_total}")

            _, finished_b = authorize_flow(b, fixtures.changed, approve, between=raise_order)
            authorized(finished_b)
            outcome_b = run_gate(b, fixtures.changed)
            print(f"  gate: {type(outcome_b).__name__}")

            print("\n=== Error body probe: a second void of the voided authorization ===")
            refusal = probe_refusal(client, changed_id, finished_b.authorization_id)
            print(f"  HTTP {refusal.status}: name={refusal.name} issues={refusal.issues}")
    except (PayPalError, RuntimeError, TypeError) as exc:
        print(f"The flow failed: {exc}", file=sys.stderr)
        return 1
    finally:
        engine.dispose()
        drop_database(admin_url, name, role)
    if not isinstance(outcome_a, GatePassed):
        print(f"Not saved: scenario A ended with {outcome_a}", file=sys.stderr)
        return 1
    if not isinstance(outcome_b, GateRejected):
        print(f"Not saved: scenario B ended with {outcome_b}", file=sys.stderr)
        return 1
    transport.save(CASSETTE)
    FIXTURE.write_text(fixtures.to_json(), encoding="utf-8")
    print()
    print(f"Saved {CASSETTE.relative_to(ROOT)} and {FIXTURE.relative_to(ROOT)}")
    print(f"  A: capture {outcome_a.capture_id} for {outcome_a.amount}")
    print(f"  B: rejected at {outcome_b.code} ({outcome_b.reason}); the authorization was voided")
    print("Check the files before you commit them.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
