"""Record the shopping agent's end-to-end run live: a real model, a headless phone, the PayPal sandbox.

What happens, in order (the same code the replay test runs, tests/integration/test_shopper_replay.py):

1. A scratch Postgres database is created from DATABASE_URL (the compose default if unset), migrated, and
   used as the restricted application role, exactly like production.
2. The sandbox business account's merchant id is read with one throwaway order that is not recorded.
3. The real service starts on a free loopback port, with its PayPal client recording to a transport.
4. The shopping agent runs with the LIVE model gateway in record mode: two model calls, written to
   eval/cassettes/llm/ through the gateway's own scrubber.
5. A headless browser plays the customer's phone: it enrols a WebCrypto device key and taps Approve on the
   real page (web/approve/test/phone_consent.mjs).
6. The agent shops, signs and completes. The script then PRINTS THE PAYPAL APPROVAL LINK AND WAITS: you
   approve as the sandbox buyer in a private window and press Enter.
7. The agent completes again, the capture gate captures, and the receipts come back.
8. Anything left open at PayPal (an authorization neither captured nor voided) is voided with a client that
   is not recording. The scratch database is dropped.

Recording is off unless you opt in. The model settings come from YOUR SHELL only, never from a file:

    export LLM_PROVIDER=... LLM_BASE_URL=... LLM_MODEL=... LLM_API_KEY=...
    PAYPAL_RECORD_CASSETTES=1 uv run python scripts/record_shopper_cassette.py

PayPal credentials come from the environment or the git-ignored .env (PAYPAL_API_BASE, PAYPAL_CLIENT_ID,
PAYPAL_CLIENT_SECRET). The sandbox host is enforced. Nothing secret is printed. This captures real sandbox
money: one authorization for the checkout total, captured in full.
"""

from __future__ import annotations

import datetime as dt
import os
import sys
from pathlib import Path

import httpx
from sqlalchemy import create_engine, text
from sqlalchemy.engine import make_url

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))  # the shared pieces live in tests/, never in the package

from agents.shopper import ShopperError, run_shopper, summary
from countersign.llm import LlmConfig, LlmError, build_gateway
from countersign.paypal.cassette import RecordingTransport, recording_enabled
from countersign.paypal.client import PayPalClient
from countersign.paypal.config import PayPalConfig
from countersign.paypal.errors import PayPalError
from scripts.record_cp_cassette import (
    DEFAULT_ADMIN_URL,
    discover_payee_merchant_id,
    drop_database,
    scratch_database,
    void_leftover,
)
from scripts.record_paypal_cassette import parse_env_file
from tests.phone import phone_consent
from tests.shopper_e2e import CASSETTE_NAME, GOAL, build_service, reserve_port, serve

CASSETTE = ROOT / "tests" / "cassettes" / CASSETTE_NAME


def payer_approval(url: str) -> None:
    print()
    print(
        "Approve the order as the sandbox buyer (a US-based sandbox account), in a private window."
    )
    print(f"  {url}")
    input("Press Enter once the order is approved: ")


def open_authorizations(admin_url: str, name: str) -> list[tuple[str, str]]:
    url = make_url(admin_url).set(database=name).render_as_string(hide_password=False)
    engine = create_engine(url)
    try:
        with engine.connect() as conn:
            rows = conn.execute(
                text(
                    "SELECT checkout_id, authorization_id FROM payment_attempts "
                    "WHERE authorization_id IS NOT NULL AND state NOT IN ('captured', 'voided')"
                )
            ).all()
    finally:
        engine.dispose()
    return [(str(r[0]), str(r[1])) for r in rows]


def main() -> int:
    env = parse_env_file(ROOT / ".env")
    env.update(
        {k: v for k, v in os.environ.items() if k.startswith(("PAYPAL_", "DATABASE_")) and v}
    )
    if not recording_enabled(env):
        print("Recording is off. Run with PAYPAL_RECORD_CASSETTES=1 to record.", file=sys.stderr)
        return 2
    try:
        # The model settings are read from the shell environment only.
        llm = LlmConfig.from_env({**os.environ, "LLM_MODE": "record"})
        gateway = build_gateway(llm)
    except LlmError as error:
        print(f"The model settings are not usable: {error}", file=sys.stderr)
        return 2
    config = PayPalConfig.from_env(env)
    admin_url = env.get("DATABASE_URL", DEFAULT_ADMIN_URL)
    print("Reading the sandbox merchant id (one throwaway order, not recorded)...")
    try:
        merchant_id = discover_payee_merchant_id(config)
    except (PayPalError, RuntimeError) as exc:
        print(f"Could not read the merchant id: {exc}", file=sys.stderr)
        return 1
    sock, base = reserve_port()
    meta = {
        "base_url": base,
        "goal": GOAL,
        "llm_model": llm.model,
        "recorded_at": dt.datetime.now(dt.UTC).strftime("%Y-%m-%dT%H:%M:%SZ"),
        "host": "sandbox",
        "flow": "countersign shopping agent: goal, phone consent, UCP checkout, payer approval, gate capture",
    }
    name, app_url, role = scratch_database(admin_url)
    engine = create_engine(app_url)
    transport = RecordingTransport(
        httpx.HTTPTransport(),
        secrets=[config.client_id, config.client_secret, merchant_id],
        meta=meta,
    )
    result = None
    try:
        with PayPalClient(config, transport=transport) as paypal:
            app = build_service(engine, base, paypal, payee_merchant_id=merchant_id)
            with serve(app, sock):
                print(f"\nThe service is up at {base}. Goal: {GOAL!r}")

                def phone(url: str) -> None:
                    print(f"  the phone opens {url} and taps Approve (headless)")
                    phone_consent(url)

                result = run_shopper(
                    GOAL, base_url=base, gateway=gateway, on_approve_url=phone,
                    on_payer_approval=payer_approval,
                    emit=lambda event: print("  agent:", event.get("event"), flush=True),
                )  # fmt: skip
    except (ShopperError, LlmError, PayPalError, RuntimeError) as exc:
        print(f"The run failed: {exc}", file=sys.stderr)
        return_code = 1
    else:
        return_code = 0
    finally:
        left = open_authorizations(admin_url, name)
        engine.dispose()
        drop_database(admin_url, name, role)
        for checkout, authorization in left:
            void_leftover(config, checkout, authorization)
    if return_code or result is None or result.outcome != "completed":
        print("Not saved: the run did not end in a capture.", file=sys.stderr)
        return 1
    transport.save(CASSETTE)
    print()
    print(summary(result))
    print(f"Saved {CASSETTE.relative_to(ROOT)} and the model cassettes in eval/cassettes/llm/")
    print("Check the files before you commit them (only SCRUBBED_ placeholders may appear).")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
