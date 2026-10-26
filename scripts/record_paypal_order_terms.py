"""Record the order-terms cassette from the live sandbox.

Creates two orders (items only, and items with tax, shipping, handling and a discount) and reads each
back with a GET. No payer approval is needed, only the sandbox REST credentials. The exchange is
saved scrubbed (no token, no credentials, no account ids, no payer data) to
tests/cassettes/paypal_order_terms.json, and the file is refused if anything sensitive remains.

    PAYPAL_RECORD_CASSETTES=1 uv run python scripts/record_paypal_order_terms.py

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

from countersign.paypal.cassette import RecordingTransport, recording_enabled
from countersign.paypal.client import PayPalClient
from countersign.paypal.config import PayPalConfig
from countersign.paypal.errors import PayPalError
from countersign.paypal.terms_flow import KINDS, run_terms_flow
from countersign.paypal.translate import TranslationError

ROOT = Path(__file__).resolve().parents[1]
OUTPUT = ROOT / "tests" / "cassettes" / "paypal_order_terms.json"
sys.path.insert(0, str(Path(__file__).resolve().parent))
from record_paypal_cassette import parse_env_file


def main() -> int:
    env = parse_env_file(ROOT / ".env")
    env.update({k: v for k, v in os.environ.items() if k.startswith("PAYPAL_") and v})
    if not recording_enabled(env):
        print("Recording is off. Run with PAYPAL_RECORD_CASSETTES=1 to record.", file=sys.stderr)
        return 2
    config = PayPalConfig.from_env(env)
    ids = {kind: f"chk_{kind}_" + secrets.token_urlsafe(12) for kind in KINDS}
    meta = {
        "checkout_ids": ids,
        "recorded_at": dt.datetime.now(dt.UTC).strftime("%Y-%m-%dT%H:%M:%SZ"),
        "host": "sandbox",
    }
    transport = RecordingTransport(
        httpx.HTTPTransport(), secrets=[config.client_id, config.client_secret], meta=meta
    )
    with PayPalClient(config, transport=transport) as client:
        for kind in KINDS:
            try:
                result = run_terms_flow(client, kind, ids[kind])
            except (PayPalError, TranslationError) as exc:
                print(f"The {kind} flow failed: {exc}", file=sys.stderr)
                return 1
            same = result.terms.checkout.terms_hash() == result.checkout.terms_hash()
            print(f"{kind}: order {result.order.id}, reverse-translated terms equal: {same}")
    transport.save(OUTPUT)
    print(f"Saved {OUTPUT.relative_to(ROOT)}")
    print("Check the file for anything you do not want committed before you commit it.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
