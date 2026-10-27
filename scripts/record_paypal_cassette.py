"""Record the PayPal authorize-and-capture cassette from the live sandbox.

Needs one approval from you: the script creates an order, prints the approval link, waits while you
approve it with the sandbox buyer, then authorizes, captures and reads everything back. The exchange
is saved scrubbed (no token, no credentials, no account ids, no payer data) to
tests/cassettes/paypal_authorize_capture.json, and the file is refused if anything sensitive remains.

Recording is off unless you opt in:

    PAYPAL_RECORD_CASSETTES=1 uv run python scripts/record_paypal_cassette.py

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

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))  # the recording cycle lives in tests/, never in the package
from tests.ungated_capture_cycle import run_cycle

OUTPUT = ROOT / "tests" / "cassettes" / "paypal_authorize_capture.json"


def parse_env_file(path: Path) -> dict[str, str]:
    values: dict[str, str] = {}
    if not path.is_file():
        return values
    for raw in path.read_text(encoding="utf-8").splitlines():
        line = raw.strip()
        if not line or line.startswith("#") or "=" not in line:
            continue
        key, _, value = line.partition("=")
        value = value.strip()
        if value[:1] in ("'", '"') and value[-1:] == value[:1] and len(value) >= 2:
            value = value[1:-1]
        elif " #" in value:
            value = value.split(" #", 1)[0].strip()
        values[key.strip()] = value
    return values


def approve(url: str) -> None:
    print()
    print("Approve the order as the sandbox buyer (a US-based sandbox account), then come back.")
    print(f"  {url}")
    input("Press Enter once the order is approved: ")


def main() -> int:
    env = parse_env_file(ROOT / ".env")
    env.update({k: v for k, v in os.environ.items() if k.startswith("PAYPAL_") and v})
    if not recording_enabled(env):
        print("Recording is off. Run with PAYPAL_RECORD_CASSETTES=1 to record.", file=sys.stderr)
        return 2
    config = PayPalConfig.from_env(env)
    checkout_id = "chk_" + secrets.token_urlsafe(16)
    meta = {
        "checkout_id": checkout_id,
        "recorded_at": dt.datetime.now(dt.UTC).strftime("%Y-%m-%dT%H:%M:%SZ"),
        "host": "sandbox",
    }
    transport = RecordingTransport(
        httpx.HTTPTransport(),
        secrets=[config.client_id, config.client_secret],
        meta=meta,
    )
    with PayPalClient(config, transport=transport) as client:
        try:
            result = run_cycle(client, checkout_id, approve=approve)
        except PayPalError as exc:
            print(f"The cycle failed: {exc}", file=sys.stderr)
            return 1
    transport.save(OUTPUT)
    capture = result.capture
    print()
    print(f"Saved {OUTPUT.relative_to(ROOT)}")
    print(f"  checkout {checkout_id}")
    print(f"  order {result.final_order.id} status {result.final_order.status}")
    print(f"  capture {capture.id} status {capture.status} final_capture {capture.final_capture}")
    print("Check the file for anything you do not want committed before you commit it.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
