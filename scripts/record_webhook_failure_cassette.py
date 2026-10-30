"""Record how PayPal answers `verify-webhook-signature` for a FABRICATED notification.

No browser approval is needed and nothing is created or changed at PayPal: the script sends one
made-up event with fake transmission headers and records the real failure answer. It cannot record a
SUCCESS answer; that needs a delivery from PayPal to a public URL (docs/ENV.md, pending item for the
Render deploy).

It needs the webhook id of a webhook registered in the sandbox developer portal, in
`PAYPAL_WEBHOOK_ID`. Without it the script stops. Recording is off unless you opt in:

    PAYPAL_RECORD_CASSETTES=1 uv run python scripts/record_webhook_failure_cassette.py

Credentials come from the environment or the git-ignored .env. The sandbox host is enforced and nothing
secret is printed. The result is saved scrubbed to tests/cassettes/webhook_verify_failure.json.
"""

from __future__ import annotations

import os
import sys
from pathlib import Path

import httpx

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from countersign.paypal.cassette import RecordingTransport, recording_enabled
from countersign.paypal.client import PayPalClient
from countersign.paypal.config import PayPalConfig
from countersign.paypal.errors import PayPalError
from scripts.record_paypal_cassette import parse_env_file

CASSETTE = ROOT / "tests" / "cassettes" / "webhook_verify_failure.json"
FABRICATED = (
    b'{"id":"WH-FABRICATED-0001","event_type":"PAYMENT.AUTHORIZATION.VOIDED",'
    b'"resource":{"id":"FABRICATED"},"summary":"fabricated for a recording"}'
)


def main() -> int:
    env = parse_env_file(ROOT / ".env")
    env.update({k: v for k, v in os.environ.items() if k.startswith("PAYPAL_") and v})
    if not recording_enabled(env):
        print("Recording is off. Run with PAYPAL_RECORD_CASSETTES=1 to record.", file=sys.stderr)
        return 2
    config = PayPalConfig.from_env(env)
    if not config.webhook_id:
        print(
            "PAYPAL_WEBHOOK_ID is not set. Register a webhook in the sandbox developer portal, "
            "put its id in .env, and run again.",
            file=sys.stderr,
        )
        return 2
    transport = RecordingTransport(
        httpx.HTTPTransport(),
        secrets=[config.client_id, config.client_secret, config.webhook_id],
        meta={"flow": "verify-webhook-signature for a fabricated event", "host": "sandbox"},
    )
    outcome = "unknown"
    with PayPalClient(config, transport=transport) as client:
        try:
            genuine = client.verify_webhook_signature(
                transmission_id="00000000-0000-0000-0000-00000000fab1",
                transmission_time="2026-10-30T10:00:00Z",
                transmission_sig="ZmFicmljYXRlZA==",
                cert_url="https://api.sandbox.paypal.com/v1/notifications/certs/CERT-FABRICATED",
                auth_algo="SHA256withRSA",
                webhook_id=config.webhook_id,
                raw_event=FABRICATED,
            )
            outcome = f"answered, genuine={genuine}"
        except PayPalError as exc:
            outcome = f"raised {type(exc).__name__} (HTTP {exc.status})"
    transport.save(CASSETTE)
    print(f"PayPal {outcome}. Saved {CASSETTE.relative_to(ROOT)}; check it before you commit it.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
