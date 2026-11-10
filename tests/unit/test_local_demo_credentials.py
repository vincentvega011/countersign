"""The PayPal-free local demo (Decision 144): the placeholder credential counts as "no credentials"."""

from __future__ import annotations

import json
from pathlib import Path

from countersign.main import NO_CREDENTIALS, wiring_from_env
from countersign.merchant.keys import generate_jwk

ROOT = Path(__file__).resolve().parents[2]


def env(client_id: str) -> dict[str, str]:
    return {
        "MERCHANT_KEY_JSON": json.dumps(generate_jwk()),
        "PAYPAL_CLIENT_ID": client_id,
        "PAYPAL_CLIENT_SECRET": client_id,
        "DATABASE_URL": "sqlite://",
    }


def test_the_placeholder_is_reported_as_not_configured() -> None:
    assert wiring_from_env(env(NO_CREDENTIALS)).paypal_configured is False


def test_a_real_looking_credential_is_reported_as_configured() -> None:
    assert wiring_from_env(env("sandbox-client-id")).paypal_configured is True


def test_the_demo_script_uses_the_same_placeholder() -> None:
    assert NO_CREDENTIALS in (ROOT / "scripts" / "demo.sh").read_text()
