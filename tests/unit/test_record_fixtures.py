"""The recording scripts build mandates that carry the mandatory `sub`, and leave nothing open.

The cassettes are recorded from the live sandbox (`scripts/record_cp_cassette.py`,
`scripts/record_gate_cassette.py`) with mandates built by `tests/cp_flow.build_fixture` and
`tests/gate_flow.build_gate_fixture`. Once the customer id is mandatory those mandates must carry it, in
the shape the Trusted Surface issuer writes, or a fresh recording would not replay. This checks the
builders and the scripts without touching PayPal.
"""

from __future__ import annotations

import base64
import json
import re
from typing import Any

import httpx
from joserfc.jwk import ECKey

from countersign.mandates import (
    VCT_CHECKOUT,
    VCT_CHECKOUT_OPEN,
    VCT_PAYMENT,
    VCT_PAYMENT_OPEN,
    verify_chain,
)
from countersign.paypal.config import PayPalConfig
from scripts.record_cp_cassette import void_leftover
from tests.cp_flow import FlowFixture, build_fixture
from tests.gate_flow import build_gate_fixture

CUSTOMER = re.compile(r"cus_[A-Za-z0-9_-]{22}")


def sub_of(token: str) -> Any:
    payload = token.split(".")[1]
    return json.loads(base64.urlsafe_b64decode(payload + "=" * (-len(payload) % 4))).get("sub")


def check(fixture: FlowFixture) -> None:
    key = ECKey.import_key(fixture.platform_jwk)
    checkout = verify_chain(
        fixture.checkout_mandate, issuer_key=key, expected_vcts=[VCT_CHECKOUT_OPEN, VCT_CHECKOUT],
        audience="merchant", clock=lambda: fixture.now,
    )  # fmt: skip
    payment = verify_chain(
        fixture.payment_token, issuer_key=key, expected_vcts=[VCT_PAYMENT_OPEN, VCT_PAYMENT],
        audience="credential-provider", clock=lambda: fixture.now,
    )  # fmt: skip
    customer = sub_of(fixture.checkout_mandate)
    assert isinstance(customer, str) and CUSTOMER.fullmatch(customer)
    assert sub_of(fixture.payment_token) == customer
    assert checkout.links[0].claims["sub"] == payment.links[0].claims["sub"] == customer


def test_the_credential_provider_fixture_carries_a_customer_id() -> None:
    check(build_fixture("chk_" + "a" * 22))


def test_the_gate_fixtures_carry_a_customer_id_each() -> None:
    first, second = build_gate_fixture("chk_" + "b" * 22), build_gate_fixture("chk_" + "c" * 22)
    check(first)
    check(second)
    assert sub_of(first.checkout_mandate) != sub_of(second.checkout_mandate)


def test_the_recording_scripts_void_what_they_leave_open() -> None:
    from pathlib import Path

    root = Path(__file__).resolve().parents[2] / "scripts"
    cp = (root / "record_cp_cassette.py").read_text()
    gate = (root / "record_gate_cassette.py").read_text()
    assert "void_leftover(config, checkout_id, finished.authorization_id)" in cp
    assert (
        "open_authorizations" in gate and "void_leftover(config, checkout, authorization)" in gate
    )


def test_void_leftover_voids_through_a_client_that_is_not_the_recording_one() -> None:
    seen: list[tuple[str, str]] = []

    def handler(request: httpx.Request) -> httpx.Response:
        seen.append((request.method, request.url.path))
        if request.url.path.endswith("/oauth2/token"):
            return httpx.Response(
                200, json={"access_token": "t", "expires_in": 3000, "token_type": "Bearer"}
            )
        return httpx.Response(204)

    config = PayPalConfig(client_id="id", client_secret="secret")
    ok = void_leftover(config, "chk_" + "d" * 22, "AUTH123", httpx.MockTransport(handler))
    assert ok is True
    assert ("POST", "/v2/payments/authorizations/AUTH123/void") in seen

    def failing(request: httpx.Request) -> httpx.Response:
        if request.url.path.endswith("/oauth2/token"):
            return httpx.Response(
                200, json={"access_token": "t", "expires_in": 3000, "token_type": "Bearer"}
            )
        return httpx.Response(
            422,
            json={
                "name": "UNPROCESSABLE_ENTITY",
                "details": [{"issue": "AUTHORIZATION_ALREADY_CAPTURED"}],
            },
        )

    assert (
        void_leftover(config, "chk_" + "d" * 22, "AUTH123", httpx.MockTransport(failing)) is False
    )
