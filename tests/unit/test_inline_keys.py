"""Keys given as JSON in the environment (a host with no secret files) go through the same validation."""

from __future__ import annotations

import json

import pytest

from countersign.main import _merchant_key, _platform_key
from countersign.merchant.keys import MerchantKeyError, generate_jwk


def test_inline_merchant_key_is_validated_like_a_file() -> None:
    jwk = generate_jwk()
    assert _merchant_key({"MERCHANT_KEY_JSON": json.dumps(jwk)}).public_jwk["kid"] == jwk["kid"]
    weak = {**jwk, "alg": "ES384"}
    with pytest.raises(MerchantKeyError):
        _merchant_key({"MERCHANT_KEY_JSON": json.dumps(weak)})
    with pytest.raises(Exception):  # noqa: B017 - duplicate keys are refused by the strict loader
        _merchant_key({"MERCHANT_KEY_JSON": '{"kty":"EC","kty":"EC"}'})


def test_inline_platform_key_wins_over_a_path_and_none_means_none() -> None:
    jwk = generate_jwk()
    got = _platform_key({"PLATFORM_KEY_JSON": json.dumps(jwk), "PLATFORM_KEY_PATH": "/nope"})
    assert got is not None and got.as_dict(private=False)["x"] == jwk["x"]
    assert _platform_key({}) is None
