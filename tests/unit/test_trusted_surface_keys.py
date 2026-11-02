"""Pure checks of device keys: JWK validation, thumbprint, origin, record and signature."""

from __future__ import annotations

from typing import Any

import pytest
from hypothesis import given
from hypothesis import strategies as st
from joserfc.jwk import ECKey

from countersign.trusted_surface.keys import (
    KeyRefused,
    normalize_origin,
    origin_string,
    registration_record,
    thumbprint_of,
    validate_public_jwk,
    verify_signature,
)
from tests.surface_support import Device, b64


def test_a_valid_key_has_the_rfc7638_thumbprint() -> None:
    device = Device()
    key = validate_public_jwk(device.jwk)
    assert key.thumbprint == device.thumbprint == ECKey.import_key(device.jwk).thumbprint()
    assert thumbprint_of(device.jwk) == key.thumbprint and len(key.thumbprint) == 43


def test_the_thumbprint_ignores_member_order_and_the_stored_jwk_is_the_four_members() -> None:
    j = Device().jwk
    shuffled = {"y": j["y"], "x": j["x"], "crv": j["crv"], "kty": j["kty"]}
    key = validate_public_jwk(shuffled)
    assert list(key.jwk) == ["kty", "crv", "x", "y"] and key.jwk == j


def test_the_thumbprint_changes_with_each_coordinate() -> None:
    a, b = Device().jwk, Device().jwk
    assert thumbprint_of(a) != thumbprint_of(b)
    assert thumbprint_of(a) != thumbprint_of({**a, "x": b["x"]})
    assert thumbprint_of(a) != thumbprint_of({**a, "y": b["y"]})


@pytest.mark.parametrize("extra", ["d", "p", "q", "dp", "dq", "qi", "oth", "k"])
def test_every_private_member_has_its_own_code(extra: str) -> None:
    with pytest.raises(KeyRefused) as error:
        validate_public_jwk({**Device().jwk, extra: "A" * 43})
    assert error.value.code == "jwk_private_member"


def test_the_infinity_and_small_order_encodings_are_not_points() -> None:
    zero = b64(bytes(32))
    for x, y in ((zero, zero), (b64(b"\xff" * 32), b64(b"\xff" * 32)), (zero, b64(b"\x01" * 32))):
        with pytest.raises(KeyRefused) as error:
            validate_public_jwk({"kty": "EC", "crv": "P-256", "x": x, "y": y})
        assert error.value.code == "jwk_not_on_curve"


@pytest.mark.parametrize(
    "value,expected",
    [
        ("https://a.example", ("https", "a.example", 443)),
        ("https://a.example/", ("https", "a.example", 443)),
        ("HTTPS://A.Example:443", ("https", "a.example", 443)),
        ("http://a.example", ("http", "a.example", 80)),
        ("http://127.0.0.1:8000", ("http", "127.0.0.1", 8000)),
        ("http://[::1]:8000", ("http", "::1", 8000)),
    ],
)
def test_origins_are_normalized(value: str, expected: tuple[str, str, int]) -> None:
    assert normalize_origin(value) == expected


@pytest.mark.parametrize(
    "value",
    [
        "", "a.example", "//a.example", "ftp://a.example", "https://", "https://a.example/x",
        "https://a.example?", "https://a.example#", "https://u@a.example", "https://a.example:99999",
        "https://a.example:abc", "https://ä.example", "https://a.example\n", "\thttps://a.example", "https://a. example", None, 3, "x" * 300,
    ],
)  # fmt: skip
def test_things_that_are_not_origins_are_refused(value: Any) -> None:
    with pytest.raises(KeyRefused) as error:
        normalize_origin(value)
    assert error.value.code == "origin_mismatch"


def test_origins_differing_in_scheme_host_or_port_are_different() -> None:
    base = normalize_origin("https://a.example")
    for other in ("http://a.example", "https://b.example", "https://a.example:444"):
        assert normalize_origin(other) != base


def test_origin_text_leaves_the_default_port_out() -> None:
    assert origin_string(normalize_origin("https://A.example:443")) == "https://a.example"
    assert origin_string(normalize_origin("http://a.example:8080")) == "http://a.example:8080"
    assert origin_string(normalize_origin("http://[::1]:80")) == "http://[::1]"


FIELDS: dict[str, Any] = {
    "challenge_id": "kch_" + "A" * 22,
    "nonce": "n" * 43,
    "thumbprint": "t" * 43,
    "customer_id": "cus_" + "B" * 22,
    "origin": "https://a.example",
}


def test_the_record_is_the_jcs_of_a_domain_separated_object() -> None:
    record = registration_record(**FIELDS)
    assert record == (
        b'{"challenge":"' + b"n" * 43 + b'","challenge_id":"kch_' + b"A" * 22
        + b'","customer_id":"cus_' + b"B" * 22 + b'","origin":"https://a.example"'
        + b',"purpose":"countersign.device-key.register.v1","thumbprint":"' + b"t" * 43
        + b'","v":1}'
    )  # fmt: skip
    assert b'"customer_id":null' in registration_record(**{**FIELDS, "customer_id": None})


@given(st.sampled_from(sorted(FIELDS)), st.text(min_size=1, max_size=20))
def test_changing_any_input_changes_the_record(field: str, value: str) -> None:
    changed = {**FIELDS, field: value}
    if changed != FIELDS:
        assert registration_record(**changed) != registration_record(**FIELDS)


def test_a_signature_verifies_only_for_its_key_and_record() -> None:
    a, b = Device(), Device()
    key_a = validate_public_jwk(a.jwk).verifying_key()
    record = registration_record(**FIELDS)
    sig = a.sign(record)
    assert verify_signature(key_a, record, sig)
    assert not verify_signature(key_a, record + b" ", sig)
    assert not verify_signature(validate_public_jwk(b.jwk).verifying_key(), record, sig)


@pytest.mark.parametrize(
    "signature",
    [
        b64(bytes(64)),  # r = s = 0
        b64(b"\xff" * 64),  # r, s above the group order
        b64(bytes(63)),
        b64(bytes(65)),
        "",
        "A" * 86,
        "A" * 85 + "=",
    ],
)
def test_degenerate_signatures_never_verify(signature: str) -> None:
    key = validate_public_jwk(Device().jwk).verifying_key()
    assert not verify_signature(key, registration_record(**FIELDS), signature)


def test_a_non_canonical_spelling_of_a_valid_signature_is_refused() -> None:
    device = Device()
    key = validate_public_jwk(device.jwk).verifying_key()
    record = registration_record(**FIELDS)
    sig = device.sign(record)
    alphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_"
    twin = sig[:-1] + alphabet[alphabet.index(sig[-1]) ^ 1]
    assert verify_signature(key, record, sig) and not verify_signature(key, record, twin)
