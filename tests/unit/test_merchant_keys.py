"""Merchant key rules: every refusal path, and the generated file."""

from __future__ import annotations

import base64
import hashlib
import json
import os
import stat
from pathlib import Path
from typing import Any

import pytest
from cryptography.hazmat.primitives.asymmetric import ec

from countersign.merchant.keys import (
    MerchantKeyError,
    generate_jwk,
    load_merchant_key,
    thumbprint,
    validate_jwk,
    write_key_file,
)


def _b64(b: bytes) -> str:
    return base64.urlsafe_b64encode(b).rstrip(b"=").decode()


def _write(path: Path, obj: Any, mode: int = 0o600) -> Path:
    path.write_text(json.dumps(obj) if not isinstance(obj, str) else obj)
    path.chmod(mode)
    return path


def _other_curve_jwk(curve: ec.EllipticCurve, name: str, size: int) -> dict[str, str]:
    k = ec.generate_private_key(curve)
    n = k.private_numbers()
    return {
        "kty": "EC",
        "crv": name,
        "x": _b64(n.public_numbers.x.to_bytes(size, "big")),
        "y": _b64(n.public_numbers.y.to_bytes(size, "big")),
        "d": _b64(n.private_value.to_bytes(size, "big")),
        "alg": "ES256",
    }


def test_thumbprint_matches_rfc7638_construction() -> None:
    jwk = generate_jwk()
    text = json.dumps(
        {"crv": jwk["crv"], "kty": jwk["kty"], "x": jwk["x"], "y": jwk["y"]},
        sort_keys=True,
        separators=(",", ":"),
    )
    assert jwk["kid"] == _b64(hashlib.sha256(text.encode()).digest())
    assert thumbprint(jwk["x"], jwk["y"]) == jwk["kid"]


def test_thumbprint_agrees_with_joserfc() -> None:
    from joserfc.jwk import ECKey

    jwk = generate_jwk()
    key = ECKey.import_key({m: jwk[m] for m in ("kty", "crv", "x", "y", "d")})
    assert key.thumbprint() == jwk["kid"]


def test_generated_key_loads(tmp_path: Path) -> None:
    path = tmp_path / "k.json"
    kid = write_key_file(path)
    key = load_merchant_key(path)
    assert key.kid == kid
    assert set(key.public_jwk) == {"kty", "crv", "x", "y", "alg", "use", "kid"}
    assert stat.S_IMODE(os.stat(path).st_mode) == 0o600


def test_write_refuses_to_overwrite(tmp_path: Path) -> None:
    path = tmp_path / "k.json"
    write_key_file(path)
    before = path.read_bytes()
    with pytest.raises(MerchantKeyError):
        write_key_file(path)
    assert path.read_bytes() == before


def test_missing_file_refused(tmp_path: Path) -> None:
    with pytest.raises(MerchantKeyError, match="missing"):
        load_merchant_key(tmp_path / "nope.json")


def test_symlink_refused(tmp_path: Path) -> None:
    real = tmp_path / "real.json"
    write_key_file(real)
    link = tmp_path / "link.json"
    link.symlink_to(real)
    with pytest.raises(MerchantKeyError, match="regular file"):
        load_merchant_key(link)


@pytest.mark.parametrize("mode", [0o640, 0o604, 0o644, 0o660, 0o666, 0o607])
def test_loose_permissions_refused(tmp_path: Path, mode: int) -> None:
    path = _write(tmp_path / "k.json", generate_jwk(), mode)
    with pytest.raises(MerchantKeyError, match="owner only"):
        load_merchant_key(path)


def test_duplicate_keys_refused(tmp_path: Path) -> None:
    jwk = generate_jwk()
    text = json.dumps(jwk)[:-1] + ', "kty": "EC"}'
    with pytest.raises(MerchantKeyError, match="strict JSON"):
        load_merchant_key(_write(tmp_path / "k.json", text))


@pytest.mark.parametrize("text", ["", "not json", "[]", "[1]", "null", '"s"'])
def test_non_object_refused(tmp_path: Path, text: str) -> None:
    with pytest.raises(MerchantKeyError):
        load_merchant_key(_write(tmp_path / "k.json", text))


def _mut(**changes: Any) -> dict[str, Any]:
    jwk: dict[str, Any] = generate_jwk()
    for k, v in changes.items():
        if v is None:
            jwk.pop(k)
        else:
            jwk[k] = v
    return jwk


@pytest.mark.parametrize(
    ("changes", "match"),
    [
        ({"kty": "OKP"}, "kty"),
        ({"kty": None}, "kty"),
        ({"kty": "ec"}, "kty"),
        ({"crv": "P-384"}, "crv"),
        ({"crv": "Ed25519"}, "crv"),
        ({"crv": None}, "crv"),
        ({"alg": "ES384"}, "alg"),
        ({"alg": "none"}, "alg"),
        ({"alg": "EdDSA"}, "alg"),
        ({"alg": None}, "alg"),
        ({"use": "enc"}, "use"),
        ({"extra": "x"}, "allowed set"),
        ({"p": "x"}, "allowed set"),
        ({"key_ops": ["sign"]}, "allowed set"),
        ({"x": "short"}, "member x"),
        ({"y": 5}, "member y"),
        ({"d": None}, "member d"),
        ({"d": "A" * 44}, "member d"),
        ({"x": "!" * 43}, "base64url"),
        ({"kid": "chosen"}, "kid"),
        ({"kid": None}, "kid"),
        ({"kid": 7}, "kid"),
    ],
)
def test_rule_violations_refused(changes: dict[str, Any], match: str) -> None:
    with pytest.raises(MerchantKeyError, match=match):
        validate_jwk(_mut(**changes))


def test_use_may_be_absent() -> None:
    assert validate_jwk(_mut(use=None)).kid


def test_p384_key_with_matching_kid_refused() -> None:
    jwk = _other_curve_jwk(ec.SECP384R1(), "P-384", 48)
    with pytest.raises(MerchantKeyError):
        validate_jwk(jwk)


def test_p256_label_on_another_curve_refused() -> None:
    # Wrong-size coordinates under the P-256 label.
    jwk = _other_curve_jwk(ec.SECP384R1(), "P-256", 48)
    with pytest.raises(MerchantKeyError):
        validate_jwk(jwk)


def test_edited_public_point_refused() -> None:
    a, b = generate_jwk(), generate_jwk()
    jwk = dict(a)
    jwk["x"], jwk["y"] = b["x"], b["y"]
    jwk["kid"] = thumbprint(b["x"], b["y"])  # kid consistent with the edit
    with pytest.raises(MerchantKeyError):
        validate_jwk(jwk)


def test_swapped_private_scalar_refused() -> None:
    a, b = generate_jwk(), generate_jwk()
    jwk = dict(a)
    jwk["d"] = b["d"]
    with pytest.raises(MerchantKeyError, match="match"):
        validate_jwk(jwk)


def test_point_not_on_curve_refused() -> None:
    jwk = generate_jwk()
    jwk["y"] = _b64(b"\x01" * 32)
    jwk["kid"] = thumbprint(jwk["x"], jwk["y"])
    with pytest.raises(MerchantKeyError):
        validate_jwk(jwk)


def test_repr_never_shows_private_material() -> None:
    jwk = generate_jwk()
    key = validate_jwk(jwk)
    text = repr(key) + str(key)
    assert jwk["d"] not in text and "private" not in text.lower()


def test_error_messages_do_not_echo_values() -> None:
    jwk = generate_jwk()
    jwk["alg"] = "SECRET-LOOKING-VALUE"
    with pytest.raises(MerchantKeyError) as exc:
        validate_jwk(jwk)
    assert "SECRET-LOOKING-VALUE" not in str(exc.value)


def test_signing_with_loaded_key_verifies_with_public_jwk(tmp_path: Path) -> None:
    from joserfc import jws
    from joserfc.jwk import ECKey

    path = tmp_path / "k.json"
    write_key_file(path)
    key = load_merchant_key(path)
    token = jws.serialize_compact(
        {"alg": "ES256", "kid": key.kid}, b"payload", key.private_key, algorithms=["ES256"]
    )
    pub = ECKey.import_key(key.public_jwk)
    assert jws.deserialize_compact(token, pub, algorithms=["ES256"]).payload == b"payload"


def test_directory_refused(tmp_path: Path) -> None:
    d = tmp_path / "dir"
    d.mkdir(mode=0o700)
    with pytest.raises(MerchantKeyError, match="regular file"):
        load_merchant_key(d)


def test_edited_x_only_refused_as_mismatch() -> None:
    a, b = generate_jwk(), generate_jwk()
    jwk = {**a, "x": b["x"]}
    jwk["kid"] = thumbprint(jwk["x"], jwk["y"])
    with pytest.raises(MerchantKeyError, match="do not match"):
        validate_jwk(jwk)


def test_edited_y_only_refused_as_mismatch() -> None:
    a, b = generate_jwk(), generate_jwk()
    jwk = {**a, "y": b["y"]}
    jwk["kid"] = thumbprint(jwk["x"], jwk["y"])
    with pytest.raises(MerchantKeyError, match="do not match"):
        validate_jwk(jwk)


_P256_ORDER = 0xFFFFFFFF00000000FFFFFFFFFFFFFFFFBCE6FAADA7179E84F3B9CAC2FC632551


@pytest.mark.parametrize("scalar", [0, _P256_ORDER, _P256_ORDER + 1])
def test_invalid_scalar_refused(scalar: int) -> None:
    jwk = {**generate_jwk(), "d": _b64(scalar.to_bytes(32, "big"))}
    with pytest.raises(MerchantKeyError, match="scalar"):
        validate_jwk(jwk)


def test_integer_kid_refused() -> None:
    with pytest.raises(MerchantKeyError, match="kid"):
        validate_jwk({**generate_jwk(), "kid": 1})
