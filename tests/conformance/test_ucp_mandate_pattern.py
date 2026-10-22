"""The vendored UCP pattern for ap2.checkout_mandate rejects valid SD-JWT forms.

The JSON Schema for ``ap2.checkout_mandate`` in the vendored UCP release allows only non-empty
base64url elements after the first ``~``. A compact SD-JWT with key binding ends in a key-binding
JWT, which contains dots. The chained mandate form defined by the Delegate SD-JWT draft needs an
empty element (``~~``). Both are valid under AP2, RFC 9901 and the draft, and both fail the
pattern.

The cases that fail are marked as strict expected failures. When the vendored schema is updated
upstream and the pattern is fixed, they will start passing, the strict marker will make the suite
fail, and the markers (and the workaround described in docs/PROTOCOL.md, Decision 9) should be
removed. Draft of the upstream report: docs/upstream/ucp-mandate-pattern.md.
"""

import base64
import hashlib
import json
import re
from pathlib import Path

import pytest
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ec, utils

ROOT = Path(__file__).resolve().parents[2]
UCP_SCHEMA = ROOT / "spec/vendor/ucp/source/schemas/common/payment_ap2_mandate.json"
AP2_CHECKOUT_DOC = ROOT / "spec/vendor/ap2/docs/checkout_mandate.md"

REASON = (
    "vendored UCP ap2.checkout_mandate pattern does not allow dots or empty elements after the "
    "first '~'; valid SD-JWT+KB and chained mandates are rejected (docs/PROTOCOL.md, Decision 9)"
)


def _b64(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode()


def _jws(header: dict, payload: dict, key: ec.EllipticCurvePrivateKey) -> str:
    signing_input = (
        _b64(json.dumps(header, separators=(",", ":")).encode())
        + "."
        + _b64(json.dumps(payload, separators=(",", ":")).encode())
    )
    der = key.sign(signing_input.encode(), ec.ECDSA(hashes.SHA256()))
    r, s = utils.decode_dss_signature(der)
    return signing_input + "." + _b64(r.to_bytes(32, "big") + s.to_bytes(32, "big"))


def _sd_jwt_with_key_binding() -> str:
    """A small, correctly formed RFC 9901 SD-JWT+KB: issuer JWT, one disclosure, KB-JWT."""
    issuer_key = ec.generate_private_key(ec.SECP256R1())
    holder_key = ec.generate_private_key(ec.SECP256R1())
    numbers = holder_key.public_key().public_numbers()
    jwk = {
        "kty": "EC",
        "crv": "P-256",
        "x": _b64(numbers.x.to_bytes(32, "big")),
        "y": _b64(numbers.y.to_bytes(32, "big")),
    }
    disclosure = _b64(json.dumps(["salt-0123456789abcd", "given_name", "Alex"]).encode())
    digest = _b64(hashlib.sha256(disclosure.encode("ascii")).digest())
    issuer_jwt = _jws(
        {"alg": "ES256", "typ": "dc+sd-jwt"},
        {"_sd": [digest], "_sd_alg": "sha-256", "cnf": {"jwk": jwk}},
        issuer_key,
    )
    presented = f"{issuer_jwt}~{disclosure}~"
    sd_hash = _b64(hashlib.sha256(presented.encode("ascii")).digest())
    kb_jwt = _jws(
        {"alg": "ES256", "typ": "kb+jwt"},
        {"iat": 1777342376, "aud": "merchant", "nonce": "n-0", "sd_hash": sd_hash},
        holder_key,
    )
    return presented + kb_jwt


def _ap2_example_tokens() -> list[str]:
    text = AP2_CHECKOUT_DOC.read_text()
    return re.findall(r"#### Encoded Token\n\n```\n(.+?)\n```", text, re.DOTALL)


@pytest.fixture(scope="module")
def pattern() -> re.Pattern[str]:
    schema = json.loads(UCP_SCHEMA.read_text())
    return re.compile(schema["$defs"]["checkout_mandate"]["pattern"])


def test_ap2_example_tokens_are_located() -> None:
    open_token, closed_token, chained_token = _ap2_example_tokens()
    assert open_token.endswith("~")
    assert chained_token == open_token + "~" + closed_token
    assert "~~" in chained_token


def test_pattern_accepts_a_bare_jwt_and_a_jwt_with_disclosures_but_no_trailing_tilde(
    pattern: re.Pattern[str],
) -> None:
    # Documents what the pattern does accept. A compact JWS, and issuer JWT plus disclosures
    # without the trailing '~' that RFC 9901 requires of a serialized SD-JWT.
    assert pattern.match("aGVhZA.cGF5bG9hZA.c2ln")
    assert pattern.match("aGVhZA.cGF5bG9hZA.c2ln~ZGlzYzE~ZGlzYzI")


def test_generated_sd_jwt_kb_is_well_formed() -> None:
    token = _sd_jwt_with_key_binding()
    issuer_jwt, disclosure, kb_jwt = token.split("~")
    assert issuer_jwt.count(".") == 2
    assert kb_jwt.count(".") == 2
    kb_payload = kb_jwt.split(".")[1]
    claims = json.loads(base64.urlsafe_b64decode(kb_payload + "=" * (-len(kb_payload) % 4)))
    expected = _b64(hashlib.sha256(f"{issuer_jwt}~{disclosure}~".encode("ascii")).digest())
    assert claims["sd_hash"] == expected


@pytest.mark.xfail(strict=True, reason=REASON)
def test_pattern_accepts_standard_sd_jwt_with_key_binding(pattern: re.Pattern[str]) -> None:
    assert pattern.match(_sd_jwt_with_key_binding())


@pytest.mark.xfail(strict=True, reason=REASON)
def test_pattern_accepts_sd_jwt_without_key_binding_in_standard_form(
    pattern: re.Pattern[str],
) -> None:
    # RFC 9901 section 4: an SD-JWT presentation ends with a '~' after the last disclosure.
    assert pattern.match("aGVhZA.cGF5bG9hZA.c2ln~ZGlzYzE~")


@pytest.mark.xfail(strict=True, reason=REASON)
def test_pattern_accepts_ap2_open_mandate_example(pattern: re.Pattern[str]) -> None:
    open_token, _, _ = _ap2_example_tokens()
    assert pattern.match(open_token)


@pytest.mark.xfail(strict=True, reason=REASON)
def test_pattern_accepts_ap2_chained_mandate_example(pattern: re.Pattern[str]) -> None:
    _, _, chained_token = _ap2_example_tokens()
    assert pattern.match(chained_token)
