"""The shared mandate vectors: valid ones verify, every invalid one fails at the named step.

The same file is consumed by scripts/mandate_chain_check.mjs (make interop). Expected codes were
written by hand in tests/mandate_vectors.py, not read back from the verifier.
"""

from __future__ import annotations

import pytest

from countersign.mandates.errors import MandateError, MandateJsonError
from tests.mandate_vector_io import load_vectors, verify_vector

VECTORS = load_vectors()

# Every defect class the P2.1 scope names must keep a vector, so none can be dropped quietly.
REQUIRED = {
    "valid-checkout-chain",
    "valid-payment-chain",
    "valid-three-link-chain",
    "bad-b64-jwt-header",
    "bad-b64-disclosure",
    "noncanonical-signature-base64",
    "jwt-two-segments",
    "single-tilde-between-links",
    "triple-tilde-between-links",
    "whitespace-inside",
    "whitespace-trailing-newline",
    "missing-trailing-tilde",
    "truncated-disclosure",
    "duplicate-disclosure",
    "disclosure-unreferenced-open",
    "disclosure-tampered-open-exp",
    "sd-hash-without-trailing-tilde",
    "splice-kb-of-other-credential",
    "open-disclosure-dropped-after-binding",
    "kb-wrong-audience",
    "kb-wrong-nonce",
    "expired-by-61",
    "valid-exp-skew-60",
    "not-yet-valid-61",
    "valid-nbf-skew-60",
    "vct-uppercase",
    "vct-prefix",
    "vct-wrong-version",
    "vct-missing-open",
    "cnf-missing",
    "cnf-jwk-off-curve",
    "cnf-jwk-private-d",
    "open-alg-none",
    "open-alg-hs256",
    "kb-alg-none",
    "kb-alg-hs256",
    "kb-signed-by-stranger",
    "json-duplicate-key-header",
    "json-nan-payload",
    "json-duplicate-key-disclosure",
}


def test_required_vectors_are_present() -> None:
    ids = {v["id"] for v in VECTORS}
    assert REQUIRED <= ids
    assert len(ids) == len(VECTORS)


def test_alg_swap_vectors_cover_every_forbidden_family() -> None:
    ids = " ".join(v["id"] for v in VECTORS)
    for alg in ("es384", "es512", "eddsa", "rs256", "hs384"):
        assert f"open-alg-swap-{alg}" in ids
    assert "kb-alg-swap-es384" in ids


@pytest.mark.parametrize("vector", VECTORS, ids=[v["id"] for v in VECTORS])
def test_vector(vector: dict) -> None:
    expect = vector["expect"]
    if expect["ok"]:
        chain = verify_vector(vector)
        assert [link.vct for link in chain.links] == vector["expected_vcts"]
        return
    with pytest.raises(MandateError) as caught:
        verify_vector(vector)
    assert caught.value.code == expect["code"], vector["description"]
    if "detail" in expect:
        assert isinstance(caught.value, MandateJsonError)
        assert caught.value.json_code == expect["detail"]
