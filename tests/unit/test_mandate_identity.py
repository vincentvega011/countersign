"""The identity of an issued mandate is a hash of what the issuer signed, never of its presentation.

Decision 86. Anyone can rewrite an ES256 signature as (r, n - s) without the key, and verifiers accept
both, so the digest of the presented serialization is not a stable key for single use, the budget or a
revocation. These tests show the problem (the digests differ) and the fix (the identity does not).
"""

from __future__ import annotations

from joserfc.jwk import ECKey

from countersign.canonical.hashing import sd_hash
from countersign.mandates import VCT_PAYMENT, VCT_PAYMENT_OPEN, mandate_identity, verify_chain
from tests.mandate_issuer import NOW, Keys, issue, malleate_signature, open_identity


def verified(token: str, keys: Keys, nonce: str = "nonce-0001") -> object:
    return verify_chain(
        token,
        issuer_key=ECKey.import_key(keys.issuer.as_dict(private=False)),
        expected_vcts=[VCT_PAYMENT_OPEN, VCT_PAYMENT],
        audience="credential-provider",
        nonce=nonce,
        clock=lambda: float(NOW),
    )


def test_the_identity_matches_an_independent_computation() -> None:
    keys = Keys()
    pair = issue("payment", keys=keys, audience="credential-provider")
    chain = verified(pair.token, keys)
    assert chain.identity == open_identity(pair.open_token, "payment")  # type: ignore[attr-defined]


def test_a_rewritten_signature_changes_the_digest_but_not_the_identity() -> None:
    keys = Keys()
    pair = issue("payment", keys=keys, audience="credential-provider")
    rewritten_open = malleate_signature(pair.open_token)
    again = issue(
        "payment", keys=keys, audience="credential-provider", reuse_open_token=rewritten_open,
        nonce="nonce-0002",
    )  # fmt: skip
    assert rewritten_open != pair.open_token
    first, second = verified(pair.token, keys), verified(again.token, keys, "nonce-0002")
    # The old key (the digest of the presented serialization) is different for the same mandate ...
    assert first.links[0].digest != second.links[0].digest  # type: ignore[attr-defined]
    assert sd_hash(rewritten_open) != sd_hash(pair.open_token)
    # ... and the identity is not.
    assert first.identity == second.identity  # type: ignore[attr-defined]


def test_the_identity_does_not_depend_on_the_key_binding_nonce_or_checkout() -> None:
    keys = Keys()
    one = issue("payment", keys=keys, audience="credential-provider", nonce="nonce-0001")
    two = issue(
        "payment", keys=keys, audience="credential-provider", nonce="nonce-0002",
        reuse_open_token=one.open_token, checkout_jwt_value="e30.e30.e30",
    )  # fmt: skip
    assert (
        verified(one.token, keys).identity  # type: ignore[attr-defined]
        == verified(two.token, keys, "nonce-0002").identity  # type: ignore[attr-defined]
    )


def test_two_issuances_of_the_same_content_have_different_identities() -> None:
    keys = Keys()
    one = issue("payment", keys=keys, audience="credential-provider")
    two = issue("payment", keys=keys, audience="credential-provider")
    assert open_identity(one.open_token, "payment") != open_identity(two.open_token, "payment")


def test_the_identity_depends_on_the_customer_and_the_issuer() -> None:
    keys = Keys()
    base = issue("payment", keys=keys, audience="credential-provider")
    other = issue(
        "payment", keys=keys, audience="credential-provider", sub="cus_BBBBBBBBBBBBBBBBBBBBBB"
    )
    assert open_identity(base.open_token, "payment") != open_identity(other.open_token, "payment")
    payload = {
        "iss": "a",
        "sub": "s",
        "iat": 1,
        "_sd_alg": "sha-256",
        "delegate_payload": [{"...": "x"}],
    }
    assert mandate_identity(payload, VCT_PAYMENT_OPEN) != mandate_identity(
        {**payload, "iss": "b"}, VCT_PAYMENT_OPEN
    )
    assert mandate_identity(payload, VCT_PAYMENT_OPEN) != mandate_identity(
        {**payload, "delegate_payload": [{"...": "y"}]}, VCT_PAYMENT_OPEN
    )
    assert mandate_identity(payload, VCT_PAYMENT_OPEN) != mandate_identity(payload, VCT_PAYMENT)
