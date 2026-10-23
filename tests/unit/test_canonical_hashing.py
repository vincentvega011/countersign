"""Hash helpers: AP2 hashes are plain SHA-256 with no prefix; internal hashes are domain separated."""

from __future__ import annotations

import base64
import hashlib
import json
import re
from pathlib import Path

import pytest

from countersign.canonical import (
    HashInputError,
    b64url,
    checkout_hash,
    domain_hash,
    receipt_reference,
    sd_hash,
    transaction_id,
)

AP2_DOCS = Path(__file__).resolve().parents[2] / "spec/vendor/ap2/docs"


def plain(text: str) -> str:
    return (
        base64.urlsafe_b64encode(hashlib.sha256(text.encode("ascii")).digest())
        .rstrip(b"=")
        .decode()
    )


def test_b64url_is_unpadded_and_url_safe():
    assert b64url(b"\xfb\xff") == "-_8"
    assert b64url(b"") == ""
    assert "=" not in b64url(b"a")


def test_known_sha256_vector():
    # FIPS 180-2 test vector: SHA-256("abc").
    expected = bytes.fromhex("ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad")
    assert b64url(expected) == "ungWv48Bz-pBQUDeXa4iI7ADYaOWF3qctBD_YfIAFa0"
    assert sd_hash("abc~") == plain("abc~")
    assert plain("abc") == "ungWv48Bz-pBQUDeXa4iI7ADYaOWF3qctBD_YfIAFa0"


def test_checkout_hash_is_plain_sha256_of_the_jws_string():
    jwt = "aGVhZGVy.cGF5bG9hZA.c2ln"
    assert checkout_hash(jwt) == plain(jwt)
    assert transaction_id(jwt) == checkout_hash(jwt)


@pytest.mark.parametrize(
    "bad",
    ["", "a.b", "a.b.c.d", "a..c", ".b.c", "a.b.", "a.b.c~", "a.b.c~d~", "hé.p.s"],
)
def test_checkout_hash_rejects_wrong_shapes(bad):
    with pytest.raises(HashInputError):
        checkout_hash(bad)


def test_sd_hash_requires_the_trailing_tilde():
    with pytest.raises(HashInputError):
        sd_hash("a.b.c~d")
    assert sd_hash("a.b.c~d~") == plain("a.b.c~d~")


def test_sd_hash_rejects_non_ascii():
    with pytest.raises(HashInputError):
        sd_hash("café~")


def test_receipt_reference_is_computed_like_sd_hash():
    token = "a.b.c~d~e~"
    assert receipt_reference(token) == sd_hash(token)
    with pytest.raises(HashInputError):
        receipt_reference("a.b.c")


def test_ap2_hashes_carry_no_prefix():
    # If a domain prefix were mixed in, the value would differ from the plain digest.
    text = "x.y.z~"
    assert sd_hash(text) != b64url(domain_hash("cs.test.v1", text.encode()))
    assert sd_hash(text) == b64url(hashlib.sha256(text.encode()).digest())


def test_domain_hash_construction():
    data = b'{"k":1}'
    assert domain_hash("cs.log.v1", data) == hashlib.sha256(b"cs.log.v1\x00" + data).digest()
    assert domain_hash("cs.log.v1", data) != hashlib.sha256(data).digest()
    assert domain_hash("cs.log.v1", data) != domain_hash("cs.log.v2", data)
    assert domain_hash("cs.log.v1", data) != domain_hash("cs.terms.v1", data)
    assert len(domain_hash("cs.log.v1", b"")) == 32


def test_domain_must_end_before_the_nul_separator():
    # A NUL inside the domain is refused, so the first NUL always marks the end of the domain and
    # bytes cannot be shifted between the domain and the data.
    with pytest.raises(HashInputError):
        domain_hash("cs.a.v1\x00b", b"")
    assert domain_hash("cs.a.v1", b"b") != domain_hash("cs.a.v1", b"\x00b")


@pytest.mark.parametrize(
    "domain",
    [
        "",
        "log.v1",
        "cs.log",
        "cs.log.v0",
        "cs.log.v1x",
        "CS.log.v1",
        "cs.Log.v1",
        "cs..v1",
        "cs.log.v1 ",
        "cs.lög.v1",
        "cs.log.v1\n",
        "cs.1log.v1",
    ],
)
def test_invalid_domains_are_rejected(domain):
    with pytest.raises(HashInputError):
        domain_hash(domain, b"x")


@pytest.mark.parametrize("domain", ["cs.log.v1", "cs.terms.v12", "cs.evidence_ref.v3", "cs.a.b.v1"])
def test_valid_domains_are_accepted(domain):
    domain_hash(domain, b"x")


# ---- AP2 worked examples (vendored documents) ----


def example_tokens(doc: str) -> list[str]:
    text = (AP2_DOCS / doc).read_text()
    return re.findall(r"#### Encoded Token\n\n```\n(.+?)\n```", text, re.DOTALL)


def b64d(text: str) -> bytes:
    return base64.urlsafe_b64decode(text + "=" * (-len(text) % 4))


def named_values(token: str) -> dict[str, list[str]]:
    """Collect string values by claim name from JWT payloads and disclosures in a token."""
    found: dict[str, list[str]] = {}

    def walk(node):
        if isinstance(node, dict):
            for key, value in node.items():
                if isinstance(value, str):
                    found.setdefault(key, []).append(value)
                walk(value)
        elif isinstance(node, list):
            if len(node) == 3 and isinstance(node[1], str) and isinstance(node[2], str):
                found.setdefault(node[1], []).append(node[2])
            for item in node:
                walk(item)

    for part in token.split("~"):
        if not part:
            continue
        pieces = part.split(".")
        raw = b64d(pieces[1]) if len(pieces) == 3 else b64d(part)
        walk(json.loads(raw))
    return found


def test_ap2_chained_checkout_mandate_checkout_hash():
    _, _, chain = example_tokens("checkout_mandate.md")
    values = named_values(chain)
    (jwt,) = set(values["checkout_jwt"])
    (expected,) = set(values["checkout_hash"])
    assert checkout_hash(jwt) == expected


def test_ap2_payment_mandate_transaction_id_equals_checkout_hash():
    _, _, checkout_chain = example_tokens("checkout_mandate.md")
    _, _, payment_chain = example_tokens("payment_mandate.md")
    (jwt,) = set(named_values(checkout_chain)["checkout_jwt"])
    (tx,) = set(named_values(payment_chain)["transaction_id"])
    assert transaction_id(jwt) == tx


def test_ap2_payment_reference_digest_is_sd_hash_of_the_open_checkout_mandate():
    open_checkout = example_tokens("checkout_mandate.md")[0]
    open_payment = example_tokens("payment_mandate.md")[0]
    (expected,) = set(named_values(open_payment)["conditional_transaction_id"])
    assert sd_hash(open_checkout) == expected
