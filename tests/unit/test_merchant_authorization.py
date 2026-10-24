"""merchant_authorization: signing, verification, and every way to break it."""

from __future__ import annotations

import base64
import copy
import json
from typing import Any

import pytest
from hypothesis import given
from hypothesis import strategies as st
from joserfc import jws
from joserfc.jwk import ECKey

from countersign.canonical.hashing import b64url, checkout_hash
from countersign.canonical.jcs import canonicalize
from countersign.canonical.models import Checkout, Item
from countersign.canonical.money import Money
from countersign.merchant.authorization import (
    INVALID,
    MISSING,
    AuthorizationError,
    checkout_jwt,
    sign_checkout,
    verify_authorization,
)
from countersign.merchant.keys import MerchantKey, generate_jwk, validate_jwk
from countersign.protocols.ucp import messages as m
from countersign.protocols.ucp.checkout_state import Status
from countersign.protocols.ucp.responses import checkout_response


def _key() -> MerchantKey:
    return validate_jwk(generate_jwk())


KEY = _key()
OTHER = _key()
PUBLISHED = [KEY.public_jwk]


def _body(messages: list[dict[str, Any]] | None = None) -> dict[str, Any]:
    a = Item(id="sku-a", title="Alpha", price=Money("USD", 250))
    b = Item(id="sku-b", title="Beta", price=Money("USD", 1999))
    checkout = Checkout.from_lines(
        "chk_abcdefghijklmnopqrstuv", "USD", [("li_1", a, 2), ("li_2", b, 1)]
    )
    return checkout_response(checkout, Status.READY_FOR_COMPLETE, 1_800_000_000_000_000, messages)


def signed(body: dict[str, Any] | None = None, key: MerchantKey = KEY) -> dict[str, Any]:
    return sign_checkout(body or _body(), key)


def seg(raw: bytes) -> str:
    return b64url(raw)


def unseg(text: str) -> bytes:
    return base64.urlsafe_b64decode(text + "=" * (-len(text) % 4))


def parts(body: dict[str, Any]) -> tuple[str, str]:
    header, _, signature = body["ap2"]["merchant_authorization"].split(".")
    return header, signature


def with_authorization(body: dict[str, Any], value: Any) -> dict[str, Any]:
    out = copy.deepcopy(body)
    out["ap2"] = {"merchant_authorization": value}
    return out


def rejects(
    body: Any, keys: Any = PUBLISHED, code: str = INVALID, match: str | None = None
) -> AuthorizationError:
    with pytest.raises(AuthorizationError, match=match) as exc:
        verify_authorization(body, keys)
    assert exc.value.code == code
    return exc.value


# ---------------- signing ----------------


def test_sign_and_verify_round_trip() -> None:
    body = signed()
    result = verify_authorization(body, PUBLISHED)
    assert result.kid == KEY.kid
    covered = {k: v for k, v in body.items() if k != "ap2"}
    assert result.payload == canonicalize(covered)


def test_value_is_a_detached_jws_with_exactly_alg_and_kid() -> None:
    value = signed()["ap2"]["merchant_authorization"]
    header, middle, signature = value.split(".")
    assert middle == "" and value.count(".") == 2
    assert unseg(header) == f'{{"alg":"ES256","kid":"{KEY.kid}"}}'.encode()
    assert len(unseg(signature)) == 64
    assert "=" not in value


def test_signature_covers_every_member_except_ap2_including_ucp_and_messages() -> None:
    msg = m.warning_message("field_ignored", "x", "$.id")
    body = signed(_body([msg]))
    covered = json.loads(verify_authorization(body, PUBLISHED).payload)
    assert set(covered) == set(body) - {"ap2"}
    assert "ucp" in covered and covered["messages"] == [msg] and "expires_at" in covered


def test_signing_does_not_mutate_the_input_and_keeps_other_ap2_members() -> None:
    body = _body()
    body["ap2"] = {"future": 1, "merchant_authorization": "old"}
    before = copy.deepcopy(body)
    out = sign_checkout(body, KEY)
    assert body == before
    assert out["ap2"]["future"] == 1 and out["ap2"]["merchant_authorization"] != "old"
    verify_authorization(out, PUBLISHED)


def test_ap2_members_other_than_the_signature_are_outside_the_signature() -> None:
    body = signed()
    body["ap2"]["checkout_mandate"] = "anything~"
    body["ap2"]["future"] = {"a": 1}
    verify_authorization(body, PUBLISHED)


def test_ecdsa_is_not_deterministic_but_every_signature_verifies() -> None:
    a, b = signed(), signed()
    assert a["ap2"] != b["ap2"]
    verify_authorization(a, PUBLISHED)
    verify_authorization(b, PUBLISHED)


def test_key_order_and_whitespace_do_not_matter() -> None:
    body = signed()
    scrambled = json.loads(json.dumps(body, sort_keys=True, indent=3))
    assert list(scrambled) != list(body)
    verify_authorization(scrambled, PUBLISHED)
    reversed_body = dict(reversed(list(body.items())))
    verify_authorization(reversed_body, PUBLISHED)


def test_a_body_with_no_canonical_form_cannot_be_signed() -> None:
    body = _body()
    body["totals"] = [{"type": "total", "amount": 1.5}, {"x": float("nan")}]
    with pytest.raises(AuthorizationError) as exc:
        sign_checkout(body, KEY)
    assert exc.value.code == INVALID


# ---------------- checkout_jwt ----------------


def test_checkout_jwt_is_the_same_signature_with_the_payload_attached() -> None:
    body = signed()
    jwt = checkout_jwt(body)
    header, payload, signature = jwt.split(".")
    assert (header, signature) == parts(body)
    assert unseg(payload) == verify_authorization(body, PUBLISHED).payload
    assert verify_authorization(body, PUBLISHED).checkout_jwt == jwt


def test_checkout_jwt_verifies_as_a_standard_compact_jws() -> None:
    jwt = checkout_jwt(signed())
    pub = ECKey.import_key(KEY.public_jwk)
    result = jws.deserialize_compact(jwt, pub, algorithms=["ES256"])
    assert result.protected == {"alg": "ES256", "kid": KEY.kid}
    assert "typ" not in result.protected


def test_checkout_hash_accepts_the_rebuilt_jwt_and_changes_with_the_checkout() -> None:
    a, b = checkout_jwt(signed()), checkout_jwt(signed())
    assert checkout_hash(a) == b64url(__import__("hashlib").sha256(a.encode("ascii")).digest())
    assert checkout_hash(a) != checkout_hash(b)  # different signatures, different JWT strings


def test_checkout_jwt_refuses_malformed_input() -> None:
    with pytest.raises(AuthorizationError) as exc:
        checkout_jwt(_body())
    assert exc.value.code == MISSING
    for value in ("a.b.c", "x..y", "", 5, None):
        with pytest.raises(AuthorizationError):
            checkout_jwt(with_authorization(_body(), value))
    good_signature = seg(bytes(64))
    # A well-formed value whose header is not exactly {alg, kid}, or whose signature is not
    # canonical base64url, must not yield a JWT-looking string.
    for header in (b"{}", b'{"alg":"ES256"}', b'{"alg":"none","kid":"k"}', b"[]"):
        with pytest.raises(AuthorizationError, match="header|strict JSON"):
            checkout_jwt(with_authorization(_body(), f"{seg(header)}..{good_signature}"))
    header = seg(b'{"alg":"ES256","kid":"k"}')
    alphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_"
    twin = good_signature[:-1] + alphabet[alphabet.index(good_signature[-1]) ^ 1]
    with pytest.raises(AuthorizationError, match="canonical"):
        checkout_jwt(with_authorization(_body(), f"{header}..{twin}"))


# ---------------- tampering with what the signature covers ----------------


def _leaves(node: Any, path: tuple[Any, ...] = ()) -> list[tuple[Any, ...]]:
    if isinstance(node, dict):
        return [p for k, v in node.items() if k != "ap2" for p in _leaves(v, (*path, k))]
    if isinstance(node, list):
        return [p for i, v in enumerate(node) for p in _leaves(v, (*path, i))]
    return [path]


def _get(node: Any, path: tuple[Any, ...]) -> Any:
    for step in path:
        node = node[step]
    return node


def _set(node: Any, path: tuple[Any, ...], value: Any) -> None:
    for step in path[:-1]:
        node = node[step]
    node[path[-1]] = value


def _replacement(old: Any) -> Any:
    if isinstance(old, bool):
        return not old
    if isinstance(old, int):
        return old + 1
    if isinstance(old, str):
        return old + "x"
    return "changed"


SIGNED = signed(_body([m.warning_message("w", "text", "$.a")]))
LEAF_PATHS = _leaves(SIGNED)


def test_every_leaf_is_covered() -> None:
    assert len(LEAF_PATHS) > 30
    for path in LEAF_PATHS:
        body = copy.deepcopy(SIGNED)
        _set(body, path, _replacement(_get(body, path)))
        rejects(body)


def test_adding_or_removing_any_member_breaks_it() -> None:
    for path in LEAF_PATHS:
        body = copy.deepcopy(SIGNED)
        parent = _get(body, path[:-1]) if len(path) > 1 else body
        if isinstance(parent, dict):
            del parent[path[-1]]
            rejects(body)
    body = copy.deepcopy(SIGNED)
    body["extra"] = 1
    rejects(body)
    body = copy.deepcopy(SIGNED)
    body["line_items"][0]["item"]["extra"] = 1
    rejects(body)
    body = copy.deepcopy(SIGNED)
    body["line_items"].append(copy.deepcopy(body["line_items"][0]))
    rejects(body)
    body = copy.deepcopy(SIGNED)
    body["line_items"].reverse()
    rejects(body)
    body = copy.deepcopy(SIGNED)
    body["totals"].pop(0)
    rejects(body)
    body = copy.deepcopy(SIGNED)
    del body["messages"]
    rejects(body)


def test_the_empty_containers_are_covered_too() -> None:
    for member, value in (
        ("links", [{"type": "x", "url": "https://x.test"}]),
        ("links", {}),
        ("ucp", {}),
    ):
        body = copy.deepcopy(SIGNED)
        body[member] = value
        rejects(body)
    body = copy.deepcopy(SIGNED)
    body["ucp"]["payment_handlers"] = {"com.example.pay": []}
    rejects(body)
    body = copy.deepcopy(SIGNED)
    body["ucp"]["capabilities"]["dev.ucp.common.payment.ap2_mandate"] = [{"version": "x"}]
    rejects(body)


def test_a_signature_from_one_checkout_does_not_verify_another() -> None:
    other = _body()
    other["id"] = "chk_ZZZZZZZZZZZZZZZZZZZZZZ"
    forged = copy.deepcopy(other)
    forged["ap2"] = copy.deepcopy(SIGNED["ap2"])
    rejects(forged)


@given(
    index=st.integers(min_value=0, max_value=len(LEAF_PATHS) - 1),
    value=st.one_of(st.integers(), st.text(max_size=8), st.booleans(), st.none()),
)
def test_property_any_single_leaf_change_breaks_verification(index: int, value: Any) -> None:
    path = LEAF_PATHS[index]
    body = copy.deepcopy(SIGNED)
    old = _get(body, path)
    if type(value) is type(old) and value == old:
        return
    if isinstance(value, int) and not isinstance(value, bool) and abs(value) > 2**53 - 1:
        return
    _set(body, path, value)
    rejects(body)


# ---------------- the header ----------------


def forge(header: dict[str, Any] | bytes, body: dict[str, Any] | None = None) -> dict[str, Any]:
    """A response whose signature is valid over `header` as given (signed with the real key)."""
    body = copy.deepcopy(body or signed())
    header_bytes = (
        header if isinstance(header, bytes) else json.dumps(header, separators=(",", ":")).encode()
    )
    payload = canonicalize({k: v for k, v in body.items() if k != "ap2"})
    signing_input = seg(header_bytes) + "." + seg(payload)
    der_key = KEY.private_key.private_key
    from cryptography.hazmat.primitives import hashes
    from cryptography.hazmat.primitives.asymmetric import ec
    from cryptography.hazmat.primitives.asymmetric.utils import decode_dss_signature

    r, s = decode_dss_signature(der_key.sign(signing_input.encode(), ec.ECDSA(hashes.SHA256())))  # type: ignore[union-attr]
    signature = seg(r.to_bytes(32, "big") + s.to_bytes(32, "big"))
    body["ap2"] = {"merchant_authorization": f"{seg(header_bytes)}..{signature}"}
    return body


def test_the_forge_helper_makes_a_valid_response_for_the_good_header() -> None:
    verify_authorization(forge({"alg": "ES256", "kid": KEY.kid}), PUBLISHED)


@pytest.mark.parametrize(
    "alg", ["none", "HS256", "ES384", "ES512", "RS256", "EdDSA", "es256", "", None, 5]
)
def test_only_es256_is_allowed(alg: Any) -> None:
    rejects(forge({"alg": alg, "kid": KEY.kid}), match="algorithm is not allowed")


@pytest.mark.parametrize(
    "extra",
    [
        {"typ": "JWT"},
        {"jwk": {"kty": "EC"}},
        {"jku": "https://evil.test/keys"},
        {"x5u": "https://evil.test/c"},
        {"crit": ["b64"]},
        {"b64": False},
        {"cty": "x"},
        {"zip": "DEF"},
        {"extra": 1},
    ],
)
def test_an_extra_header_member_is_refused_even_with_a_valid_signature(
    extra: dict[str, Any],
) -> None:
    rejects(forge({"alg": "ES256", "kid": KEY.kid, **extra}), match="exactly alg and kid")


@pytest.mark.parametrize("header", [{"alg": "ES256"}, {"kid": "KID"}, {}])
def test_a_missing_header_member_is_refused(header: dict[str, Any]) -> None:
    header = {k: (KEY.kid if v == "KID" else v) for k, v in header.items()}
    rejects(forge(header), match="exactly alg and kid")


@pytest.mark.parametrize("kid", [None, 5, "", ["a"], {"a": 1}])
def test_the_kid_must_be_a_non_empty_string(kid: Any) -> None:
    rejects(forge({"alg": "ES256", "kid": kid}), match="kid must be a non-empty string")


def test_member_order_in_the_header_does_not_matter_when_the_signature_is_over_it() -> None:
    verify_authorization(forge({"kid": KEY.kid, "alg": "ES256"}), PUBLISHED)


@pytest.mark.parametrize(
    "raw",
    [
        b"",
        b"not json",
        b"[]",
        b'"ES256"',
        b"null",
        b'{"alg":"ES256","alg":"ES256","kid":"x"}',
        b'{"alg":"ES256","kid":"x","kid":"y"}',
        b'{"alg":NaN,"kid":"x"}',
        b"\xff\xfe",
    ],
)
def test_a_header_that_is_not_a_strict_json_object_is_refused(raw: bytes) -> None:
    rejects(forge(raw), match="strict JSON|exactly alg and kid|detached")


def test_a_duplicate_member_header_with_the_right_kid_is_refused() -> None:
    raw = f'{{"alg":"ES256","kid":"{KEY.kid}","kid":"{KEY.kid}"}}'.encode()
    rejects(forge(raw), match="strict JSON")


def test_an_unsigned_header_edit_breaks_the_signature() -> None:
    body = signed()
    header, signature = parts(body)
    edited = seg(json.dumps({"kid": KEY.kid, "alg": "ES256"}, separators=(",", ":")).encode())
    assert edited != header
    rejects(with_authorization(body, f"{edited}..{signature}"), match="does not verify")
    padded = f"{header}=..{signature}"
    rejects(with_authorization(body, padded), match="detached")


def test_a_kid_edit_to_another_published_key_fails_the_signature() -> None:
    body = signed()
    keys = [KEY.public_jwk, OTHER.public_jwk]
    swapped = forge({"alg": "ES256", "kid": OTHER.kid}, body)  # signed by KEY, claims OTHER's kid
    rejects(swapped, keys)
    verify_authorization(body, keys)  # the right kid among several keys works


# ---------------------------------------------- the signature ----------------------------------


def test_every_flipped_signature_bit_is_refused() -> None:
    body = signed()
    header, signature = parts(body)
    raw = bytearray(unseg(signature))
    for i in range(0, 64, 3):
        flipped = bytearray(raw)
        flipped[i] ^= 0x01
        rejects(
            with_authorization(body, f"{header}..{seg(bytes(flipped))}"), match="does not verify"
        )


@pytest.mark.parametrize("size", [0, 1, 32, 63, 65, 72, 96])
def test_a_signature_that_is_not_64_bytes_is_refused(size: int) -> None:
    body = signed()
    header, signature = parts(body)
    raw = (unseg(signature) * 2)[:size]
    value = f"{header}..{seg(raw)}" if size else f"{header}.."
    rejects(with_authorization(body, value), match="detached" if size == 0 else "64 bytes")


def test_zero_and_swapped_halves_are_refused() -> None:
    body = signed()
    header, signature = parts(body)
    raw = unseg(signature)
    rejects(with_authorization(body, f"{header}..{seg(bytes(64))}"), match="does not verify")
    rejects(
        with_authorization(body, f"{header}..{seg(raw[32:] + raw[:32])}"), match="does not verify"
    )


def test_non_canonical_base64_is_refused() -> None:
    body = signed()
    header, signature = parts(body)
    # The last character of an unpadded 64 byte value carries two spare bits; setting them gives a
    # different text that decodes to the same bytes.
    alphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_"
    last = alphabet.index(signature[-1])
    twin = alphabet[last ^ 1]
    assert unseg(signature[:-1] + twin) == unseg(signature)
    rejects(with_authorization(body, f"{header}..{signature[:-1]}{twin}"), match="canonical")


# ---------------------------------------------- the published keys ------------------------------


def test_a_kid_that_is_not_published_is_refused() -> None:
    body = signed()
    rejects(body, [], match="exactly one published key")
    rejects(body, [OTHER.public_jwk], match="exactly one published key")
    rejects(body, [{**KEY.public_jwk, "kid": "other"}], match="exactly one published key")


def test_a_duplicated_kid_is_ambiguous_and_refused() -> None:
    rejects(signed(), [KEY.public_jwk, KEY.public_jwk], match="exactly one published key")
    other = {**OTHER.public_jwk, "kid": KEY.kid}
    rejects(signed(), [KEY.public_jwk, other], match="exactly one published key")


@pytest.mark.parametrize(
    ("change", "match"),
    [
        ({"d": "x"}, "private"),
        ({"p": "x"}, "private"),
        ({"kty": "RSA"}, "EC P-256"),
        ({"kty": "OKP"}, "EC P-256"),
        ({"crv": "P-384"}, "EC P-256"),
        ({"crv": "Ed25519"}, "EC P-256"),
        ({"alg": "ES384"}, "ES256 signature key"),
        ({"alg": "none"}, "ES256 signature key"),
        ({"use": "enc"}, "ES256 signature key"),
    ],
)
def test_an_unsuitable_published_key_is_refused(change: dict[str, Any], match: str) -> None:
    rejects(signed(), [{**KEY.public_jwk, **change}], match=match)


def test_a_published_key_may_omit_alg_and_use() -> None:
    bare = {m_: KEY.public_jwk[m_] for m_ in ("kty", "crv", "x", "y", "kid")}
    verify_authorization(signed(), [bare])


def test_a_published_key_that_does_not_parse_is_refused() -> None:
    rejects(signed(), [{**KEY.public_jwk, "x": "AAAA"}], match="does not parse")
    rejects(
        signed(), [{k: v for k, v in KEY.public_jwk.items() if k != "y"}], match="does not parse"
    )
    rejects(signed(), ["not a key", 5, None], match="exactly one published key")


def test_the_wrong_key_with_the_right_kid_fails() -> None:
    rejects(signed(), [{**OTHER.public_jwk, "kid": KEY.kid}], match="does not verify")


# ---------------------------------------------- missing and malformed -------------------------


def test_a_response_without_authorization_is_missing() -> None:
    rejects(_body(), code=MISSING)
    rejects({**_body(), "ap2": {}}, code=MISSING)
    rejects({**_body(), "ap2": "x"}, code=MISSING)
    rejects({**_body(), "ap2": None}, code=MISSING)


@pytest.mark.parametrize(
    "value",
    [
        "",
        "a",
        "a.b",
        "a.b.c",
        "..",
        "a..",
        "..b",
        "a...b",
        "a..b.c",
        "a b..c",
        "é..c",
        5,
        None,
        [],
        {},
    ],
)
def test_a_malformed_value_is_invalid(value: Any) -> None:
    rejects(with_authorization(_body(), value), match="detached")


@pytest.mark.parametrize("body", [None, [], "x", 5])
def test_a_non_object_is_invalid(body: Any) -> None:
    rejects(body)


def test_attached_payload_forms_are_refused() -> None:
    jwt = checkout_jwt(signed())
    rejects(with_authorization(_body(), jwt), match="detached")
