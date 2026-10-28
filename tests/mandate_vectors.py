"""Generate tests/vectors/mandates/chain_vectors.json with the test issuer.

    uv run python -m tests.mandate_vectors

Every vector names the expected outcome and, for a rejection, the expected failing step (the
`code` of the typed error). The expectations are written by hand below, never read back from the
verifier, so a verifier bug cannot rewrite its own test. The file is committed and consumed by
both tests/unit/test_mandate_vectors.py (Python) and scripts/mandate_chain_check.mjs (Node).
Signatures are random, so regenerating changes the file; only do it on purpose.
"""

from __future__ import annotations

import base64
import json
from pathlib import Path
from typing import Any

from tests.mandate_issuer import (
    CLOSED_VCT,
    NOW,
    OPEN_VCT,
    Issued,
    Keys,
    b64e,
    compact_json,
    digest,
    issue,
    public_jwk,
)

OUT = Path(__file__).parent / "vectors" / "mandates" / "chain_vectors.json"
ALPHABET = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_"

vectors: list[dict[str, Any]] = []


def add(
    id: str,
    description: str,
    issued: Issued,
    *,
    code: str | None = None,
    detail: str | None = None,
    token: str | None = None,
    now: int | None = None,
    vcts: list[str] | None = None,
    audience: str | None = None,
    nonce: str | None = None,
) -> None:
    assert all(v["id"] != id for v in vectors), id
    expect: dict[str, Any] = {"ok": code is None}
    if code:
        expect["code"] = code
    if detail:
        expect["detail"] = detail
    vectors.append(
        {
            "id": id,
            "description": description,
            "token": token if token is not None else issued.token,
            "issuer_jwk": public_jwk(issued.keys.issuer),
            "expected_vcts": vcts or [OPEN_VCT[issued.kind], CLOSED_VCT[issued.kind]],
            "audience": audience or issued.audience,
            "nonce": nonce or issued.nonce,
            "now": now if now is not None else issued.now,
            "expect": expect,
        }
    )


def links(token: str) -> list[list[str]]:
    """[[jwt, disclosure...], ...] for a well-formed token."""
    return [chunk.split("~") for chunk in token[:-1].split("~~")]


def join(parts: list[list[str]]) -> str:
    return "~~".join("~".join(link) for link in parts) + "~"


def edit_json_disclosure(text: str, edit: Any) -> str:
    padded = text + "=" * (-len(text) % 4)
    value = json.loads(base64.urlsafe_b64decode(padded))
    edit(value)
    return b64e(compact_json(value).encode())


def main() -> None:
    for kind in ("checkout", "payment"):
        i = issue(kind)
        add(f"valid-{kind}-chain", f"Open and closed {kind} mandate, issued and key bound.", i)
    base = issue("checkout")

    # ----- legitimate variations that must verify -----
    def decoys_open(payload: dict[str, Any]) -> None:
        payload["_sd"] = [digest("decoy-1"), digest("decoy-2")]

    def decoys_kb(content: dict[str, Any]) -> None:
        content["_sd"].append(digest("decoy-3"))

    add(
        "valid-decoy-digests",
        "Unmatched digests (decoys or withheld claims) are ignored.",
        issue(edit_open_payload=decoys_open, edit_kb_content=decoys_kb),
    )
    three = issue(hops=3)
    add(
        "valid-three-link-chain",
        "A longer chain: intermediate link typ kb-sd-jwt+kb, final kb+sd-jwt.",
        three,
        vcts=[OPEN_VCT["checkout"], OPEN_VCT["checkout"], CLOSED_VCT["checkout"]],
    )
    exp = NOW + 3600
    add("valid-exp-skew-60", "now is exactly 60 s after exp: inside the skew.", base, now=exp + 60)
    add(
        "valid-nbf-skew-60",
        "nbf is exactly 60 s ahead of now: inside the skew.",
        issue(open_nbf=NOW + 60),
    )
    add(
        "valid-iat-skew-60",
        "iat is exactly 60 s ahead of now: inside the skew.",
        issue(open_iat=NOW + 60, kb_iat=NOW + 60),
    )

    # ----- structure -----
    parts = links(base.token)
    jwt0 = parts[0][0].split(".")
    h, p, s = jwt0

    def with_jwt0(new: str) -> str:
        return join([[new, *parts[0][1:]], parts[1]])

    add(
        "bad-b64-jwt-header",
        "Header segment of length 1 mod 4.",
        base,
        code="structure_base64url",
        token=with_jwt0(f"A.{p}.{s}"),
    )
    add(
        "bad-b64-jwt-payload",
        "Payload segment of length 1 mod 4.",
        base,
        code="structure_base64url",
        token=with_jwt0(f"{h}.A.{s}"),
    )
    sig_tail = ALPHABET[ALPHABET.index(s[-1]) | 1]
    add(
        "noncanonical-signature-base64",
        "Last signature character changed in its unused bits: same decoded bytes, different text.",
        base,
        code="structure_base64url",
        token=with_jwt0(f"{h}.{p}.{s[:-1]}{sig_tail}"),
    )
    bad_disc = [list(parts[0]), list(parts[1])]
    bad_disc[0][-1] = "AAAAA"
    add(
        "bad-b64-disclosure",
        "A disclosure of length 1 mod 4.",
        base,
        code="structure_base64url",
        token=join(bad_disc),
    )
    add(
        "jwt-two-segments",
        "A JWT with only two segments.",
        base,
        code="structure_segments",
        token=with_jwt0(f"{h}.{p}"),
    )
    add(
        "jwt-four-segments",
        "A JWT with four segments.",
        base,
        code="structure_segments",
        token=with_jwt0(f"{h}.{p}.{s}.{s}"),
    )
    add(
        "single-tilde-between-links",
        "'~' instead of '~~' between links.",
        base,
        code="structure_separator",
        token=base.token.replace("~~", "~", 1),
    )
    add(
        "triple-tilde-between-links",
        "'~~~' between links.",
        base,
        code="structure_separator",
        token=base.token.replace("~~", "~~~", 1),
    )
    add(
        "dangling-separator",
        "A '~~' with no JWT after it.",
        base,
        code="structure_separator",
        token=base.open_token + "~",
    )
    add("empty-string", "The empty string.", base, code="structure_separator", token="")
    add(
        "whitespace-inside",
        "A space inside the token.",
        base,
        code="structure_charset",
        token=base.token.replace("~", "~ ", 1),
    )
    add(
        "whitespace-trailing-newline",
        "A trailing newline.",
        base,
        code="structure_charset",
        token=base.token + "\n",
    )
    add(
        "whitespace-leading",
        "A leading space.",
        base,
        code="structure_charset",
        token=" " + base.token,
    )
    add(
        "tab-inside",
        "A tab inside the token.",
        base,
        code="structure_charset",
        token=base.token.replace("~", "~\t", 1),
    )
    add(
        "padding-character",
        "A base64 padding '=' character.",
        base,
        code="structure_charset",
        token=base.token.replace("~", "=~", 1),
    )
    add(
        "non-ascii",
        "A non-ASCII character.",
        base,
        code="structure_charset",
        token=base.token[:-3] + "é" + base.token[-3:],
    )
    add(
        "missing-trailing-tilde",
        "The final '~' removed.",
        base,
        code="structure_trailing_tilde",
        token=base.token[:-1],
    )
    add(
        "cut-in-disclosure",
        "The token cut off in the middle of the last disclosure.",
        base,
        code="structure_trailing_tilde",
        token=base.token[:-9],
    )
    add(
        "trailing-key-binding-jwt",
        "A trailing delegate key-binding JWT (dSD-JWT+KB).",
        base,
        code="structure_trailing_kb",
        token=base.token + f"{h}.{p}.{s}",
    )
    cut = [list(parts[0]), list(parts[1])]
    cut[1][-1] = cut[1][-1][:-4]
    add(
        "truncated-disclosure",
        "The last disclosure cut short but still base64url.",
        base,
        code="json_invalid",
        detail="json_syntax",
        token=join(cut),
    )
    dup = [list(parts[0]) + [parts[0][1]], parts[1]]
    add(
        "duplicate-disclosure",
        "A disclosure presented twice in one link.",
        base,
        code="structure_duplicate_disclosure",
        token=join(dup),
    )
    add(
        "chain-too-short",
        "Only the open mandate where two links are expected.",
        base,
        code="structure_chain_length",
        token=base.open_token,
    )
    add(
        "chain-too-long",
        "Three links where two are expected.",
        three,
        code="structure_chain_length",
    )
    add(
        "one-link-expected",
        "Two links where one is expected.",
        base,
        code="structure_chain_length",
        vcts=[OPEN_VCT["checkout"]],
    )

    # ----- algorithms -----
    def alg_case(id: str, desc: str, **kwargs: Any) -> None:
        add(id, desc, issue(**kwargs), code="alg_not_allowed")

    alg_case(
        "open-alg-none",
        "alg none, empty signature, in the issuer JWT.",
        issuer_alg_header="none",
        issuer_sign_alg="none",
    )
    alg_case(
        "open-alg-hs256",
        "HS256 signed with the public key as the secret, issuer JWT.",
        issuer_alg_header="HS256",
        issuer_sign_alg="HS256",
    )
    for alg in ("ES384", "ES512", "EdDSA", "RS256", "PS256", "HS384", "es256", "ES256 ", "none"):
        alg_case(
            f"open-alg-swap-{alg.strip().lower()}-{len(alg)}",
            f"Header alg changed to {alg!r}, ES256 signature kept (issuer JWT).",
            issuer_alg_header=alg,
        )
    alg_case(
        "open-alg-missing",
        "No alg in the issuer header.",
        issuer_header=compact_json({"typ": "dc+sd-jwt"}),
    )
    alg_case(
        "open-alg-not-string",
        "alg is a list.",
        issuer_header=compact_json({"alg": ["ES256"], "typ": "dc+sd-jwt"}),
    )
    alg_case(
        "kb-alg-none", "alg none in the key-binding JWT.", kb_alg_header="none", kb_sign_alg="none"
    )
    alg_case(
        "kb-alg-hs256",
        "HS256 in the key-binding JWT, signed with the cnf public key.",
        kb_alg_header="HS256",
        kb_sign_alg="HS256",
    )
    for alg in ("ES384", "ES512", "EdDSA", "RS256"):
        alg_case(
            f"kb-alg-swap-{alg.lower()}",
            f"Header alg changed to {alg} in the KB JWT only.",
            kb_alg_header=alg,
        )

    # ----- header parameters and typ -----
    for name, value in (
        ("crit", ["exp"]),
        ("b64", False),
        ("zip", "DEF"),
        ("jwk", public_jwk(base.keys.stranger)),
        ("jku", "https://x.example/k"),
    ):
        add(
            f"open-header-{name}",
            f"Forbidden header parameter {name} in the issuer JWT.",
            issue(issuer_header_extra={name: value}),
            code="header_invalid",
        )
    add(
        "kb-header-x5c",
        "Forbidden header parameter x5c in the KB JWT.",
        issue(kb_header_extra={"x5c": ["AAAA"]}),
        code="header_invalid",
    )
    for typ in ("JWT", "example+sd-jwt", "kb+sd-jwt", "dc+sd-jwt+kb"):
        add(
            f"open-typ-{typ}",
            f"Issuer JWT typ {typ!r}.",
            issue(issuer_typ=typ),
            code="typ_mismatch",
        )
    for typ in ("kb+jwt", "kb-sd-jwt+kb", "dc+sd-jwt", "KB+SD-JWT"):
        add(
            f"kb-typ-{typ}",
            f"Final key-binding JWT typ {typ!r}.",
            issue(kb_typ=typ),
            code="typ_mismatch",
        )

    # ----- signatures and keys -----
    add(
        "open-signed-by-stranger",
        "Issuer JWT signed by a key the verifier does not trust.",
        issue(issuer_signer=Keys().stranger),
        code="signature_invalid",
    )
    add(
        "kb-signed-by-stranger",
        "Key binding signed by a key other than the open mandate cnf.",
        issue(kb_signer=Keys().stranger),
        code="signature_invalid",
    )
    other_agent = Keys()
    keys_two = Keys()
    add(
        "kb-signed-by-other-agent-key",
        "Key binding signed by another real agent key.",
        issue(keys=keys_two, kb_signer=other_agent.agent),
        code="signature_invalid",
    )
    add(
        "signature-truncated",
        "Signature cut by four characters (still base64url).",
        base,
        code="signature_invalid",
        token=with_jwt0(f"{h}.{p}.{s[:-2]}"),
    )
    add(
        "signature-empty-with-es256",
        "Empty signature segment with alg ES256.",
        base,
        code="signature_invalid",
        token=with_jwt0(f"{h}.{p}."),
    )

    # ----- strict JSON -----
    hdr = '{"alg":"ES256","typ":"dc+sd-jwt","alg":"ES256"}'
    add(
        "json-duplicate-key-header",
        "Duplicate key in the issuer header.",
        issue(issuer_header=hdr),
        code="json_invalid",
        detail="json_duplicate_key",
    )
    add(
        "json-duplicate-key-payload",
        "Duplicate key in the issuer payload.",
        issue(open_payload_text='{"iss":"a","iss":"b","delegate_payload":[]}'),
        code="json_invalid",
        detail="json_duplicate_key",
    )
    add(
        "json-nan-payload",
        "NaN in the issuer payload.",
        issue(open_payload_text='{"iss":"a","nbf":NaN,"delegate_payload":[]}'),
        code="json_invalid",
        detail="json_non_finite",
    )
    add(
        "json-infinity-payload",
        "Infinity in the issuer payload.",
        issue(open_payload_text='{"iss":"a","nbf":Infinity,"delegate_payload":[]}'),
        code="json_invalid",
        detail="json_non_finite",
    )
    add(
        "json-syntax-payload",
        "Truncated JSON in the issuer payload.",
        issue(open_payload_text='{"iss":"a",'),
        code="json_invalid",
        detail="json_syntax",
    )
    add(
        "json-payload-not-object",
        "The issuer payload is an array.",
        issue(open_payload_text="[]"),
        code="payload_shape",
    )
    dup_disc = b64e(b'["salt",{"vct":"a","vct":"b"}]')
    add(
        "json-duplicate-key-disclosure",
        "Duplicate key inside a disclosure.",
        issue(kb_disclosure_text=dup_disc),
        code="json_invalid",
        detail="json_duplicate_key",
    )
    add(
        "json-duplicate-key-kb-payload",
        "Duplicate key in the key-binding payload.",
        issue(kb_payload_text='{"aud":"merchant","aud":"merchant"}'),
        code="json_invalid",
        detail="json_duplicate_key",
    )

    # ----- disclosures -----
    for text, why in (
        (b'["s","n","v","extra"]', "four elements"),
        (b'["s","_sd","v"]', "reserved name _sd"),
        (b'["s","...","v"]', "reserved name ..."),
        (b'{"a":1}', "not an array"),
        (b'[1,"v"]', "non-string salt"),
    ):
        add(
            f"disclosure-malformed-{why.replace(' ', '-')}",
            f"Disclosure with {why}.",
            issue(kb_disclosure_text=b64e(text)),
            code="disclosure_malformed",
        )
    add(
        "disclosure-unreferenced-open",
        "An extra, unreferenced disclosure in the open link.",
        issue(extra_open_disclosures=1),
        code="disclosure_unreferenced",
    )
    add(
        "disclosure-unreferenced-kb",
        "An extra, unreferenced disclosure in the KB link.",
        issue(extra_kb_disclosures=1),
        code="disclosure_unreferenced",
    )
    tampered = [list(parts[0]), list(parts[1])]
    tampered[0][-1] = edit_json_disclosure(
        parts[0][-1], lambda v: v[1].__setitem__("exp", v[1]["exp"] + 10_000_000)
    )
    add(
        "disclosure-tampered-open-exp",
        "exp inside the open mandate disclosure raised: its digest "
        "no longer matches the signed one.",
        base,
        code="disclosure_unreferenced",
        token=join(tampered),
    )
    tampered = [list(parts[0]), list(parts[1])]
    tampered[1][-1] = edit_json_disclosure(
        parts[1][-1], lambda v: v[1].__setitem__("checkout_hash", digest("other"))
    )
    add(
        "disclosure-tampered-closed-hash",
        "checkout_hash inside the closed mandate disclosure replaced.",
        base,
        code="disclosure_unreferenced",
        token=join(tampered),
    )

    def dup_digest(payload: dict[str, Any]) -> None:
        payload["delegate_payload"] = payload["delegate_payload"] * 2

    add(
        "disclosure-duplicate-digest",
        "The same digest twice in the signed payload.",
        issue(edit_open_payload=dup_digest),
        code="disclosure_duplicate_digest",
    )

    def collide(content: dict[str, Any]) -> None:
        content["checkout_jwt"] = "plaintext"

    add(
        "disclosure-claim-collision",
        "A disclosed name equal to a plaintext claim.",
        issue(edit_kb_content=collide),
        code="disclosure_claim_collision",
    )

    def sha512(payload: dict[str, Any]) -> None:
        payload["_sd_alg"] = "sha-512"

    add(
        "sd-alg-sha512",
        "_sd_alg other than sha-256.",
        issue(edit_open_payload=sha512),
        code="sd_alg_unsupported",
    )

    # ----- delegate payload -----
    add(
        "delegate-plaintext-element",
        "A plaintext delegate_payload element, not a disclosure.",
        issue(plaintext_delegate=True),
        code="delegate_payload_invalid",
    )
    add(
        "delegate-two-disclosed",
        "Two delegate_payload elements both disclosed.",
        issue(two_delegate_elements=True),
        code="delegate_payload_invalid",
    )
    none_disclosed = [[parts[0][0]], parts[1]]
    add(
        "delegate-none-disclosed",
        "No delegate_payload element disclosed.",
        base,
        code="delegate_payload_invalid",
        token=join(none_disclosed),
    )

    # ----- key binding: sd_hash both ways, aud, nonce -----
    add(
        "sd-hash-without-trailing-tilde",
        "sd_hash over the open token without its final '~'.",
        issue(sd_hash_over=lambda previous: previous[:-1]),
        code="sd_hash_mismatch",
    )
    add(
        "sd-hash-over-jwt-only",
        "sd_hash over the open JWT alone, no disclosures.",
        issue(sd_hash_over=lambda previous: previous.split("~")[0] + "~"),
        code="sd_hash_mismatch",
    )
    shared = Keys()
    a, b = issue(keys=shared), issue(keys=shared)
    add(
        "sd-hash-other-credential",
        "sd_hash of another open mandate with the same cnf key.",
        issue(keys=shared, sd_hash_value=digest(b.open_token)),
        code="sd_hash_mismatch",
    )
    kb_of_b = links(b.token)[1]
    add(
        "splice-kb-of-other-credential",
        "Open mandate A with the key binding made for open "
        "mandate B (same cnf key, valid signature).",
        a,
        code="sd_hash_mismatch",
        token=join([links(a.token)[0], kb_of_b]),
    )
    withheld = [[parts[0][0], *parts[0][2:]], parts[1]]
    add(
        "open-disclosure-dropped-after-binding",
        "A disclosure dropped from the open mandate after the key binding committed to it.",
        base,
        code="sd_hash_mismatch",
        token=join(withheld),
    )
    add(
        "sd-hash-non-string",
        "sd_hash is a number.",
        issue(edit_kb_payload=lambda p: p.update(sd_hash=1)),
        code="sd_hash_mismatch",
    )
    add(
        "sd-hash-missing",
        "No sd_hash in the key binding.",
        issue(omit_sd_hash=True),
        code="sd_hash_missing",
    )
    add(
        "issuer-jwt-hash-only",
        "issuer_jwt_hash instead of sd_hash.",
        issue(issuer_jwt_hash_only=True),
        code="sd_hash_missing",
    )
    add(
        "kb-wrong-audience",
        "Key binding aud is another verifier.",
        issue(kb_aud="elsewhere"),
        code="kb_audience_mismatch",
        audience="merchant",
    )
    add(
        "kb-wrong-nonce",
        "Key binding nonce is not the expected one.",
        issue(kb_nonce="other"),
        code="kb_nonce_mismatch",
    )
    add(
        "kb-missing-aud",
        "No aud in the key binding.",
        issue(omit_aud=True),
        code="kb_claim_missing",
    )
    add(
        "kb-missing-nonce",
        "No nonce in the key binding.",
        issue(omit_nonce=True),
        code="kb_claim_missing",
    )
    add(
        "kb-empty-nonce",
        "An empty nonce in the key binding.",
        issue(edit_kb_payload=lambda p: p.update(nonce="")),
        code="kb_claim_missing",
    )
    add(
        "kb-missing-iat",
        "No iat in the key binding.",
        issue(omit_iat=True),
        code="kb_claim_missing",
    )

    # ----- vct -----
    def vct_case(id: str, desc: str, value: Any) -> None:
        add(id, desc, issue(open_vct=value), code="vct_mismatch")

    vct_case("vct-wrong-version", "Open vct with version 2.", "mandate.checkout.open.2")
    vct_case("vct-uppercase", "Open vct in another case.", "Mandate.Checkout.Open.1")
    vct_case("vct-trailing-space", "Open vct with a trailing space.", "mandate.checkout.open.1 ")
    vct_case("vct-longer", "Open vct with a longer version suffix.", "mandate.checkout.open.1.1")
    vct_case("vct-prefix", "Open vct that is a prefix.", "mandate.checkout.open")
    vct_case("vct-unknown", "Open vct that is unknown.", "mandate.refund.1")
    vct_case("vct-not-string", "Open vct that is a number.", 1)
    vct_case("vct-empty", "Open vct that is empty.", "")
    add(
        "vct-open-where-closed-expected",
        "An open vct in the closed position.",
        issue(closed_vct=OPEN_VCT["checkout"]),
        code="vct_mismatch",
    )
    add(
        "vct-closed-where-open-expected",
        "A closed vct in the open position.",
        issue(open_vct=CLOSED_VCT["checkout"]),
        code="vct_mismatch",
    )
    add(
        "vct-payment-in-checkout-chain",
        "Payment vct strings where checkout is expected.",
        issue("payment"),
        code="vct_mismatch",
        vcts=[OPEN_VCT["checkout"], CLOSED_VCT["checkout"]],
    )
    add(
        "vct-missing-open",
        "No vct in the open mandate.",
        issue(omit_open_vct=True),
        code="vct_missing",
    )
    add(
        "vct-missing-closed",
        "No vct in the closed mandate.",
        issue(omit_closed_vct=True),
        code="vct_missing",
    )

    # ----- cnf -----
    good = public_jwk(base.keys.agent)

    def cnf_case(id: str, desc: str, cnf: Any, code: str) -> None:
        add(id, desc, issue(cnf=cnf), code=code)

    cnf_case("cnf-missing", "No cnf in the open mandate.", None, "cnf_missing")
    cnf_case("cnf-not-object", "cnf is a string.", "abc", "cnf_malformed")
    cnf_case("cnf-jwk-not-object", "cnf.jwk is a string.", {"jwk": "abc"}, "cnf_malformed")
    cnf_case("cnf-no-jwk", "cnf without jwk (kid only).", {"kid": "agent-1"}, "cnf_unsupported_key")
    cnf_case(
        "cnf-extra-member",
        "cnf with jwk and kid.",
        {"jwk": good, "kid": "a"},
        "cnf_unsupported_key",
    )
    cnf_case(
        "cnf-jwk-missing-x",
        "cnf.jwk without x.",
        {"jwk": {k: v for k, v in good.items() if k != "x"}},
        "cnf_malformed",
    )
    cnf_case(
        "cnf-jwk-short-y",
        "cnf.jwk y of 31 bytes.",
        {"jwk": {**good, "y": b64e(base64.urlsafe_b64decode(good["y"] + "=")[:31])}},
        "cnf_malformed",
    )
    cnf_case(
        "cnf-jwk-private-d",
        "cnf.jwk carrying a private scalar.",
        {"jwk": {**good, "d": b64e(b"\x01" * 32)}},
        "cnf_malformed",
    )
    cnf_case(
        "cnf-jwk-off-curve",
        "cnf.jwk point not on P-256.",
        {"jwk": {**good, "y": b64e(b"\x02" * 32)}},
        "cnf_malformed",
    )
    cnf_case(
        "cnf-jwk-rsa",
        "cnf.jwk of another key type.",
        {"jwk": {"kty": "RSA", "n": "AQAB", "e": "AQAB"}},
        "cnf_unsupported_key",
    )
    cnf_case(
        "cnf-jwk-p384",
        "cnf.jwk on another curve.",
        {"jwk": {**good, "crv": "P-384"}},
        "cnf_unsupported_key",
    )
    cnf_case(
        "cnf-jwk-alg-es384",
        "cnf.jwk with alg ES384.",
        {"jwk": {**good, "alg": "ES384"}},
        "cnf_unsupported_key",
    )
    cnf_case(
        "cnf-jwk-use-enc",
        "cnf.jwk with use enc.",
        {"jwk": {**good, "use": "enc"}},
        "cnf_unsupported_key",
    )
    cnf_case(
        "cnf-jwk-key-ops-sign",
        "cnf.jwk with key_ops sign only.",
        {"jwk": {**good, "key_ops": ["sign"]}},
        "cnf_unsupported_key",
    )

    # ----- time -----
    add(
        "expired-by-61",
        "now is 61 s after exp: outside the skew.",
        base,
        code="expired",
        now=exp + 61,
    )
    add("expired-long-ago", "exp far in the past.", issue(open_exp=NOW - 86_400), code="expired")
    add(
        "expired-closed",
        "exp on the closed mandate in the past.",
        issue(closed_exp=NOW - 61),
        code="expired",
    )
    add("exp-missing", "No exp on the open mandate.", issue(open_exp=None), code="exp_missing")
    for label, value in (("true", True), ("string", "1800003600"), ("float", 1800003600.5)):
        add(
            f"exp-type-{label}",
            f"exp is {label}, not an integer.",
            issue(open_exp=value),
            code="time_claim_type",
        )
    add(
        "not-yet-valid-61",
        "nbf is 61 s ahead of now.",
        issue(open_nbf=NOW + 61),
        code="not_yet_valid",
    )
    add(
        "not-yet-valid-closed",
        "nbf on the closed mandate an hour ahead.",
        issue(closed_nbf=NOW + 3600),
        code="not_yet_valid",
    )
    add(
        "open-issued-in-future-61",
        "iat is 61 s ahead of now.",
        issue(open_iat=NOW + 61),
        code="issued_in_future",
    )
    add(
        "kb-issued-in-future-61",
        "Key binding iat is 61 s ahead of now.",
        issue(kb_iat=NOW + 61),
        code="issued_in_future",
    )

    OUT.parent.mkdir(parents=True, exist_ok=True)
    OUT.write_text(json.dumps({"version": 1, "vectors": vectors}, indent=1) + "\n")
    print(f"wrote {len(vectors)} vectors to {OUT}")


if __name__ == "__main__":
    main()
