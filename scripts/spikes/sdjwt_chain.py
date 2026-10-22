"""Spike: SD-JWT mandate chains built from scratch on joserfc and hashlib.

Shows that the chain format AP2 uses (docs/PROTOCOL.md section 1.2.3) can be parsed, verified and
issued without a third-party SD-JWT library:

* split `<SD-JWT>~~<KB-SD-JWT>~<disclosures>~` with the exactly-one-empty-component rule of the
  Delegate SD-JWT draft,
* resolve selective disclosures (object properties and array elements, RFC 9901 section 7.1),
* verify each key-binding link with the `cnf` key of the previous link, and check `sd_hash` over the
  US-ASCII bytes of the previous serialization including its trailing `~` (RFC 9901 section 4.3.1),
* verify the three worked examples in spec/vendor/ap2/docs/checkout_mandate.md and
  payment_mandate.md (their issuer key is not published, so the issuer signature is not checked),
* issue and verify a new chain, with the checkout_jwt built as in docs/PROTOCOL.md Decision 7.

Run: uv run python scripts/spikes/sdjwt_chain.py
"""

import base64
import hashlib
import json
import re
import secrets
import time
from dataclasses import dataclass
from pathlib import Path

import rfc8785
from joserfc import jws
from joserfc.jwk import ECKey

ROOT = Path(__file__).resolve().parents[2]
ALGS = ["ES256"]


def b64e(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode()


def b64d(text: str) -> bytes:
    return base64.urlsafe_b64decode(text + "=" * (-len(text) % 4))


def digest(text: str) -> str:
    """base64url(SHA-256(US-ASCII bytes)): disclosure digests, sd_hash and checkout_hash."""
    return b64e(hashlib.sha256(text.encode("ascii")).digest())


class ChainError(ValueError):
    pass


@dataclass
class Link:
    jwt: str
    disclosures: list[str]

    @property
    def serialization(self) -> str:
        """`<jwt>~<disclosure 1>~...~<disclosure N>~`, the input to sd_hash."""
        return "~".join([self.jwt, *self.disclosures]) + "~"


def split_chain(token: str) -> tuple[list[Link], str | None]:
    """Split on `~` with exactly one empty component between links (Delegate SD-JWT draft)."""
    if not re.fullmatch(r"[A-Za-z0-9_.~-]+", token):
        raise ChainError("characters outside base64url, '.' and '~'")
    parts = token.split("~")
    links: list[Link] = []
    final_kb: str | None = None
    i = 0
    while True:
        if i >= len(parts) or parts[i] == "":
            raise ChainError("expected a JWT")
        jwt = parts[i]
        i += 1
        disclosures: list[str] = []
        while i < len(parts) and parts[i] != "" and "." not in parts[i]:
            disclosures.append(parts[i])
            i += 1
        links.append(Link(jwt, disclosures))
        if i == len(parts):
            raise ChainError("must end with '~' or a key binding JWT")
        if parts[i] == "" and i == len(parts) - 1:
            return links, None  # dSD-JWT: trailing '~'
        if parts[i] == "":
            i += 1  # the single empty component between links
            continue
        if i == len(parts) - 1:
            final_kb = parts[i]  # dSD-JWT+KB: delegate key binding JWT
            return links, final_kb
        raise ChainError("unexpected element")


def resolve(node, table: dict, used: set):
    """Replace disclosed digests with their values (object properties and array elements)."""
    if isinstance(node, dict):
        out = {k: resolve(v, table, used) for k, v in node.items() if k != "_sd"}
        for d in node.get("_sd", []):
            if d in table:
                _, name, value = table[d]
                if name in out:
                    raise ChainError(f"duplicate claim {name}")
                used.add(d)
                out[name] = resolve(value, table, used)
        return out
    if isinstance(node, list):
        out_list = []
        for element in node:
            if isinstance(element, dict) and set(element) == {"..."}:
                d = element["..."]
                if d in table:
                    used.add(d)
                    out_list.append(resolve(table[d][1], table, used))
            else:
                out_list.append(resolve(element, table, used))
        return out_list
    return node


def disclosure_table(disclosures: list[str]) -> dict:
    table = {}
    for d in disclosures:
        decoded = json.loads(b64d(d))
        if len(decoded) not in (2, 3):  # [salt, value] or [salt, name, value]
            raise ChainError("bad disclosure")
        if digest(d) in table:
            raise ChainError("duplicate disclosure")
        table[digest(d)] = decoded
    return table


def verify_chain(token: str, issuer_key: ECKey | None) -> list[dict]:
    """Verify a chain. Returns the resolved delegate payload of every link."""
    links, final_kb = split_chain(token)
    if final_kb is not None:
        raise ChainError("a trailing delegate key binding JWT is not used by AP2 mandates")
    delegates: list[dict] = []
    for n, link in enumerate(links):
        header_b64, payload_b64, _ = link.jwt.split(".")
        header = json.loads(b64d(header_b64))
        if header.get("alg") not in ALGS:
            raise ChainError("algorithm not allowed")
        if n == 0:
            key = issuer_key
        else:
            if header.get("typ") != "kb+sd-jwt":
                raise ChainError("link typ must be kb+sd-jwt")
            key = ECKey.import_key(delegates[-1]["cnf"]["jwk"])
        if key is not None:
            payload = json.loads(jws.deserialize_compact(link.jwt, key, algorithms=ALGS).payload)
        else:
            payload = json.loads(b64d(payload_b64))  # issuer key not published: not verified
        if payload.get("_sd_alg", "sha-256") != "sha-256":
            raise ChainError("unsupported _sd_alg")
        table = disclosure_table(link.disclosures)
        used: set = set()
        claims = resolve(payload, table, used)
        if used != set(table):
            raise ChainError("unreferenced disclosure")
        if n > 0:
            for claim in ("iat", "aud", "nonce", "sd_hash"):
                if claim not in claims:
                    raise ChainError(f"missing {claim}")
            if claims["sd_hash"] != digest(links[n - 1].serialization):
                raise ChainError("sd_hash does not match the preceding serialization")
        delegate = claims.get("delegate_payload")
        if not isinstance(delegate, list) or len(delegate) != 1:
            raise ChainError("exactly one disclosed delegate_payload element is required")
        if n < len(links) - 1 and "cnf" not in delegate[0]:
            raise ChainError("cnf required to continue the chain")
        delegates.append(delegate[0] | {"_claims": claims})
    return delegates


def expect_error(label: str, fn) -> None:
    try:
        fn()
    except Exception as error:  # noqa: BLE001 - spike: any rejection counts
        print(f"OK rejected: {label} ({type(error).__name__})")
    else:
        raise AssertionError(f"{label} was accepted")


# ----- the worked examples in the vendored AP2 documents -----


def example_tokens(doc: str) -> list[str]:
    text = (ROOT / "spec/vendor/ap2/docs" / doc).read_text()
    return re.findall(r"#### Encoded Token\n\n```\n(.+?)\n```", text, re.DOTALL)


def check_ap2_examples() -> None:
    checkout = example_tokens("checkout_mandate.md")
    payment = example_tokens("payment_mandate.md")
    open_c, _, chain_c = checkout
    open_p, _, chain_p = payment

    (open_only,) = verify_chain(open_c, None)
    assert open_only["vct"] == "mandate.checkout.open.1"
    assert [c["type"] for c in open_only["constraints"]] == [
        "checkout.line_items",
        "checkout.allowed_merchants",
    ]
    assert open_only["constraints"][0]["items"][0]["acceptable_items"][0]["id"]
    print("OK AP2 open Checkout Mandate: disclosures resolved, constraints readable")

    _, closed = verify_chain(chain_c, None)
    assert closed["vct"] == "mandate.checkout.1"
    checkout_jwt = closed["checkout_jwt"]
    assert digest(checkout_jwt) == closed["checkout_hash"]
    print("OK AP2 chained Checkout Mandate: ~~ split, KB signature, sd_hash, checkout_hash")

    _, pay_closed = verify_chain(chain_p, None)
    assert pay_closed["vct"] == "mandate.payment.1"
    assert pay_closed["transaction_id"] == closed["checkout_hash"]
    open_payment = verify_chain(open_p, None)[0]
    reference = next(c for c in open_payment["constraints"] if c["type"] == "payment.reference")
    assert reference["conditional_transaction_id"] == digest(open_c)
    print("OK AP2 chained Payment Mandate: transaction_id == checkout_hash, reference == digest")


# ----- issuing and verifying a new chain -----


def disclosure(value, name: str | None = None) -> tuple[str, str]:
    salt = b64e(secrets.token_bytes(16))
    items = [salt, value] if name is None else [salt, name, value]
    text = b64e(json.dumps(items, separators=(",", ":")).encode())
    return text, digest(text)


def sign(header: dict, payload: dict, key: ECKey) -> str:
    return jws.serialize_compact(
        header, json.dumps(payload, separators=(",", ":")), key, algorithms=ALGS
    )


def issue_chain(
    platform: ECKey,
    agent: ECKey,
    merchant: ECKey,
    kb_signer: ECKey | None = None,
    sd_hash_input: str | None = None,
) -> str:
    now = int(time.time())
    item, d_item = disclosure({"id": "sku-headphones", "title": "Over-ear headphones"})
    shop, d_shop = disclosure({"id": "m1", "name": "Demo Store", "website": "https://demo.example"})
    open_content = {
        "vct": "mandate.checkout.open.1",
        "constraints": [
            {
                "type": "checkout.line_items",
                "items": [{"id": "line_1", "acceptable_items": [{"...": d_item}], "quantity": 1}],
            },
            {"type": "checkout.allowed_merchants", "allowed": [{"...": d_shop}]},
        ],
        "cnf": {"jwk": agent.as_dict(private=False)},
        "iat": now,
        "exp": now + 3600,
    }
    open_disc, d_open = disclosure(open_content)
    open_jwt = sign(
        {"alg": "ES256", "typ": "example+sd-jwt", "kid": "platform-key-1"},
        {
            "iss": "https://platform.example",
            "delegate_payload": [{"...": d_open}],
            "_sd_alg": "sha-256",
        },
        platform,
    )
    open_token = f"{open_jwt}~{item}~{shop}~{open_disc}~"

    # checkout_jwt: one merchant signature, compact form with the JCS payload attached.
    checkout = {"id": "chk_1", "currency": "USD", "totals": [{"type": "total", "amount": 7900}]}
    checkout_jwt = jws.serialize_compact(
        {"alg": "ES256", "kid": "merchant-key-1"},
        rfc8785.dumps(checkout),
        merchant,
        algorithms=ALGS,
    )
    cj_disc, d_cj = disclosure(checkout_jwt, "checkout_jwt")
    closed_content = {
        "_sd": [d_cj],
        "vct": "mandate.checkout.1",
        "checkout_hash": digest(checkout_jwt),
    }
    closed_disc, d_closed = disclosure(closed_content)
    kb = sign(
        {"alg": "ES256", "typ": "kb+sd-jwt"},
        {
            "delegate_payload": [{"...": d_closed}],
            "iat": now,
            "aud": "merchant",
            "nonce": b64e(secrets.token_bytes(12)),
            "sd_hash": digest(sd_hash_input or open_token),
            "_sd_alg": "sha-256",
        },
        kb_signer or agent,
    )
    return f"{open_token}~{kb}~{closed_disc}~{cj_disc}~"


def check_new_chain() -> None:
    platform, agent, merchant, stranger = (ECKey.generate_key("P-256") for _ in range(4))
    token = issue_chain(platform, agent, merchant)
    _, closed = verify_chain(token, platform)
    assert closed["checkout_hash"] == digest(closed["checkout_jwt"])
    print("OK new chain: platform-signed open mandate, agent-signed closed mandate verify")

    expect_error("wrong issuer key", lambda: verify_chain(token, stranger))
    expect_error(
        "single tilde instead of ~~", lambda: verify_chain(token.replace("~~", "~", 1), platform)
    )
    forged = issue_chain(platform, agent, merchant, kb_signer=stranger)
    expect_error("closed mandate not signed by the cnf key", lambda: verify_chain(forged, platform))
    # The usual mistake: hashing the open token without its trailing '~'.
    open_token = token[: token.index("~~") + 1]
    wrong_hash = issue_chain(platform, agent, merchant, sd_hash_input=open_token.rstrip("~"))
    expect_error(
        "sd_hash computed without the trailing tilde", lambda: verify_chain(wrong_hash, platform)
    )
    first_disclosure = token.split("~")[1]
    expect_error(
        "altered disclosure",
        lambda: verify_chain(
            token.replace(
                first_disclosure, b64e(json.dumps(["x", {"id": "other", "title": "t"}]).encode()), 1
            ),
            platform,
        ),
    )
    expect_error("dropped trailing tilde", lambda: verify_chain(token[:-1], platform))


if __name__ == "__main__":
    check_ap2_examples()
    check_new_chain()
    print("SD-JWT chains verified without a third-party SD-JWT library")
