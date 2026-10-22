"""Spike: ES256, detached payload and an algorithm allowlist with joserfc.

Builds a UCP style merchant_authorization (detached JWS over the JCS bytes of a checkout minus
its ap2 member, header exactly {alg, kid}) and the compact checkout_jwt from the same signature
(docs/PROTOCOL.md, Decision 7). Also writes test vectors for the Node check in jose_detached.mjs.

Run: uv run python scripts/spikes/jws_detached.py [vectors.json]
"""

import base64
import json
import sys

import joserfc
import rfc8785
from joserfc import jws
from joserfc.errors import JoseError
from joserfc.jwk import ECKey

ALLOWED = ["ES256"]


def b64(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode()


def sign_checkout(checkout: dict, key: ECKey, kid: str) -> tuple[str, str]:
    """Return (merchant_authorization, checkout_jwt) from one signature."""
    payload = rfc8785.dumps({k: v for k, v in checkout.items() if k != "ap2"})
    compact = jws.serialize_compact({"alg": "ES256", "kid": kid}, payload, key, algorithms=ALLOWED)
    header, _, signature = compact.split(".")
    return f"{header}..{signature}", compact


def verify_detached(detached: str, checkout: dict, key: ECKey) -> None:
    payload = rfc8785.dumps({k: v for k, v in checkout.items() if k != "ap2"})
    jws.deserialize_compact(detached, key, algorithms=ALLOWED, payload=payload)


def expect_failure(label: str, fn) -> None:
    try:
        fn()
    except (JoseError, ValueError) as error:
        print(f"OK rejected: {label} ({type(error).__name__})")
    else:
        raise AssertionError(f"{label} was accepted")


def main() -> None:
    key = ECKey.generate_key("P-256")
    checkout = {
        "id": "chk_1",
        "currency": "USD",
        "line_items": [{"id": "li_1", "item": {"id": "sku", "title": "Widget", "price": 2500}}],
        "totals": [{"type": "subtotal", "amount": 5000}, {"type": "total", "amount": 5000}],
        "ap2": {"merchant_authorization": "placeholder"},
    }
    detached, compact = sign_checkout(checkout, key, "merchant-key-1")
    assert detached.count("..") == 1
    verify_detached(detached, checkout, key)
    print("OK detached JWS verifies with the payload re-attached")

    # The compact form carries the same header and signature.
    header, payload, signature = compact.split(".")
    assert detached == f"{header}..{signature}"
    assert base64.urlsafe_b64decode(payload + "==") == rfc8785.dumps(
        {k: v for k, v in checkout.items() if k != "ap2"}
    )
    result = jws.deserialize_compact(compact, key, algorithms=ALLOWED)
    assert result.protected == {"alg": "ES256", "kid": "merchant-key-1"}
    print("OK compact checkout_jwt shares header and signature with the detached form")

    # Changing any covered field breaks verification. The ap2 member is excluded from coverage.
    tampered = json.loads(json.dumps(checkout))
    tampered["totals"][1]["amount"] = 4999
    expect_failure("tampered total", lambda: verify_detached(detached, tampered, key))
    checkout["ap2"] = {"merchant_authorization": detached}
    verify_detached(detached, checkout, key)
    print("OK adding the ap2 member does not change the signed bytes")

    # Algorithm allowlist.
    other = ECKey.generate_key("P-384")
    es384 = jws.serialize_compact({"alg": "ES384"}, b"x", other, algorithms=["ES384"])
    expect_failure(
        "ES384 under an ES256 allowlist",
        lambda: jws.deserialize_compact(es384, other, algorithms=ALLOWED),
    )
    none_header = b64(b'{"alg":"none"}')
    unsigned = f"{none_header}.{b64(b'x')}."
    expect_failure("alg none", lambda: jws.deserialize_compact(unsigned, key, algorithms=ALLOWED))
    hs256_header = b64(b'{"alg":"HS256"}')
    forged = f"{hs256_header}.{b64(b'x')}.{b64(b'0' * 32)}"
    expect_failure(
        "HS256 forged with a public key",
        lambda: jws.deserialize_compact(forged, key, algorithms=ALLOWED),
    )

    print(f"joserfc {joserfc.__version__}: ES256, detached payload and allowlist verified")
    if len(sys.argv) > 1:
        public = key.as_dict(private=False)
        with open(sys.argv[1], "w") as handle:
            json.dump(
                {
                    "jwk": {**public, "kid": "merchant-key-1"},
                    "checkout": checkout,
                    "merchant_authorization": detached,
                    "tampered": tampered,
                },
                handle,
            )
        print(f"wrote vectors to {sys.argv[1]}")


if __name__ == "__main__":
    main()
