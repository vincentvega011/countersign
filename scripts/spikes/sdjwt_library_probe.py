"""Probe: what does the `sd-jwt` package (OpenWallet Foundation, 0.10.4) do with our requirements?

Not a project dependency. Run it with the package injected for this one run:

    uv run --with sd-jwt python scripts/spikes/sdjwt_library_probe.py

The requirements come from docs/PROTOCOL.md section 1.2.3: the `<SD-JWT>~~<KB-SD-JWT>~...` chain
format, `typ` `kb+sd-jwt` links, sd_hash over the previous serialization, ES256 only, and exp/nbf
checks. The tokens are the ones issued by sdjwt_chain.py.
"""

import inspect
import json
import sys
from pathlib import Path

from joserfc.jwk import ECKey
from jwcrypto.jwk import JWK
from sd_jwt import verifier as library_verifier
from sd_jwt.verifier import SDJWTVerifier

sys.path.insert(0, str(Path(__file__).resolve().parent))
import sdjwt_chain


def outcome(label: str, fn) -> str:
    try:
        result = fn()
    except Exception as error:  # noqa: BLE001 - a probe reports whatever happens
        print(f"REJECTS  {label}: {type(error).__name__}: {str(error)[:70]}")
        return "rejects"
    print(f"ACCEPTS  {label}: {str(result)[:70]}")
    return "accepts"


def main() -> None:
    platform, agent, merchant = (ECKey.generate_key("P-256") for _ in range(3))
    chain = sdjwt_chain.issue_chain(platform, agent, merchant)
    open_token = chain[: chain.index("~~") + 1]
    closed_token = chain[chain.index("~~") + 2 :]
    issuer_jwk = JWK.from_json(json.dumps(platform.as_dict(private=False)))

    def get_key(_iss, _header):
        return issuer_jwk

    # 1. The open mandate on its own is a plain SD-JWT with array element disclosures.
    results = {}
    results["open mandate alone"] = outcome(
        "open mandate as a plain SD-JWT",
        lambda: SDJWTVerifier(open_token, get_key).get_verified_payload()["delegate_payload"][0][
            "vct"
        ],
    )
    # 2. The chain itself, with the empty component.
    results["chain"] = outcome(
        "full chain with ~~", lambda: SDJWTVerifier(chain, get_key).get_verified_payload()
    )
    # 3. Treat the closed link (typ kb+sd-jwt) as the key binding JWT of the open mandate.
    kb_jwt = closed_token.split("~")[0]
    results["kb typ"] = outcome(
        "closed link (typ kb+sd-jwt) as the KB-JWT",
        lambda: SDJWTVerifier(
            open_token + kb_jwt, get_key, expected_aud="merchant", expected_nonce="x"
        ),
    )
    # 4. Static facts from the source.
    source = inspect.getsource(library_verifier)
    print("SOURCE   exp/nbf/iat checks are a TODO:", "TODO: Check exp/nbf/iat" in source)
    print(
        "SOURCE   issuer signature verified with no algorithm allowlist:",
        "sign_alg: str = None" in source,
    )
    print("SOURCE   key binding typ is a fixed constant:", "KB_JWT_TYP_HEADER" in source)
    print(
        "SOURCE   other _sd_alg values unsupported:",
        "TODO: Support other hash algorithms" in source,
    )
    print("RESULT  ", results)


if __name__ == "__main__":
    main()
