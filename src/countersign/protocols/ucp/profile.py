"""The UCP business profile served at `/.well-known/ucp`.

Shape follows the vendored UCP profile example for the AP2 mandates extension: the checkout
capability, then `dev.ucp.common.payment.ap2_mandate` with `extends` and a `config` holding
`vp_formats_supported` (docs/PROTOCOL.md, Decision 6). `keys[]` is a top-level profile member.

Security reasoning. The profile is public, so the only key material allowed in it is the public
JWK, and it is copied member by member from an allowlist, never by deleting private members from
a private key. After building, the result is checked once more and the build fails if any private
JWK member is present anywhere under `keys`.
"""

from __future__ import annotations

from typing import Any

from countersign.merchant.keys import PRIVATE_ONLY_MEMBERS, PUBLIC_MEMBERS, MerchantKey

UCP_VERSION = "2026-08-25"
CHECKOUT_CAPABILITY = "dev.ucp.shopping.checkout"
AP2_CAPABILITY = "dev.ucp.common.payment.ap2_mandate"
SHOPPING_SERVICE = "dev.ucp.shopping"
# Base path of the REST binding; the OpenAPI paths (`/checkout-sessions`, ...) are appended to it.
REST_BASE_PATH = "/ucp/v1"
# The payment handler that carries the AP2 Payment Mandate token (docs/PROTOCOL.md Decision 39).
# The name is a placeholder in reverse-domain form: Countersign has no registered domain yet.
PAYMENT_HANDLER_NAME = "dev.countersign.payment.ap2_payment_mandate"
PAYMENT_HANDLER_ID = "countersign_ap2_payment_mandate"
PAYMENT_CREDENTIAL_TYPE = "ap2_payment_mandate"


def payment_handlers() -> dict[str, Any]:
    """A fresh `payment_handlers` registry: one handler whose instruments hold the mandate token."""
    return {
        PAYMENT_HANDLER_NAME: [
            {
                "id": PAYMENT_HANDLER_ID,
                "version": UCP_VERSION,
                "config": {"credential_type": PAYMENT_CREDENTIAL_TYPE},
            }
        ]
    }


class ProfileError(Exception):
    code = "profile_invalid"


def _public_jwk(key: MerchantKey) -> dict[str, str]:
    jwk = {m: key.public_jwk[m] for m in PUBLIC_MEMBERS if m in key.public_jwk}
    if PRIVATE_ONLY_MEMBERS & set(jwk):
        raise ProfileError("private member in public key")
    return jwk


def build_profile(*, public_base_url: str, key: MerchantKey) -> dict[str, Any]:
    """Build the business profile for `public_base_url` (no trailing slash, https in production)."""
    if public_base_url.endswith("/"):
        raise ProfileError("public base URL must have no trailing slash")
    # An empty string fails this check too.
    if not public_base_url.startswith(("http://", "https://")):
        raise ProfileError("public base URL must have an http or https scheme")
    v = UCP_VERSION
    profile: dict[str, Any] = {
        "ucp": {
            "version": v,
            "services": {
                SHOPPING_SERVICE: [
                    {
                        "version": v,
                        "spec": f"https://ucp.dev/{v}/specification/overview/",
                        "transport": "rest",
                        "endpoint": public_base_url + REST_BASE_PATH,
                        "schema": f"https://ucp.dev/{v}/services/shopping/rest.openapi.json",
                    }
                ]
            },
            "capabilities": {
                CHECKOUT_CAPABILITY: [
                    {
                        "version": v,
                        "spec": f"https://ucp.dev/{v}/specification/shopping/checkout",
                        "schema": f"https://ucp.dev/{v}/schemas/shopping/checkout.json",
                    }
                ],
                AP2_CAPABILITY: [
                    {
                        "version": v,
                        "spec": f"https://ucp.dev/{v}/specification/payment/extensions/ap2-mandates",
                        "schema": f"https://ucp.dev/{v}/schemas/common/payment_ap2_mandate.json",
                        "extends": CHECKOUT_CAPABILITY,
                        "config": {"vp_formats_supported": {"dc+sd-jwt": {}}},
                    }
                ],
            },
            "payment_handlers": payment_handlers(),
        },
        "keys": [_public_jwk(key)],
    }
    leaked = [k for entry in profile["keys"] for k in entry if k in PRIVATE_ONLY_MEMBERS]
    if leaked:
        raise ProfileError("private member in profile keys")
    return profile
