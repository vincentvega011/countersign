"""Client configuration. Sandbox only unless explicitly configured otherwise, never live.

The default base URL is the sandbox host and any other host is refused unless `allow_non_sandbox`
is set (for a local test server). The two live PayPal hosts are refused whatever the flag says:
Countersign handles sandbox credentials only (docs/ENV.md section 2). Credentials are excluded from
`repr` and `str`, so a config in a log line or a traceback shows nothing secret.
"""

from __future__ import annotations

import os
from collections.abc import Mapping
from dataclasses import dataclass, field
from urllib.parse import urlsplit

from countersign.paypal.errors import PayPalConfigError

SANDBOX_HOST = "api-m.sandbox.paypal.com"
SANDBOX_URL = f"https://{SANDBOX_HOST}"
LIVE_HOSTS = frozenset({"api-m.paypal.com", "api.paypal.com"})  # secret-scan:allow (refusal list)
_LOCAL_HOSTS = frozenset({"localhost", "127.0.0.1", "::1"})


def _clean(value: str, name: str) -> str:
    if not isinstance(value, str) or not value.strip():
        raise PayPalConfigError(f"{name} is required")
    if any(ord(c) < 0x20 or ord(c) == 0x7F for c in value) or value != value.strip():
        raise PayPalConfigError(f"{name} has surrounding whitespace or control characters")
    return value


@dataclass(frozen=True)
class PayPalConfig:
    client_id: str = field(repr=False)
    client_secret: str = field(repr=False)
    base_url: str = SANDBOX_URL
    allow_non_sandbox: bool = False
    connect_timeout_s: float = 5.0
    read_timeout_s: float = 30.0
    max_attempts: int = 3
    backoff_s: float = 0.5
    token_skew_s: float = 60.0
    authorization_expiry_skew_s: float = 60.0

    def __post_init__(self) -> None:
        _clean(self.client_id, "PAYPAL_CLIENT_ID")
        _clean(self.client_secret, "PAYPAL_CLIENT_SECRET")
        if not 1 <= self.max_attempts <= 5:
            raise PayPalConfigError("max_attempts must be from 1 to 5")
        if self.authorization_expiry_skew_s < 0:
            raise PayPalConfigError("authorization_expiry_skew_s must not be negative")
        if min(self.connect_timeout_s, self.read_timeout_s) <= 0 or self.backoff_s < 0:
            raise PayPalConfigError("timeouts must be positive and the backoff not negative")
        parts = urlsplit(self.base_url)
        host = (parts.hostname or "").lower()
        if host in LIVE_HOSTS:
            raise PayPalConfigError("the live PayPal API is not allowed; use the sandbox")
        if host != SANDBOX_HOST and not self.allow_non_sandbox:
            raise PayPalConfigError(f"the host must be {SANDBOX_HOST} unless explicitly allowed")
        if parts.scheme != "https" and not (parts.scheme == "http" and host in _LOCAL_HOSTS):
            raise PayPalConfigError("the base URL must be https (http only for a local host)")
        if parts.username or parts.password or parts.query or parts.fragment:
            raise PayPalConfigError(
                "the base URL must not carry credentials, a query or a fragment"
            )
        if parts.path not in ("", "/"):
            raise PayPalConfigError("the base URL must not have a path")

    def __repr__(self) -> str:
        return f"PayPalConfig(base_url={self.base_url!r}, credentials=<redacted>)"

    __str__ = __repr__

    @classmethod
    def from_env(cls, env: Mapping[str, str] | None = None) -> PayPalConfig:
        """Read PAYPAL_API_BASE (or PAYPAL_BASE_URL), PAYPAL_CLIENT_ID and PAYPAL_CLIENT_SECRET."""
        source = os.environ if env is None else env
        base = source.get("PAYPAL_API_BASE") or source.get("PAYPAL_BASE_URL") or SANDBOX_URL
        return cls(
            client_id=source.get("PAYPAL_CLIENT_ID", ""),
            client_secret=source.get("PAYPAL_CLIENT_SECRET", ""),
            base_url=base.rstrip("/"),
            allow_non_sandbox=source.get("PAYPAL_ALLOW_NON_SANDBOX") == "1",
        )
