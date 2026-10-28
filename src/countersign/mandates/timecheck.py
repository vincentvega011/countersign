"""`exp`, `nbf` and `iat` checks with an explicit skew and an injected clock.

Security reasoning. An open mandate is a standing authority, so its expiry is enforced strictly
and a mandate that never expires is refused (`require_exp`). The specs give no clock skew
(docs/PROTOCOL.md gap 7); Countersign uses `CLOCK_SKEW_SECONDS` (Decision 10), applied as:

    expired            when now - exp  >  skew      (exactly skew seconds past exp still passes)
    not yet valid      when nbf - now  >  skew      (exactly skew seconds early still passes)
    issued in future   when iat - now  >  skew

Time claims must be JSON integers (not booleans, floats or strings): `True` would otherwise
compare as 1 and a string as an error somewhere unexpected. The clock is a parameter so tests
control it; production passes `time.time`.
"""

from __future__ import annotations

from collections.abc import Callable, Mapping

from countersign.canonical import JsonValue
from countersign.mandates.errors import (
    ClaimTypeError,
    ExpiredError,
    ExpMissingError,
    IssuedInFutureError,
    NotYetValidError,
)

CLOCK_SKEW_SECONDS = 60

type Clock = Callable[[], float]


def _claim(claims: Mapping[str, JsonValue], name: str) -> int | None:
    if name not in claims:
        return None
    value = claims[name]
    if isinstance(value, bool) or not isinstance(value, int):
        raise ClaimTypeError(f"{name} must be an integer NumericDate")
    return value


def check_times(claims: Mapping[str, JsonValue], now: float, *, require_exp: bool) -> None:
    """Check `exp`, `nbf` and `iat` found in `claims` against `now`, or raise a typed error."""
    exp = _claim(claims, "exp")
    nbf = _claim(claims, "nbf")
    iat = _claim(claims, "iat")
    if exp is None and require_exp:
        raise ExpMissingError("the mandate has no exp claim")
    if exp is not None and now - exp > CLOCK_SKEW_SECONDS:
        raise ExpiredError("the mandate has expired")
    if nbf is not None and nbf - now > CLOCK_SKEW_SECONDS:
        raise NotYetValidError("the mandate is not valid yet")
    if iat is not None and iat - now > CLOCK_SKEW_SECONDS:
        raise IssuedInFutureError("the mandate was issued in the future")
