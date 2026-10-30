"""Merchant lock policy as pure data (docs/PROTOCOL.md Decision 48).

Three modes: `off`, `all` (require AP2 for every agent) and `over_threshold` (require it when the
checkout total is above a limit given in integer minor units of one currency, INV-9). A policy has a
version and a hash over its JCS bytes (INV-8), so a change is visible and a tampered row is caught
when it is read. The unmandated cap and the velocity limits are not built yet.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Literal

from countersign.canonical import canonicalize
from countersign.canonical.hashing import b64url, domain_hash
from countersign.canonical.money import Money

Mode = Literal["off", "all", "over_threshold"]
MODES = ("off", "all", "over_threshold")
POLICY_DOMAIN = "cs.lock.policy.v1"


class PolicyError(ValueError):
    """A policy that is not well formed."""


@dataclass(frozen=True)
class MerchantPolicy:
    version: int
    mode: Mode = "off"
    threshold_minor: int | None = None
    currency: str | None = None

    def __post_init__(self) -> None:
        if not isinstance(self.version, int) or isinstance(self.version, bool) or self.version < 0:
            raise PolicyError("the version is a non-negative integer")
        if self.mode not in MODES:
            raise PolicyError("unknown mode")
        if self.mode == "over_threshold":
            if (
                not isinstance(self.threshold_minor, int)
                or isinstance(self.threshold_minor, bool)
                or self.threshold_minor < 0
                or not isinstance(self.currency, str)
                or len(self.currency) != 3
            ):
                raise PolicyError("a threshold is integer minor units with a currency")
        elif self.threshold_minor is not None or self.currency is not None:
            raise PolicyError("only the over_threshold mode has a threshold")

    def data(self) -> dict[str, object]:
        return {
            "version": self.version,
            "mode": self.mode,
            "threshold_minor": self.threshold_minor,
            "currency": self.currency,
        }

    def hash(self) -> str:
        return b64url(domain_hash(POLICY_DOMAIN, canonicalize(self.data())))

    def requires_ap2(self, amount: Money | None) -> bool:
        """Does the merchant demand a mandate for a checkout of this total?

        `over_threshold` means strictly above the limit. A total in another currency, or none, cannot
        be compared, so it counts as over (INV-10).
        """
        if self.mode == "off":
            return False
        if self.mode == "all":
            return True
        if amount is None or amount.currency != self.currency:
            return True
        assert self.threshold_minor is not None
        return amount.minor > self.threshold_minor
