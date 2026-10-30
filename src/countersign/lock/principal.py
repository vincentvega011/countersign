"""The principal: who a checkout belongs to, independent of protocol and session (INV-5).

A principal is (customer id, agent key thumbprint). The thumbprint is the RFC 7638 thumbprint of the
key in the open mandate's `cnf`. The customer id is the `sub` claim of the platform-signed issuer JWT
([PROTOCOL.md](../../../docs/PROTOCOL.md) Decision 47). Either part may be unknown (`None`): a
Human Present mandate names no agent key, and a mandate issued without a `sub` names no customer. An
unknown part is never read as "not locked": the lock matches on the known parts and fails closed when
the policy needs the customer.
"""

from __future__ import annotations

from dataclasses import dataclass

from joserfc.jwk import ECKey

from countersign.mandates import (
    VCT_CHECKOUT_OPEN,
    Clock,
    MandateError,
    VerifiedChain,
    customer_id_of,
    verify_chain,
)


@dataclass(frozen=True)
class Principal:
    customer_id: str | None = None
    agent_thumbprint: str | None = None

    @property
    def known(self) -> bool:
        return bool(self.customer_id or self.agent_thumbprint)


def principal_from_chain(chain: VerifiedChain) -> Principal:
    """The principal of an already verified chain (link 0 is the platform-signed issuer JWT)."""
    first = chain.links[0]
    return Principal(customer_id_of(first.claims), first.cnf_thumbprint)


def principal_from_delegation(
    token: str | None, platform_key: ECKey | None, clock: Clock
) -> Principal | None:
    """The principal named by an open Checkout Mandate presented at negotiation, or None.

    The token is one open link (the delegation the customer signed on the Trusted Surface). It is
    verified against the one trusted platform key and must be unexpired. Anything that does not
    verify names nobody: the result is None and the caller treats the principal as unknown.
    """
    if not token or platform_key is None:
        return None
    try:
        chain = verify_chain(
            token,
            issuer_key=platform_key,
            expected_vcts=[VCT_CHECKOUT_OPEN],
            audience="",
            clock=clock,
        )
    except (MandateError, ValueError, TypeError):
        return None
    return principal_from_chain(chain)
