"""The agent channel: a proposal in, the issued mandates out (PROTOCOL.md Decision 87, closes L40).

Security reasoning. Before this, an agent handed its request to the approval page in the address
fragment and had no way to fetch what it caused to be issued. Now the agent talks to the backend:

1. **Propose.** The agent signs a server challenge (purpose `agent_proposal`) together with its
   proposal (item ids and quantities, a ceiling, an expiry; structured fields only) using the agent key
   it names. A proposal is stored under a short opaque id. The id is only an address: knowing it lets a
   page show the proposal and a customer consent to it, nothing more.
2. **Consent.** The customer's device key signs the consent record as before. The record's terms must
   equal the stored proposal, and the proposal is spent for issuing by an INSERT into `proposal_uses`
   (primary key = proposal id), so a proposal backs one consent.
3. **Fetch.** The agent proves possession of the same key (the key the proposal stored, which is the key
   in `cnf`) over a fresh challenge (purpose `agent_fetch`) bound to the proposal id. The key used to
   verify is the stored one, never one from the request. Nobody else can fetch the mandates, and a
   stolen proposal id is worthless without the key.

Challenges are the existing single use, 5 minute mechanism with distinct purposes, and every record is
JCS bytes that name the purpose, challenge, key thumbprint and origin, so a signature made for one use
cannot be replayed as another. Refusals are logged before the answer (INV-12). Deterministic (INV-1).
"""

from __future__ import annotations

import re
import secrets
from dataclasses import dataclass
from typing import TYPE_CHECKING, Any

from sqlalchemy import select
from sqlalchemy.exc import IntegrityError

from countersign.canonical.jcs import JcsError, canonicalize
from countersign.canonical.jsonstrict import loads_strict
from countersign.catalog.catalog import load_catalog
from countersign.tables import agent_proposals, consent_records, proposal_uses
from countersign.trusted_surface.consent import (
    CURRENCY,
    MAX_CEILING_MINOR,
    MAX_ITEMS,
    MAX_MANDATE_SECONDS,
    MAX_QUANTITY,
    MIN_MANDATE_SECONDS,
    ConsentRefused,
)
from countersign.trusted_surface.keys import (
    KeyRefused,
    validate_public_jwk,
    verify_signature,
)

if TYPE_CHECKING:
    from countersign.trusted_surface.service import TrustedSurface

PURPOSE_PROPOSAL = "countersign.agent.proposal.v1"
PURPOSE_FETCH = "countersign.agent.fetch.v1"
CHALLENGE_PURPOSE_PROPOSAL = "agent_proposal"
CHALLENGE_PURPOSE_FETCH = "agent_fetch"
PROPOSAL_TTL_US = 15 * 60 * 1_000_000
PROPOSAL_ID = re.compile(r"prp_[A-Za-z0-9_-]{16}")
LOG_KIND_PROPOSAL = "ts.proposal.created"
LOG_KIND_PROPOSAL_REFUSED = "ts.proposal.refused"
LOG_KIND_FETCHED = "ts.mandates.fetched"
LOG_KIND_FETCH_REFUSED = "ts.mandates.refused"
_ITEM_ID = re.compile(r"[\x20-\x7e]{1,200}")
_PROPOSAL_MEMBERS = frozenset({"items", "ceiling_minor", "currency", "mandate_expires_at"})


@dataclass(frozen=True)
class Proposed:
    proposal_id: str
    expires_us: int
    agent_thumbprint: str


@dataclass(frozen=True)
class ProposalView:
    proposal_id: str
    items: list[dict[str, Any]]
    ceiling_minor: int
    currency: str
    mandate_expires_at: int
    agent_jwk: dict[str, str]
    expires_us: int


@dataclass(frozen=True)
class Fetched:
    consent_id: str
    customer_id: str
    checkout_mandate: str
    payment_mandate: str
    expires_at: int


def proposal_record(
    *, challenge_id: str, nonce: str, agent_thumbprint: str, origin: str, terms: dict[str, Any]
) -> bytes:
    try:
        return canonicalize(
            {
                "v": 1, "purpose": PURPOSE_PROPOSAL, "challenge_id": challenge_id,
                "challenge": nonce, "agent_thumbprint": agent_thumbprint, "origin": origin,
                "proposal": terms,
            }
        )  # fmt: skip
    except JcsError:
        raise KeyRefused("proof_invalid") from None


def fetch_record(
    *, challenge_id: str, nonce: str, agent_thumbprint: str, origin: str, proposal_id: str
) -> bytes:
    try:
        return canonicalize(
            {
                "v": 1, "purpose": PURPOSE_FETCH, "challenge_id": challenge_id,
                "challenge": nonce, "agent_thumbprint": agent_thumbprint, "origin": origin,
                "proposal_id": proposal_id,
            }
        )  # fmt: skip
    except JcsError:
        raise KeyRefused("proof_invalid") from None


def check_proposal_terms(value: object, now_s: int) -> dict[str, Any]:
    """The proposal's shape and meaning: catalog items, a sane ceiling, a short expiry."""
    bad = "proposal_invalid"
    if not isinstance(value, dict) or set(value) != _PROPOSAL_MEMBERS:
        raise ConsentRefused(bad, "members")
    items = value["items"]
    if not isinstance(items, list) or not 1 <= len(items) <= MAX_ITEMS:
        raise ConsentRefused(bad, "items")
    known = {item.id for item in load_catalog().items}
    seen: set[str] = set()
    for item in items:
        if (
            not isinstance(item, dict) or set(item) != {"id", "quantity"}
            or not isinstance(item["id"], str) or _ITEM_ID.fullmatch(item["id"]) is None
            or type(item["quantity"]) is not int or not 1 <= item["quantity"] <= MAX_QUANTITY
        ):  # fmt: skip
            raise ConsentRefused(bad, "item")
        if item["id"] not in known or item["id"] in seen:
            raise ConsentRefused(bad, "item is not in the catalog or repeated")
        seen.add(item["id"])
    ceiling, expiry = value["ceiling_minor"], value["mandate_expires_at"]
    if type(ceiling) is not int or not 1 <= ceiling <= MAX_CEILING_MINOR:
        raise ConsentRefused(bad, "ceiling")
    if value["currency"] != CURRENCY:
        raise ConsentRefused(bad, "currency")
    if type(expiry) is not int or not MIN_MANDATE_SECONDS <= expiry - now_s <= MAX_MANDATE_SECONDS:
        raise ConsentRefused(bad, "expiry")
    return {
        "items": [{"id": i["id"], "quantity": i["quantity"]} for i in items],
        "ceiling_minor": ceiling, "currency": CURRENCY, "mandate_expires_at": expiry,
    }  # fmt: skip


def create_proposal(
    ts: TrustedSurface,
    *,
    challenge_id: object,
    agent_jwk: object,
    proposal: object,
    origin: object,
    signature: object,
    origin_header: str | None = None,
) -> Proposed:
    from countersign.trusted_surface.service import CHALLENGE_ID, _Seen

    seen = _Seen(
        challenge_id=challenge_id
        if isinstance(challenge_id, str) and CHALLENGE_ID.fullmatch(challenge_id)
        else None
    )

    def work() -> Proposed:
        key = validate_public_jwk(agent_jwk)
        seen.thumbprint = key.thumbprint
        if not isinstance(signature, str) or seen.challenge_id is None:
            raise ts.refusal_for("malformed_request")
        ts.check_origin(origin, origin_header)
        with ts.engine.begin() as conn:
            now_us = ts.now_us()
            row = ts.challenge(conn, seen.challenge_id, CHALLENGE_PURPOSE_PROPOSAL, now_us)
            terms = check_proposal_terms(proposal, now_us // 1_000_000)
            record = proposal_record(
                challenge_id=seen.challenge_id, nonce=row.nonce, agent_thumbprint=key.thumbprint,
                origin=ts.origin, terms=terms,
            )  # fmt: skip
            if not verify_signature(key.verifying_key(), record, signature):
                raise ts.refusal_for("proof_invalid")
            proposal_id = "prp_" + secrets.token_urlsafe(12)
            ts.consume(conn, seen.challenge_id, key.thumbprint, now_us)
            conn.execute(
                agent_proposals.insert().values(
                    id=proposal_id, challenge_id=seen.challenge_id, agent_thumbprint=key.thumbprint,
                    agent_jwk=canonicalize(key.jwk).decode(), terms=canonicalize(terms).decode(),
                    signature=signature, created_us=now_us,
                )
            )  # fmt: skip
            ts.append(
                conn, LOG_KIND_PROPOSAL, now_us,
                {"proposal_id": proposal_id, "agent_thumbprint": key.thumbprint,
                 "challenge_id": seen.challenge_id},
            )  # fmt: skip
            return Proposed(proposal_id, now_us + PROPOSAL_TTL_US, key.thumbprint)

    result: Proposed = ts.guard(LOG_KIND_PROPOSAL_REFUSED, seen, work)
    return result


def load_proposal(ts: TrustedSurface, conn: Any, proposal_id: object) -> Any:
    if not isinstance(proposal_id, str) or PROPOSAL_ID.fullmatch(proposal_id) is None:
        raise ts.refusal_for("proposal_unknown")
    row = conn.execute(select(agent_proposals).where(agent_proposals.c.id == proposal_id)).first()
    if row is None:
        raise ts.refusal_for("proposal_unknown")
    return row


def view_proposal(ts: TrustedSurface, proposal_id: object) -> ProposalView:
    """What the approval page loads by id. Refuses an unknown, expired or spent proposal."""
    from countersign.trusted_surface.service import _Seen

    def work() -> ProposalView:
        with ts.engine.connect() as conn:
            row = load_proposal(ts, conn, proposal_id)
            if ts.now_us() >= int(row.created_us) + PROPOSAL_TTL_US:
                raise ts.refusal_for("proposal_expired")
            used = conn.execute(
                select(proposal_uses.c.proposal_id).where(proposal_uses.c.proposal_id == row.id)
            ).first()
            if used is not None:
                raise ts.refusal_for("proposal_used")
        terms: Any = loads_strict(str(row.terms).encode())
        jwk: Any = loads_strict(str(row.agent_jwk).encode())
        return ProposalView(
            str(row.id), list(terms["items"]), int(terms["ceiling_minor"]), str(terms["currency"]),
            int(terms["mandate_expires_at"]), dict(jwk), int(row.created_us) + PROPOSAL_TTL_US,
        )  # fmt: skip

    result: ProposalView = ts.guard(LOG_KIND_PROPOSAL_REFUSED, _Seen(), work)
    return result


def fetch_mandates(
    ts: TrustedSurface,
    *,
    proposal_id: object,
    challenge_id: object,
    origin: object,
    signature: object,
    origin_header: str | None = None,
) -> Fetched:
    from countersign.trusted_surface.service import CHALLENGE_ID, _Seen

    seen = _Seen(
        challenge_id=challenge_id
        if isinstance(challenge_id, str) and CHALLENGE_ID.fullmatch(challenge_id)
        else None
    )

    def work() -> Fetched:
        if not isinstance(signature, str) or seen.challenge_id is None:
            raise ts.refusal_for("malformed_request")
        ts.check_origin(origin, origin_header)
        with ts.engine.begin() as conn:
            now_us = ts.now_us()
            proposal = load_proposal(ts, conn, proposal_id)
            row = ts.challenge(conn, seen.challenge_id, CHALLENGE_PURPOSE_FETCH, now_us)
            # The key that must sign is the one the proposal stored, which is the key in `cnf`.
            key = validate_public_jwk(loads_strict(str(proposal.agent_jwk).encode()))
            seen.thumbprint = key.thumbprint
            record = fetch_record(
                challenge_id=seen.challenge_id, nonce=row.nonce, agent_thumbprint=key.thumbprint,
                origin=ts.origin, proposal_id=str(proposal.id),
            )  # fmt: skip
            if not verify_signature(key.verifying_key(), record, signature):
                raise ts.refusal_for("proof_invalid")
            found = conn.execute(
                select(consent_records)
                .select_from(
                    proposal_uses.join(
                        consent_records, consent_records.c.id == proposal_uses.c.consent_id
                    )
                )
                .where(proposal_uses.c.proposal_id == proposal.id)
            ).first()
            if found is None:
                if now_us >= int(proposal.created_us) + PROPOSAL_TTL_US:
                    raise ts.refusal_for("proposal_expired")
                raise ts.refusal_for("consent_pending")
            ts.consume(conn, seen.challenge_id, key.thumbprint, now_us)
            ts.append(
                conn, LOG_KIND_FETCHED, now_us,
                {"proposal_id": proposal.id, "consent_id": found.id,
                 "agent_thumbprint": key.thumbprint, "challenge_id": seen.challenge_id},
            )  # fmt: skip
            return Fetched(
                str(found.id), str(found.customer_id), str(found.checkout_mandate),
                str(found.payment_mandate), int(found.mandate_exp),
            )  # fmt: skip

    result: Fetched = ts.guard(LOG_KIND_FETCH_REFUSED, seen, work)
    return result


def spend_proposal(
    ts: TrustedSurface, conn: Any, proposal_id: str, consent_id: str, now_us: int
) -> None:
    """Spend a proposal for issuing: an INSERT whose primary key is the proposal id."""
    try:
        with conn.begin_nested():
            conn.execute(
                proposal_uses.insert().values(
                    proposal_id=proposal_id, consent_id=consent_id, used_us=now_us
                )
            )
    except IntegrityError:
        raise ts.refusal_for("proposal_used") from None
