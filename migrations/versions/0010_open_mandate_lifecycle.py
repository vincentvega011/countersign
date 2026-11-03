"""Open mandate identity, insert-only revocation, agent proposals, purchase offers, activity sessions.

Revision ID: 0010
Revises: 0009

Security reasoning. Every table is insert only for the runtime role (SELECT and INSERT, no UPDATE and
no DELETE), so nothing here can be edited or un-revoked by the running service.

- `open_mandates`: the registry of open mandate pairs the platform issued. Its key is the payment
  open mandate identity, a hash of the issuer-signed content that does not depend on how the mandate
  is presented (PROTOCOL.md Decision 86).
- `open_mandate_revocations`: a mandate is revoked when a row exists. It replaces `mandate_revocations`
  of migration 0004, which was keyed on a presentation-dependent digest; that table is dropped (it was
  never written by a running service) and the downgrade restores it.
- `agent_proposals`, `proposal_uses`: the backend channel by which an agent asks for consent
  (Decision 87). A proposal is spent for issuing by inserting a `proposal_uses` row.
- `purchase_offers`, `purchase_consents`: the merchant-signed checkout a customer is shown and the
  consent that follows (Decision 90).
- `activity_sessions`: short lived read sessions proven by a device key (Decision 92); only the hash of
  the token is stored.
"""

import os
import re

import sqlalchemy as sa
from alembic import context, op

revision = "0010"
down_revision = "0009"
branch_labels = None
depends_on = None

_ROLE = re.compile(r"[a-z_][a-z0-9_]{0,62}")
_NEW = (
    "open_mandates", "open_mandate_revocations", "agent_proposals", "proposal_uses",
    "purchase_offers", "purchase_consents", "activity_sessions",
)  # fmt: skip


def _app_role() -> str:
    role = (
        context.config.attributes.get("app_role")
        or os.environ.get("LEDGER_APP_ROLE")
        or "countersign_app"
    )
    if not _ROLE.fullmatch(role):
        raise RuntimeError("the application role must be a lowercase identifier")
    return str(role)


def upgrade() -> None:
    op.drop_table("mandate_revocations")
    op.create_table(
        "open_mandates",
        sa.Column("id", sa.Text, primary_key=True),
        sa.Column("checkout_identity", sa.Text, nullable=False, unique=True),
        sa.Column("customer_id", sa.Text, nullable=False),
        sa.Column(
            "consent_id", sa.Text, sa.ForeignKey("consent_records.id"), nullable=False, unique=True
        ),
        sa.Column("agent_thumbprint", sa.Text, nullable=False),
        sa.Column("ceiling_minor", sa.BigInteger, nullable=False),
        sa.Column("currency", sa.Text, nullable=False),
        sa.Column("exp", sa.BigInteger, nullable=False),
        sa.Column("created_us", sa.BigInteger, nullable=False),
    )
    op.create_index("open_mandates_customer_idx", "open_mandates", ["customer_id"])
    op.create_table(
        "open_mandate_revocations",
        sa.Column("payment_identity", sa.Text, primary_key=True),
        sa.Column("checkout_identity", sa.Text, nullable=False, unique=True),
        sa.Column("customer_id", sa.Text),
        sa.Column("signer_thumbprint", sa.Text),
        sa.Column("challenge_id", sa.Text),
        sa.Column("record", sa.Text),
        sa.Column("signature", sa.Text),
        sa.Column("revoked_us", sa.BigInteger, nullable=False),
    )
    op.create_table(
        "agent_proposals",
        sa.Column("id", sa.Text, primary_key=True),
        sa.Column(
            "challenge_id", sa.Text, sa.ForeignKey("key_challenges.id"), nullable=False, unique=True
        ),
        sa.Column("agent_thumbprint", sa.Text, nullable=False),
        sa.Column("agent_jwk", sa.Text, nullable=False),
        sa.Column("terms", sa.Text, nullable=False),
        sa.Column("signature", sa.Text, nullable=False),
        sa.Column("created_us", sa.BigInteger, nullable=False),
    )
    op.create_table(
        "proposal_uses",
        sa.Column("proposal_id", sa.Text, sa.ForeignKey("agent_proposals.id"), primary_key=True),
        sa.Column(
            "consent_id", sa.Text, sa.ForeignKey("consent_records.id"), nullable=False, unique=True
        ),
        sa.Column("used_us", sa.BigInteger, nullable=False),
    )
    op.create_table(
        "purchase_offers",
        sa.Column("id", sa.Text, primary_key=True),
        sa.Column("checkout_id", sa.Text, nullable=False),
        sa.Column("checkout_jwt", sa.Text, nullable=False),
        sa.Column("checkout_hash", sa.Text, nullable=False),
        sa.Column("terms", sa.Text, nullable=False),
        sa.Column("created_us", sa.BigInteger, nullable=False),
    )
    op.create_table(
        "purchase_consents",
        sa.Column("id", sa.Text, primary_key=True),
        sa.Column(
            "offer_id", sa.Text, sa.ForeignKey("purchase_offers.id"), nullable=False, unique=True
        ),
        sa.Column(
            "challenge_id", sa.Text, sa.ForeignKey("key_challenges.id"), nullable=False, unique=True
        ),
        sa.Column("customer_id", sa.Text, nullable=False),
        sa.Column(
            "device_thumbprint", sa.Text, sa.ForeignKey("customer_keys.thumbprint"), nullable=False
        ),
        sa.Column("device_jwk", sa.Text, nullable=False),
        sa.Column("record", sa.Text, nullable=False),
        sa.Column("signature", sa.Text, nullable=False),
        sa.Column("checkout_mandate", sa.Text, nullable=False),
        sa.Column("payment_mandate", sa.Text, nullable=False),
        sa.Column("created_us", sa.BigInteger, nullable=False),
    )
    op.create_table(
        "activity_sessions",
        sa.Column("token_hash", sa.Text, primary_key=True),
        sa.Column("customer_id", sa.Text, nullable=False),
        sa.Column(
            "device_thumbprint", sa.Text, sa.ForeignKey("customer_keys.thumbprint"), nullable=False
        ),
        sa.Column(
            "challenge_id", sa.Text, sa.ForeignKey("key_challenges.id"), nullable=False, unique=True
        ),
        sa.Column("created_us", sa.BigInteger, nullable=False),
    )
    role = _app_role()
    for table in _NEW:
        op.execute(f"REVOKE ALL ON TABLE {table} FROM PUBLIC")
        op.execute(f'GRANT SELECT, INSERT ON TABLE {table} TO "{role}"')


def downgrade() -> None:
    for table in reversed(_NEW):
        op.drop_table(table)
    op.create_table(
        "mandate_revocations",
        sa.Column("mandate_digest", sa.Text, primary_key=True),
        sa.Column("revoked_us", sa.BigInteger, nullable=False),
    )
    role = _app_role()
    op.execute("REVOKE ALL ON TABLE mandate_revocations FROM PUBLIC")
    op.execute(f'GRANT SELECT, INSERT ON TABLE mandate_revocations TO "{role}"')
