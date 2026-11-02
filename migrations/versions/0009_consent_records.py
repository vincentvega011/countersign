"""Consent records: the signed consent, the device key that signed it and the mandates issued for it.

Revision ID: 0009
Revises: 0008

Security reasoning. A consent record is the evidence that the platform signed open mandates because the
customer's device key said so. It is kept exactly as signed (JCS text and the raw signature), next to the
device public key that verified it and the two open mandates it produced, so a third party can check the
chain without trusting the platform key (PROTOCOL.md Decision 5). The table is insert-only for the
runtime role (SELECT and INSERT), `challenge_id` is unique (one consent per challenge, and the challenge
is also spent in `key_challenge_uses`), and the challenge and the key must exist (foreign keys).
"""

import os
import re

import sqlalchemy as sa
from alembic import context, op

revision = "0009"
down_revision = "0008"
branch_labels = None
depends_on = None

_ROLE = re.compile(r"[a-z_][a-z0-9_]{0,62}")


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
    op.create_table(
        "consent_records",
        sa.Column("id", sa.Text, primary_key=True),
        sa.Column(
            "challenge_id", sa.Text, sa.ForeignKey("key_challenges.id"), nullable=False, unique=True
        ),
        sa.Column("customer_id", sa.Text, nullable=False),
        sa.Column(
            "device_thumbprint", sa.Text, sa.ForeignKey("customer_keys.thumbprint"), nullable=False
        ),
        sa.Column("device_jwk", sa.Text, nullable=False),
        sa.Column("agent_thumbprint", sa.Text, nullable=False),
        sa.Column("record", sa.Text, nullable=False),
        sa.Column("signature", sa.Text, nullable=False),
        sa.Column("checkout_mandate", sa.Text, nullable=False),
        sa.Column("payment_mandate", sa.Text, nullable=False),
        sa.Column("checkout_open_digest", sa.Text, nullable=False),
        sa.Column("payment_open_digest", sa.Text, nullable=False),
        sa.Column("mandate_exp", sa.BigInteger, nullable=False),
        sa.Column("created_us", sa.BigInteger, nullable=False),
    )
    op.create_index("consent_records_customer_idx", "consent_records", ["customer_id"])
    role = _app_role()
    op.execute("REVOKE ALL ON TABLE consent_records FROM PUBLIC")
    op.execute(f'GRANT SELECT, INSERT ON TABLE consent_records TO "{role}"')


def downgrade() -> None:
    op.drop_table("consent_records")
