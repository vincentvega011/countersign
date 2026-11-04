"""Evidence: sanitized PayPal observations and frozen evidence bundles (insert only).

`paypal_observations` keeps an allowlisted copy of each order, authorization and capture the service
READ from PayPal (never a header, a token or a payer member). `evidence_bundles` keeps the bundle
assembled at capture, keyed by the PayPal capture id. The runtime role has SELECT and INSERT only.

Revision ID: 0011
Revises: 0010
"""

from __future__ import annotations

import os
import re

import sqlalchemy as sa
from alembic import context, op

revision = "0011"
down_revision = "0010"
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
        "paypal_observations",
        sa.Column("seq", sa.BigInteger, sa.Identity(), primary_key=True),
        sa.Column("kind", sa.Text, nullable=False),
        sa.Column("object_id", sa.Text, nullable=False),
        sa.Column("body", sa.Text, nullable=False),
        sa.Column("observed_us", sa.BigInteger, nullable=False),
    )
    op.create_index("paypal_observations_object_idx", "paypal_observations", ["object_id", "seq"])
    op.create_table(
        "evidence_bundles",
        sa.Column("capture_id", sa.Text, primary_key=True),
        sa.Column("checkout_id", sa.Text, nullable=False, unique=True),
        sa.Column("bundle", sa.Text, nullable=False),
        sa.Column("created_us", sa.BigInteger, nullable=False),
    )
    role = _app_role()
    for table in ("paypal_observations", "evidence_bundles"):
        op.execute(f"REVOKE ALL ON TABLE {table} FROM PUBLIC")
        op.execute(f'GRANT SELECT, INSERT ON TABLE {table} TO "{role}"')
    op.execute(f'GRANT USAGE ON SEQUENCE paypal_observations_seq_seq TO "{role}"')


def downgrade() -> None:
    op.drop_table("evidence_bundles")
    op.drop_table("paypal_observations")
