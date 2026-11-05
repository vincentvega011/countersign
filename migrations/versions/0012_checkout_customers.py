"""The customer a checkout belongs to, where its data comes from, and whom an offer was opened for.

`checkout_customers` holds one row per checkout, written once: at create when the delegation names a
customer, otherwise by the first Human Present offer or the first verified complete. It never changes.
`purchase_offers.customer_id` names the customer whose device key opened the offer (NULL for rows from
before this revision, which are refused at consent). `checkout_sources` labels each checkout with the
PayPal it was written against (`live_sandbox`, `recorded` or `simulator`), so the dashboard never shows a
simulated row as a sandbox capture. The runtime role has SELECT and INSERT only.

Revision ID: 0012
Revises: 0011
"""

from __future__ import annotations

import os
import re

import sqlalchemy as sa
from alembic import context, op

revision = "0012"
down_revision = "0011"
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
        "checkout_customers",
        sa.Column("checkout_id", sa.Text, primary_key=True),
        sa.Column("customer_id", sa.Text, nullable=False),
        sa.Column("agent_thumbprint", sa.Text, nullable=True),
        sa.Column("source", sa.Text, nullable=False),
        sa.Column("created_us", sa.BigInteger, nullable=False),
    )
    op.create_table(
        "checkout_sources",
        sa.Column("checkout_id", sa.Text, primary_key=True),
        sa.Column("source", sa.Text, nullable=False),
        sa.Column("created_us", sa.BigInteger, nullable=False),
        sa.CheckConstraint(
            "source IN ('live_sandbox', 'recorded', 'simulator')", name="checkout_sources_label"
        ),
    )
    op.add_column("purchase_offers", sa.Column("customer_id", sa.Text, nullable=True))
    role = _app_role()
    for table in ("checkout_customers", "checkout_sources"):
        op.execute(f"REVOKE ALL ON TABLE {table} FROM PUBLIC")
        op.execute(f'GRANT SELECT, INSERT ON TABLE {table} TO "{role}"')


def downgrade() -> None:
    op.drop_column("purchase_offers", "customer_id")
    op.drop_table("checkout_sources")
    op.drop_table("checkout_customers")
