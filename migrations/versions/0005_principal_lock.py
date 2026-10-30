"""Principal lock: merchant lock policy versions and lock events.

Revision ID: 0005
Revises: 0004

Security reasoning. A lock must outlive a session and a process, and an agent must not be able to
undo it, so the runtime role gets SELECT and INSERT only on both tables: no UPDATE and no DELETE
(tests/integration/test_lock_database.py checks the grants).

- `lock_policies`: one row per version of the merchant policy (pure data: mode, integer minor unit
  threshold, currency, and its hash). A change is a new version; nothing is edited.
- `lock_events`: insert only. `lock` records a principal as locked; `unlock` is written only by the
  merchant policy action that also creates a new policy version. A principal is locked when the
  newest event for its key is `lock`. An unknown customer or agent is stored as the empty string.
"""

import os
import re

import sqlalchemy as sa
from alembic import context, op

revision = "0005"
down_revision = "0004"
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
        "lock_policies",
        sa.Column("version", sa.BigInteger, primary_key=True),
        sa.Column("mode", sa.Text, nullable=False),
        sa.Column("threshold_minor", sa.BigInteger),
        sa.Column("currency", sa.Text),
        sa.Column("policy_hash", sa.Text, nullable=False),
        sa.Column("reason", sa.Text, nullable=False),
        sa.Column("created_us", sa.BigInteger, nullable=False),
        sa.CheckConstraint("version >= 1", name="lock_policies_version"),
        sa.CheckConstraint("mode IN ('off', 'all', 'over_threshold')", name="lock_policies_mode"),
        sa.CheckConstraint(
            "(mode = 'over_threshold') = (threshold_minor IS NOT NULL AND currency IS NOT NULL)",
            name="lock_policies_threshold_shape",
        ),
        sa.CheckConstraint(
            "threshold_minor IS NULL OR threshold_minor >= 0", name="lock_threshold"
        ),
    )
    op.create_table(
        "lock_events",
        sa.Column("seq", sa.BigInteger, sa.Identity(), primary_key=True),
        sa.Column("kind", sa.Text, nullable=False),
        sa.Column("customer_id", sa.Text, nullable=False),
        sa.Column("agent_thumbprint", sa.Text, nullable=False),
        sa.Column("policy_version", sa.BigInteger, nullable=False),
        sa.Column("checkout_id", sa.Text),
        sa.Column("created_us", sa.BigInteger, nullable=False),
        sa.CheckConstraint("kind IN ('lock', 'unlock')", name="lock_events_kind"),
        sa.CheckConstraint(
            "customer_id <> '' OR agent_thumbprint <> ''", name="lock_events_some_identity"
        ),
    )
    op.create_index(
        "lock_events_key_idx", "lock_events", ["customer_id", "agent_thumbprint", "seq"]
    )
    op.create_index("lock_events_agent_idx", "lock_events", ["agent_thumbprint", "seq"])
    op.create_index("lock_events_customer_idx", "lock_events", ["customer_id", "seq"])
    role = _app_role()
    for table in ("lock_policies", "lock_events"):
        op.execute(f"REVOKE ALL ON TABLE {table} FROM PUBLIC")
        op.execute(f'GRANT SELECT, INSERT ON TABLE {table} TO "{role}"')
    # The identity sequence needs USAGE for INSERT by the runtime role.
    op.execute(f'GRANT USAGE ON SEQUENCE lock_events_seq_seq TO "{role}"')


def downgrade() -> None:
    op.drop_table("lock_events")
    op.drop_table("lock_policies")
