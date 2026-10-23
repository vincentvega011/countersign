"""Create the append-only decision log and grant the application role INSERT and SELECT only.

Revision ID: 0001
Revises:
"""

import os
import re

import sqlalchemy as sa
from alembic import context, op

revision = "0001"
down_revision = None
branch_labels = None
depends_on = None

_ROLE = re.compile(r"[a-z_][a-z0-9_]{0,62}")


def _app_role() -> str:
    """The application role: Alembic attribute, then LEDGER_APP_ROLE, then the default."""
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
        "decision_log",
        sa.Column("seq", sa.BigInteger, primary_key=True, autoincrement=False),
        sa.Column("ts_us", sa.BigInteger, nullable=False),
        sa.Column("checkout_id", sa.Text),
        sa.Column("kind", sa.Text, nullable=False),
        sa.Column("payload", sa.LargeBinary, nullable=False),
        sa.Column("payload_hash", sa.LargeBinary, nullable=False),
        sa.Column("policy_hash", sa.LargeBinary, nullable=False),
        sa.Column("prev_hash", sa.LargeBinary, nullable=False),
        sa.Column("entry_hash", sa.LargeBinary, nullable=False),
        sa.UniqueConstraint("prev_hash", name="decision_log_prev_hash_key"),
        sa.UniqueConstraint("entry_hash", name="decision_log_entry_hash_key"),
        sa.CheckConstraint("seq >= 1", name="decision_log_seq_positive"),
        sa.CheckConstraint("ts_us >= 0", name="decision_log_ts_nonnegative"),
        sa.CheckConstraint(
            "kind ~ '^[A-Za-z0-9][A-Za-z0-9._:-]{0,63}$'", name="decision_log_kind_shape"
        ),
        sa.CheckConstraint(
            "checkout_id IS NULL OR (octet_length(checkout_id) BETWEEN 1 AND 127)",
            name="decision_log_checkout_id_shape",
        ),
        sa.CheckConstraint("octet_length(payload) >= 2", name="decision_log_payload_present"),
        sa.CheckConstraint("octet_length(payload_hash) = 32", name="decision_log_payload_hash_len"),
        sa.CheckConstraint("octet_length(policy_hash) = 32", name="decision_log_policy_hash_len"),
        sa.CheckConstraint("octet_length(prev_hash) = 32", name="decision_log_prev_hash_len"),
        sa.CheckConstraint("octet_length(entry_hash) = 32", name="decision_log_entry_hash_len"),
    )
    op.create_index("decision_log_checkout_idx", "decision_log", ["checkout_id", "seq"])
    op.create_index("decision_log_ts_idx", "decision_log", ["ts_us"])

    role = _app_role()
    bind = op.get_bind()
    exists = bind.execute(sa.text("SELECT 1 FROM pg_roles WHERE rolname = :r"), {"r": role}).first()
    if exists is None:
        # NOLOGIN: the operator sets the login and password out of band.
        op.execute(f'CREATE ROLE "{role}" NOLOGIN')
    op.execute("REVOKE ALL ON TABLE decision_log FROM PUBLIC")
    op.execute(f'GRANT SELECT, INSERT ON TABLE decision_log TO "{role}"')


def downgrade() -> None:
    op.drop_index("decision_log_ts_idx", table_name="decision_log")
    op.drop_index("decision_log_checkout_idx", table_name="decision_log")
    op.drop_table("decision_log")
