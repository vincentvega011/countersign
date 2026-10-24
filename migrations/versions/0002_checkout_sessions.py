"""Create checkout session storage for the UCP checkout binding.

Revision ID: 0002
Revises: 0001

The application role may SELECT, INSERT and UPDATE the table and nothing else (no DELETE, no
TRUNCATE). A trigger makes a final checkout (`completed` or `canceled`) immutable and requires every
update to advance `version` by exactly one and to keep `id` and `created_us`, so an application bug
or a stale writer cannot reopen a finished checkout or rewrite its history.
"""

import os
import re

import sqlalchemy as sa
from alembic import context, op

revision = "0002"
down_revision = "0001"
branch_labels = None
depends_on = None

_ROLE = re.compile(r"[a-z_][a-z0-9_]{0,62}")
_STATUSES = (
    "incomplete",
    "requires_escalation",
    "ready_for_complete",
    "complete_in_progress",
    "completed",
    "canceled",
)


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
    statuses = ", ".join(f"'{s}'" for s in _STATUSES)
    op.create_table(
        "checkout_sessions",
        sa.Column("id", sa.Text, primary_key=True),
        sa.Column("status", sa.Text, nullable=False),
        sa.Column("version", sa.Integer, nullable=False),
        sa.Column("checkout", sa.LargeBinary, nullable=False),
        sa.Column("next_line_seq", sa.Integer, nullable=False),
        sa.Column("catalog_hash", sa.LargeBinary, nullable=False),
        sa.Column("created_us", sa.BigInteger, nullable=False),
        sa.Column("updated_us", sa.BigInteger, nullable=False),
        sa.Column("expires_us", sa.BigInteger, nullable=False),
        sa.CheckConstraint("id ~ '^chk_[A-Za-z0-9_-]{22}$'", name="checkout_sessions_id_shape"),
        sa.CheckConstraint(f"status IN ({statuses})", name="checkout_sessions_status_known"),
        sa.CheckConstraint("version >= 1", name="checkout_sessions_version_positive"),
        sa.CheckConstraint("next_line_seq >= 1", name="checkout_sessions_line_seq_positive"),
        sa.CheckConstraint(
            "octet_length(checkout) >= 2", name="checkout_sessions_checkout_present"
        ),
        sa.CheckConstraint(
            "octet_length(catalog_hash) = 32", name="checkout_sessions_catalog_hash"
        ),
        sa.CheckConstraint("expires_us > created_us", name="checkout_sessions_expiry_after_create"),
    )
    op.create_index("checkout_sessions_expires_idx", "checkout_sessions", ["expires_us"])
    op.execute(
        """
        CREATE FUNCTION checkout_sessions_guard() RETURNS trigger LANGUAGE plpgsql AS $$
        BEGIN
          IF OLD.status IN ('completed', 'canceled') THEN
            RAISE EXCEPTION 'checkout is final' USING ERRCODE = 'check_violation';
          END IF;
          IF NEW.id <> OLD.id OR NEW.created_us <> OLD.created_us THEN
            RAISE EXCEPTION 'id and created_us are immutable' USING ERRCODE = 'check_violation';
          END IF;
          IF NEW.version <> OLD.version + 1 THEN
            RAISE EXCEPTION 'version must advance by one' USING ERRCODE = 'check_violation';
          END IF;
          RETURN NEW;
        END $$
        """
    )
    op.execute(
        "CREATE TRIGGER checkout_sessions_guard BEFORE UPDATE ON checkout_sessions "
        "FOR EACH ROW EXECUTE FUNCTION checkout_sessions_guard()"
    )

    role = _app_role()
    bind = op.get_bind()
    exists = bind.execute(sa.text("SELECT 1 FROM pg_roles WHERE rolname = :r"), {"r": role}).first()
    if exists is None:
        op.execute(f'CREATE ROLE "{role}" NOLOGIN')
    op.execute("REVOKE ALL ON TABLE checkout_sessions FROM PUBLIC")
    op.execute(f'GRANT SELECT, INSERT, UPDATE ON TABLE checkout_sessions TO "{role}"')


def downgrade() -> None:
    op.execute("DROP TRIGGER checkout_sessions_guard ON checkout_sessions")
    op.execute("DROP FUNCTION checkout_sessions_guard()")
    op.drop_index("checkout_sessions_expires_idx", table_name="checkout_sessions")
    op.drop_table("checkout_sessions")
