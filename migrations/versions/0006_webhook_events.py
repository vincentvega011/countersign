"""Webhook events: one row per verified PayPal event id, the dedupe key.

Revision ID: 0006
Revises: 0005

Security reasoning. A notification can be delivered twice, in parallel, late or out of order, and
PayPal retries anything the receiver does not acknowledge. The primary key on `event_id` is what makes
processing happen once: the handler inserts the row and works inside the same transaction, so a
second delivery of the same id waits on the unique index and then finds the row finished. A crash
rolls the row back with the work, so the retry starts clean. A trigger lets a row move only from
`processing` to `done` or `ignored` and never change after that; the runtime role has SELECT, INSERT
and UPDATE only (no DELETE, no TRUNCATE).
"""

import os
import re

import sqlalchemy as sa
from alembic import context, op

revision = "0006"
down_revision = "0005"
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
        "webhook_events",
        sa.Column("event_id", sa.Text, primary_key=True),
        sa.Column("event_type", sa.Text, nullable=False),
        sa.Column("state", sa.Text, nullable=False),
        sa.Column("outcome", sa.Text),
        sa.Column("checkout_id", sa.Text),
        sa.Column("received_us", sa.BigInteger, nullable=False),
        sa.Column("finished_us", sa.BigInteger),
        sa.CheckConstraint("state IN ('processing', 'done', 'ignored')", name="webhook_state"),
        sa.CheckConstraint("char_length(event_id) BETWEEN 1 AND 128", name="webhook_event_id_len"),
    )
    op.execute(
        """
        CREATE FUNCTION webhook_events_guard() RETURNS trigger LANGUAGE plpgsql AS $$
        BEGIN
          IF NEW.event_id <> OLD.event_id OR NEW.event_type <> OLD.event_type
             OR NEW.received_us <> OLD.received_us THEN
            RAISE EXCEPTION 'a webhook event row is immutable' USING ERRCODE = 'check_violation';
          END IF;
          IF OLD.state <> 'processing' THEN
            RAISE EXCEPTION 'a finished webhook event is final' USING ERRCODE = 'check_violation';
          END IF;
          RETURN NEW;
        END $$
        """
    )
    op.execute(
        "CREATE TRIGGER webhook_events_guard BEFORE UPDATE ON webhook_events "
        "FOR EACH ROW EXECUTE FUNCTION webhook_events_guard()"
    )
    role = _app_role()
    op.execute("REVOKE ALL ON TABLE webhook_events FROM PUBLIC")
    op.execute(f'GRANT SELECT, INSERT, UPDATE ON TABLE webhook_events TO "{role}"')


def downgrade() -> None:
    op.execute("DROP TRIGGER webhook_events_guard ON webhook_events")
    op.execute("DROP FUNCTION webhook_events_guard()")
    op.drop_table("webhook_events")
