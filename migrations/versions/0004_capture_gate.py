"""Capture gate state: attempt states, stored mandates, mandate revocations.

Revision ID: 0004
Revises: 0003

Security reasoning.

- `payment_attempts` gains the states the capture gate moves through (`gating`, `capturing`,
  `captured`) and the columns it records (`capture_id`, `receipt`, `gate_code`, `gate_reason`).
  The guard trigger is replaced: `captured` is final like `voided`, and `capture_id` and `receipt`
  never change once set. The claim `authorized` to `gating` is one conditional UPDATE, so two
  gates racing on one checkout cannot both win it (docs/PROTOCOL.md Decision 41).
- `attempt_mandates` keeps the presented Payment Mandate token and Checkout Mandate of an attempt,
  insert only, so the gate verifies the mandates again at capture time from what was presented and
  not from anything a caller passes in (INV-4).
- `mandate_revocations` is insert only: a revocation of an open mandate cannot be undone by the
  application role.

The application role gets SELECT and INSERT on the new tables, and keeps SELECT, INSERT and UPDATE
on `payment_attempts` (revision 0003).
"""

import os
import re

import sqlalchemy as sa
from alembic import context, op

revision = "0004"
down_revision = "0003"
branch_labels = None
depends_on = None

_ROLE = re.compile(r"[a-z_][a-z0-9_]{0,62}")

_OLD_STATES = (
    "'reserved', 'order_created', 'authorizing', 'authorized', 'abandoned', 'voided', "
    "'failed', 'unresolved'"
)
_NEW_STATES = _OLD_STATES + ", 'gating', 'capturing', 'captured'"


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
    op.drop_constraint("payment_attempts_state_known", "payment_attempts", type_="check")
    op.create_check_constraint(
        "payment_attempts_state_known", "payment_attempts", f"state IN ({_NEW_STATES})"
    )
    for column in ("capture_id", "receipt", "gate_code", "gate_reason"):
        op.add_column("payment_attempts", sa.Column(column, sa.Text))
    op.execute(
        """
        CREATE OR REPLACE FUNCTION payment_attempts_guard() RETURNS trigger LANGUAGE plpgsql AS $$
        BEGIN
          IF NEW.checkout_id <> OLD.checkout_id OR NEW.spend_id <> OLD.spend_id
             OR NEW.reservation_handle <> OLD.reservation_handle
             OR NEW.mandate_digest <> OLD.mandate_digest OR NEW.custom_id <> OLD.custom_id
             OR NEW.created_us <> OLD.created_us THEN
            RAISE EXCEPTION 'payment attempt identity is immutable' USING ERRCODE = 'check_violation';
          END IF;
          IF OLD.state IN ('abandoned', 'voided', 'failed', 'captured') THEN
            RAISE EXCEPTION 'a finished payment attempt is final' USING ERRCODE = 'check_violation';
          END IF;
          IF OLD.order_id IS NOT NULL AND NEW.order_id IS DISTINCT FROM OLD.order_id THEN
            RAISE EXCEPTION 'the PayPal order of an attempt does not change'
              USING ERRCODE = 'check_violation';
          END IF;
          IF OLD.capture_id IS NOT NULL AND NEW.capture_id IS DISTINCT FROM OLD.capture_id THEN
            RAISE EXCEPTION 'the capture of an attempt does not change'
              USING ERRCODE = 'check_violation';
          END IF;
          IF NEW.state = 'captured' AND (NEW.capture_id IS NULL OR NEW.receipt IS NULL) THEN
            RAISE EXCEPTION 'a captured attempt names its capture and receipt'
              USING ERRCODE = 'check_violation';
          END IF;
          RETURN NEW;
        END $$
        """
    )

    op.create_table(
        "attempt_mandates",
        sa.Column("checkout_id", sa.Text, primary_key=True),
        sa.Column("payment_token", sa.Text, nullable=False),
        sa.Column("checkout_mandate", sa.Text, nullable=False),
        sa.Column("created_us", sa.BigInteger, nullable=False),
    )
    op.create_table(
        "mandate_revocations",
        sa.Column("mandate_digest", sa.Text, primary_key=True),
        sa.Column("revoked_us", sa.BigInteger, nullable=False),
    )
    role = _app_role()
    for table in ("attempt_mandates", "mandate_revocations"):
        op.execute(f"REVOKE ALL ON TABLE {table} FROM PUBLIC")
        op.execute(f'GRANT SELECT, INSERT ON TABLE {table} TO "{role}"')


def downgrade() -> None:
    op.drop_table("mandate_revocations")
    op.drop_table("attempt_mandates")
    op.execute(
        """
        CREATE OR REPLACE FUNCTION payment_attempts_guard() RETURNS trigger LANGUAGE plpgsql AS $$
        BEGIN
          IF NEW.checkout_id <> OLD.checkout_id OR NEW.spend_id <> OLD.spend_id
             OR NEW.reservation_handle <> OLD.reservation_handle
             OR NEW.mandate_digest <> OLD.mandate_digest OR NEW.custom_id <> OLD.custom_id
             OR NEW.created_us <> OLD.created_us THEN
            RAISE EXCEPTION 'payment attempt identity is immutable' USING ERRCODE = 'check_violation';
          END IF;
          IF OLD.state IN ('abandoned', 'voided', 'failed') THEN
            RAISE EXCEPTION 'a finished payment attempt is final' USING ERRCODE = 'check_violation';
          END IF;
          IF OLD.order_id IS NOT NULL AND NEW.order_id IS DISTINCT FROM OLD.order_id THEN
            RAISE EXCEPTION 'the PayPal order of an attempt does not change'
              USING ERRCODE = 'check_violation';
          END IF;
          RETURN NEW;
        END $$
        """
    )
    for column in ("gate_reason", "gate_code", "receipt", "capture_id"):
        op.drop_column("payment_attempts", column)
    op.drop_constraint("payment_attempts_state_known", "payment_attempts", type_="check")
    op.create_check_constraint(
        "payment_attempts_state_known", "payment_attempts", f"state IN ({_OLD_STATES})"
    )
