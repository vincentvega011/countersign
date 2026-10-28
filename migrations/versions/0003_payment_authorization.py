"""Single-use reservations, the spend ledger and payment attempts (Merchant and Credential Provider).

Revision ID: 0003
Revises: 0002

Security reasoning. Single use and the budget must hold across processes and under concurrency, so
they are enforced by the database, not by process memory:

- `reservations`: one row per presentation, per role (`merchant` or `cp`). Partial unique indexes
  make each key unique while the row is not `aborted`: the checkout id (checkout_hash alone is not
  unique per checkout, so the id is its own key), the checkout hash, and the nonce scoped to the
  agent key thumbprint and the audience. A fourth partial unique index allows one open mandate in
  `reserved` or `consumed` state at a time. A `released` row keeps its checkout id, hash and nonce
  consumed and frees the mandate (docs/PROTOCOL.md Decision 28). A trigger allows only the legal
  state changes and makes the keys immutable.
- `open_payment_mandates`: one row per open Payment Mandate digest. Its `FOR UPDATE` lock is the
  row lock under which the budget is checked and reserved.
- `spend_entries`: add-only spend (docs/PROTOCOL.md Decision 33). A trigger allows `in_flight` to
  become `captured` or `voided` once, never changes an amount, and lets `refunded_minor` grow only on
  captured entries and never above the amount. A refund never lowers a captured entry.
- `payment_attempts`: one row per checkout id, the Credential Provider's record of where a
  payment is, so a retry, a crash or a second process resumes from the database.
- `payer_vault`: the vault id of a sandbox wallet per principal (docs/PROTOCOL.md 4.7).

The application role gets SELECT, INSERT and UPDATE only: no DELETE and no TRUNCATE on any of them,
and nothing beyond INSERT and SELECT on the decision log (revision 0001).
"""

import os
import re

import sqlalchemy as sa
from alembic import context, op

revision = "0003"
down_revision = "0002"
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
        "reservations",
        sa.Column("handle", sa.Text, primary_key=True),
        sa.Column("role", sa.Text, nullable=False),
        sa.Column("checkout_id", sa.Text, nullable=False),
        sa.Column("checkout_hash", sa.Text, nullable=False),
        sa.Column("mandate_digest", sa.Text, nullable=False),
        sa.Column("nonce_thumbprint", sa.Text),
        sa.Column("nonce_audience", sa.Text),
        sa.Column("nonce_value", sa.Text),
        sa.Column("state", sa.Text, nullable=False),
        sa.Column("created_us", sa.BigInteger, nullable=False),
        sa.Column("updated_us", sa.BigInteger, nullable=False),
        sa.CheckConstraint("role IN ('merchant', 'cp')", name="reservations_role_known"),
        sa.CheckConstraint(
            "state IN ('reserved', 'released', 'consumed', 'aborted')",
            name="reservations_state_known",
        ),
        sa.CheckConstraint(
            "(nonce_thumbprint IS NULL) = (nonce_audience IS NULL) "
            "AND (nonce_audience IS NULL) = (nonce_value IS NULL)",
            name="reservations_nonce_all_or_none",
        ),
    )
    live = "state <> 'aborted'"
    op.create_index(
        "reservations_checkout_id_key", "reservations", ["role", "checkout_id"],
        unique=True, postgresql_where=sa.text(live),
    )  # fmt: skip
    op.create_index(
        "reservations_checkout_hash_key", "reservations", ["role", "checkout_hash"],
        unique=True, postgresql_where=sa.text(live),
    )  # fmt: skip
    op.create_index(
        "reservations_nonce_key", "reservations",
        ["role", "nonce_thumbprint", "nonce_audience", "nonce_value"],
        unique=True, postgresql_where=sa.text(f"{live} AND nonce_value IS NOT NULL"),
    )  # fmt: skip
    op.create_index(
        "reservations_mandate_key", "reservations", ["role", "mandate_digest"],
        unique=True, postgresql_where=sa.text("state IN ('reserved', 'consumed')"),
    )  # fmt: skip
    op.execute(
        """
        CREATE FUNCTION reservations_guard() RETURNS trigger LANGUAGE plpgsql AS $$
        BEGIN
          IF NEW.handle <> OLD.handle OR NEW.role <> OLD.role
             OR NEW.checkout_id <> OLD.checkout_id OR NEW.checkout_hash <> OLD.checkout_hash
             OR NEW.mandate_digest <> OLD.mandate_digest
             OR NEW.nonce_thumbprint IS DISTINCT FROM OLD.nonce_thumbprint
             OR NEW.nonce_audience IS DISTINCT FROM OLD.nonce_audience
             OR NEW.nonce_value IS DISTINCT FROM OLD.nonce_value
             OR NEW.created_us <> OLD.created_us THEN
            RAISE EXCEPTION 'reservation keys are immutable' USING ERRCODE = 'check_violation';
          END IF;
          IF OLD.state <> 'reserved' OR NEW.state NOT IN ('released', 'consumed', 'aborted') THEN
            RAISE EXCEPTION 'illegal reservation state change' USING ERRCODE = 'check_violation';
          END IF;
          RETURN NEW;
        END $$
        """
    )
    op.execute(
        "CREATE TRIGGER reservations_guard BEFORE UPDATE ON reservations "
        "FOR EACH ROW EXECUTE FUNCTION reservations_guard()"
    )

    op.create_table(
        "open_payment_mandates",
        sa.Column("digest", sa.Text, primary_key=True),
        sa.Column("currency", sa.Text, nullable=False),
        sa.Column("created_us", sa.BigInteger, nullable=False),
        sa.CheckConstraint("currency ~ '^[A-Z]{3}$'", name="open_payment_mandates_currency"),
    )
    op.create_table(
        "spend_entries",
        sa.Column("id", sa.Text, primary_key=True),
        sa.Column(
            "mandate_digest", sa.Text, sa.ForeignKey("open_payment_mandates.digest"), nullable=False
        ),
        sa.Column("checkout_id", sa.Text, nullable=False, unique=True),
        sa.Column("amount_minor", sa.BigInteger, nullable=False),
        sa.Column("currency", sa.Text, nullable=False),
        sa.Column("state", sa.Text, nullable=False),
        sa.Column("refunded_minor", sa.BigInteger, nullable=False, server_default="0"),
        sa.Column("created_us", sa.BigInteger, nullable=False),
        sa.Column("updated_us", sa.BigInteger, nullable=False),
        sa.CheckConstraint("amount_minor > 0", name="spend_entries_amount_positive"),
        sa.CheckConstraint(
            "state IN ('in_flight', 'captured', 'voided')", name="spend_entries_state_known"
        ),
        sa.CheckConstraint(
            "refunded_minor >= 0 AND refunded_minor <= amount_minor",
            name="spend_entries_refund_range",
        ),
        sa.CheckConstraint(
            "refunded_minor = 0 OR state = 'captured'", name="spend_entries_refund_only_captured"
        ),
    )
    op.create_index("spend_entries_mandate_idx", "spend_entries", ["mandate_digest", "state"])
    op.execute(
        """
        CREATE FUNCTION spend_entries_guard() RETURNS trigger LANGUAGE plpgsql AS $$
        BEGIN
          IF NEW.id <> OLD.id OR NEW.mandate_digest <> OLD.mandate_digest
             OR NEW.checkout_id <> OLD.checkout_id OR NEW.amount_minor <> OLD.amount_minor
             OR NEW.currency <> OLD.currency OR NEW.created_us <> OLD.created_us THEN
            RAISE EXCEPTION 'spend entries are add-only' USING ERRCODE = 'check_violation';
          END IF;
          IF NEW.refunded_minor < OLD.refunded_minor THEN
            RAISE EXCEPTION 'a refund never restores headroom' USING ERRCODE = 'check_violation';
          END IF;
          IF NEW.state <> OLD.state AND NOT (OLD.state = 'in_flight'
                                             AND NEW.state IN ('captured', 'voided')) THEN
            RAISE EXCEPTION 'illegal spend state change' USING ERRCODE = 'check_violation';
          END IF;
          RETURN NEW;
        END $$
        """
    )
    op.execute(
        "CREATE TRIGGER spend_entries_guard BEFORE UPDATE ON spend_entries "
        "FOR EACH ROW EXECUTE FUNCTION spend_entries_guard()"
    )

    op.create_table(
        "payment_attempts",
        sa.Column("checkout_id", sa.Text, primary_key=True),
        sa.Column("reservation_handle", sa.Text, nullable=False),
        sa.Column("spend_id", sa.Text, nullable=False),
        sa.Column("mandate_digest", sa.Text, nullable=False),
        sa.Column("state", sa.Text, nullable=False),
        sa.Column("mode", sa.Text, nullable=False),
        sa.Column("custom_id", sa.Text, nullable=False),
        sa.Column("principal", sa.Text),
        sa.Column("order_id", sa.Text),
        sa.Column("authorization_id", sa.Text),
        sa.Column("created_us", sa.BigInteger, nullable=False),
        sa.Column("updated_us", sa.BigInteger, nullable=False),
        sa.CheckConstraint(
            "state IN ('reserved', 'order_created', 'authorizing', 'authorized', 'abandoned', "
            "'voided', 'failed', 'unresolved')",
            name="payment_attempts_state_known",
        ),
        sa.CheckConstraint("mode IN ('redirect', 'vault')", name="payment_attempts_mode_known"),
    )
    op.create_index("payment_attempts_state_idx", "payment_attempts", ["state", "updated_us"])
    op.execute(
        """
        CREATE FUNCTION payment_attempts_guard() RETURNS trigger LANGUAGE plpgsql AS $$
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
    op.execute(
        "CREATE TRIGGER payment_attempts_guard BEFORE UPDATE ON payment_attempts "
        "FOR EACH ROW EXECUTE FUNCTION payment_attempts_guard()"
    )
    op.create_table(
        "payer_vault",
        sa.Column("principal", sa.Text, primary_key=True),
        sa.Column("vault_id", sa.Text, nullable=False),
        sa.Column("created_us", sa.BigInteger, nullable=False),
    )

    role = _app_role()
    bind = op.get_bind()
    exists = bind.execute(sa.text("SELECT 1 FROM pg_roles WHERE rolname = :r"), {"r": role}).first()
    if exists is None:
        op.execute(f'CREATE ROLE "{role}" NOLOGIN')
    for table in (
        "reservations", "open_payment_mandates", "spend_entries", "payment_attempts", "payer_vault",
    ):  # fmt: skip
        op.execute(f"REVOKE ALL ON TABLE {table} FROM PUBLIC")
        op.execute(f'GRANT SELECT, INSERT, UPDATE ON TABLE {table} TO "{role}"')


def downgrade() -> None:
    for table, trigger in (
        ("payment_attempts", "payment_attempts_guard"),
        ("spend_entries", "spend_entries_guard"),
        ("reservations", "reservations_guard"),
    ):
        op.execute(f"DROP TRIGGER {trigger} ON {table}")
        op.execute(f"DROP FUNCTION {trigger}()")
    op.drop_table("payer_vault")
    op.drop_table("payment_attempts")
    op.drop_table("spend_entries")
    op.drop_table("open_payment_mandates")
    op.drop_table("reservations")
