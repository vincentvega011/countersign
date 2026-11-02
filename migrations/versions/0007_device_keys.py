"""Trusted Surface device keys: challenges, challenge uses and registered customer keys.

Revision ID: 0007
Revises: 0006

Security reasoning. A device key is what later signs consent (PROTOCOL.md Decision 5), so a key row
must never be rewritten, replaced or removed, and a challenge must be spendable exactly once.

- The runtime role has SELECT and INSERT on all three tables: no UPDATE, no DELETE, no TRUNCATE.
- `key_challenges`: one row per issued challenge (random nonce, purpose, issue time). Expiry is not
  stored; it is `created_us` plus the lifetime in code, so no row is ever updated to expire it.
- `key_challenge_uses`: consuming a challenge is an INSERT with the challenge id as primary key. Of
  any number of simultaneous registrations on one challenge the unique index lets exactly one commit;
  the others get a unique violation, which the service reports as `challenge_used`.
- `customer_keys`: add-only. The thumbprint is the primary key, so one key belongs to one customer
  for ever. `revoked_us` is the only column that may ever change, and only from NULL to a value, once
  (trigger). The runtime role cannot set it: revocation is an owner action until the revoke flow is
  built (PROTOCOL.md Decision 77). A trigger also refuses DELETE for every role.
"""

import os
import re

import sqlalchemy as sa
from alembic import context, op

revision = "0007"
down_revision = "0006"
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
        "key_challenges",
        sa.Column("id", sa.Text, primary_key=True),
        sa.Column("purpose", sa.Text, nullable=False),
        sa.Column("nonce", sa.Text, nullable=False, unique=True),
        sa.Column("created_us", sa.BigInteger, nullable=False),
        sa.CheckConstraint("char_length(id) BETWEEN 8 AND 64", name="key_challenges_id_len"),
        sa.CheckConstraint(
            "char_length(nonce) BETWEEN 32 AND 128", name="key_challenges_nonce_len"
        ),
        sa.CheckConstraint(
            "char_length(purpose) BETWEEN 1 AND 64", name="key_challenges_purpose_len"
        ),
    )
    op.create_table(
        "key_challenge_uses",
        sa.Column("challenge_id", sa.Text, sa.ForeignKey("key_challenges.id"), primary_key=True),
        sa.Column("thumbprint", sa.Text, nullable=False),
        sa.Column("used_us", sa.BigInteger, nullable=False),
    )
    op.create_table(
        "customer_keys",
        sa.Column("customer_id", sa.Text, nullable=False),
        sa.Column("thumbprint", sa.Text, primary_key=True),
        sa.Column("jwk", sa.Text, nullable=False),
        sa.Column("created_us", sa.BigInteger, nullable=False),
        sa.Column("revoked_us", sa.BigInteger),
        sa.CheckConstraint("char_length(customer_id) BETWEEN 1 AND 128", name="customer_keys_cid"),
        sa.CheckConstraint("char_length(thumbprint) = 43", name="customer_keys_thumbprint_len"),
        sa.CheckConstraint(
            "revoked_us IS NULL OR revoked_us >= created_us", name="customer_keys_rev"
        ),
    )
    op.create_index("customer_keys_customer_idx", "customer_keys", ["customer_id"])
    op.execute(
        """
        CREATE FUNCTION customer_keys_guard() RETURNS trigger LANGUAGE plpgsql AS $$
        BEGIN
          IF TG_OP = 'DELETE' THEN
            RAISE EXCEPTION 'customer keys are never deleted' USING ERRCODE = 'check_violation';
          END IF;
          IF NEW.customer_id <> OLD.customer_id OR NEW.thumbprint <> OLD.thumbprint
             OR NEW.jwk <> OLD.jwk OR NEW.created_us <> OLD.created_us THEN
            RAISE EXCEPTION 'a customer key is immutable' USING ERRCODE = 'check_violation';
          END IF;
          IF OLD.revoked_us IS NOT NULL THEN
            RAISE EXCEPTION 'a revoked key stays revoked' USING ERRCODE = 'check_violation';
          END IF;
          RETURN NEW;
        END $$
        """
    )
    op.execute(
        "CREATE TRIGGER customer_keys_guard BEFORE UPDATE OR DELETE ON customer_keys "
        "FOR EACH ROW EXECUTE FUNCTION customer_keys_guard()"
    )
    role = _app_role()
    for table in ("key_challenges", "key_challenge_uses", "customer_keys"):
        op.execute(f"REVOKE ALL ON TABLE {table} FROM PUBLIC")
        op.execute(f'GRANT SELECT, INSERT ON TABLE {table} TO "{role}"')


def downgrade() -> None:
    op.execute("DROP TRIGGER customer_keys_guard ON customer_keys")
    op.execute("DROP FUNCTION customer_keys_guard()")
    op.drop_table("customer_keys")
    op.drop_table("key_challenge_uses")
    op.drop_table("key_challenges")
