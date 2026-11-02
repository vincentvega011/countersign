"""Key revocations become an insert-only table; the `customer_keys` owner trigger goes away.

Revision ID: 0008
Revises: 0007

Security reasoning. Migration 0007 let an owner role set `customer_keys.revoked_us` once, guarded by a
trigger, because the runtime role had no UPDATE grant. A revocation is a decision that a customer's
own key made, so it should be stored with the evidence of that decision, and it should need no UPDATE
for anyone. Now:

- `key_revocations` has the thumbprint as primary key: one row means "revoked", and a key is revoked
  when a row exists. The row keeps the revocation record (JCS text), the signature, the signing key's
  thumbprint, the challenge that was spent and the time. The runtime role has SELECT and INSERT only.
- `customer_keys` loses `revoked_us` and the guard trigger. It has no updatable column left, and the
  runtime role has no UPDATE or DELETE grant (migration 0007), which is the whole of its protection.
- Nothing in the application writes a revocation except through a verified, challenge-bound request.

The migration is safe on a database that already has revoked keys: they are copied into
`key_revocations` (with the marker proof `migrated` and the owner's own signer) before the column is
dropped. `downgrade` puts the column and the trigger back and copies the revocations over.
"""

import os
import re

import sqlalchemy as sa
from alembic import context, op

revision = "0008"
down_revision = "0007"
branch_labels = None
depends_on = None

_ROLE = re.compile(r"[a-z_][a-z0-9_]{0,62}")

_GUARD = """
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
        "key_revocations",
        sa.Column(
            "thumbprint", sa.Text, sa.ForeignKey("customer_keys.thumbprint"), primary_key=True
        ),
        sa.Column("customer_id", sa.Text, nullable=False),
        sa.Column("signer_thumbprint", sa.Text, nullable=False),
        sa.Column("challenge_id", sa.Text, nullable=False),
        sa.Column("record", sa.Text, nullable=False),
        sa.Column("signature", sa.Text, nullable=False),
        sa.Column("revoked_us", sa.BigInteger, nullable=False),
    )
    op.create_index("key_revocations_customer_idx", "key_revocations", ["customer_id"])
    # Keep every revocation that exists. The proof of a migrated row is the marker, nothing else.
    op.execute(
        "INSERT INTO key_revocations (thumbprint, customer_id, signer_thumbprint, challenge_id, "
        "record, signature, revoked_us) SELECT thumbprint, customer_id, thumbprint, 'migrated', "
        "'migrated', 'migrated', revoked_us FROM customer_keys WHERE revoked_us IS NOT NULL"
    )
    op.execute("DROP TRIGGER customer_keys_guard ON customer_keys")
    op.execute("DROP FUNCTION customer_keys_guard()")
    op.drop_constraint("customer_keys_rev", "customer_keys", type_="check")
    op.drop_column("customer_keys", "revoked_us")
    role = _app_role()
    op.execute("REVOKE ALL ON TABLE key_revocations FROM PUBLIC")
    op.execute(f'GRANT SELECT, INSERT ON TABLE key_revocations TO "{role}"')


def downgrade() -> None:
    op.add_column("customer_keys", sa.Column("revoked_us", sa.BigInteger))
    op.execute(
        "UPDATE customer_keys SET revoked_us = r.revoked_us FROM key_revocations r "
        "WHERE r.thumbprint = customer_keys.thumbprint"
    )
    op.create_check_constraint(
        "customer_keys_rev", "customer_keys", "revoked_us IS NULL OR revoked_us >= created_us"
    )
    op.execute(_GUARD)
    op.execute(
        "CREATE TRIGGER customer_keys_guard BEFORE UPDATE OR DELETE ON customer_keys "
        "FOR EACH ROW EXECUTE FUNCTION customer_keys_guard()"
    )
    op.drop_table("key_revocations")
