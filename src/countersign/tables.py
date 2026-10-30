"""SQLAlchemy Core definitions of the tables in migrations 0003 and 0004 (the schema itself is the migration)."""

from __future__ import annotations

from sqlalchemy import BigInteger, Column, MetaData, Table, Text

metadata = MetaData()

reservations = Table(
    "reservations",
    metadata,
    Column("handle", Text, primary_key=True),
    Column("role", Text, nullable=False),
    Column("checkout_id", Text, nullable=False),
    Column("checkout_hash", Text, nullable=False),
    Column("mandate_digest", Text, nullable=False),
    Column("nonce_thumbprint", Text),
    Column("nonce_audience", Text),
    Column("nonce_value", Text),
    Column("state", Text, nullable=False),
    Column("created_us", BigInteger, nullable=False),
    Column("updated_us", BigInteger, nullable=False),
)

open_payment_mandates = Table(
    "open_payment_mandates",
    metadata,
    Column("digest", Text, primary_key=True),
    Column("currency", Text, nullable=False),
    Column("created_us", BigInteger, nullable=False),
)

spend_entries = Table(
    "spend_entries",
    metadata,
    Column("id", Text, primary_key=True),
    Column("mandate_digest", Text, nullable=False),
    Column("checkout_id", Text, nullable=False),
    Column("amount_minor", BigInteger, nullable=False),
    Column("currency", Text, nullable=False),
    Column("state", Text, nullable=False),
    Column("refunded_minor", BigInteger, nullable=False),
    Column("created_us", BigInteger, nullable=False),
    Column("updated_us", BigInteger, nullable=False),
)

payment_attempts = Table(
    "payment_attempts",
    metadata,
    Column("checkout_id", Text, primary_key=True),
    Column("reservation_handle", Text, nullable=False),
    Column("spend_id", Text, nullable=False),
    Column("mandate_digest", Text, nullable=False),
    Column("state", Text, nullable=False),
    Column("mode", Text, nullable=False),
    Column("custom_id", Text, nullable=False),
    Column("principal", Text),
    Column("order_id", Text),
    Column("authorization_id", Text),
    Column("created_us", BigInteger, nullable=False),
    Column("updated_us", BigInteger, nullable=False),
    Column("capture_id", Text),
    Column("receipt", Text),
    Column("gate_code", Text),
    Column("gate_reason", Text),
)

attempt_mandates = Table(
    "attempt_mandates",
    metadata,
    Column("checkout_id", Text, primary_key=True),
    Column("payment_token", Text, nullable=False),
    Column("checkout_mandate", Text, nullable=False),
    Column("created_us", BigInteger, nullable=False),
)

mandate_revocations = Table(
    "mandate_revocations",
    metadata,
    Column("mandate_digest", Text, primary_key=True),
    Column("revoked_us", BigInteger, nullable=False),
)

payer_vault = Table(
    "payer_vault",
    metadata,
    Column("principal", Text, primary_key=True),
    Column("vault_id", Text, nullable=False),
    Column("created_us", BigInteger, nullable=False),
)

lock_policies = Table(
    "lock_policies",
    metadata,
    Column("version", BigInteger, primary_key=True),
    Column("mode", Text, nullable=False),
    Column("threshold_minor", BigInteger),
    Column("currency", Text),
    Column("policy_hash", Text, nullable=False),
    Column("reason", Text, nullable=False),
    Column("created_us", BigInteger, nullable=False),
)

lock_events = Table(
    "lock_events",
    metadata,
    Column("seq", BigInteger, primary_key=True, autoincrement=True),
    Column("kind", Text, nullable=False),
    Column("customer_id", Text, nullable=False),
    Column("agent_thumbprint", Text, nullable=False),
    Column("policy_version", BigInteger, nullable=False),
    Column("checkout_id", Text),
    Column("created_us", BigInteger, nullable=False),
)
