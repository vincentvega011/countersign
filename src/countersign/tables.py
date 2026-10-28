"""SQLAlchemy Core definitions of the tables in migrations 0003 (the schema itself is the migration)."""

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
)

payer_vault = Table(
    "payer_vault",
    metadata,
    Column("principal", Text, primary_key=True),
    Column("vault_id", Text, nullable=False),
    Column("created_us", BigInteger, nullable=False),
)
