"""SQLAlchemy Core definitions of the tables added by the migrations (the schema itself is the migration)."""

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

webhook_events = Table(
    "webhook_events",
    metadata,
    Column("event_id", Text, primary_key=True),
    Column("event_type", Text, nullable=False),
    Column("state", Text, nullable=False),
    Column("outcome", Text),
    Column("checkout_id", Text),
    Column("received_us", BigInteger, nullable=False),
    Column("finished_us", BigInteger),
)

key_challenges = Table(
    "key_challenges",
    metadata,
    Column("id", Text, primary_key=True),
    Column("purpose", Text, nullable=False),
    Column("nonce", Text, nullable=False),
    Column("created_us", BigInteger, nullable=False),
)

key_challenge_uses = Table(
    "key_challenge_uses",
    metadata,
    Column("challenge_id", Text, primary_key=True),
    Column("thumbprint", Text, nullable=False),
    Column("used_us", BigInteger, nullable=False),
)

customer_keys = Table(
    "customer_keys",
    metadata,
    Column("customer_id", Text, nullable=False),
    Column("thumbprint", Text, primary_key=True),
    Column("jwk", Text, nullable=False),
    Column("created_us", BigInteger, nullable=False),
)

key_revocations = Table(
    "key_revocations",
    metadata,
    Column("thumbprint", Text, primary_key=True),
    Column("customer_id", Text, nullable=False),
    Column("signer_thumbprint", Text, nullable=False),
    Column("challenge_id", Text, nullable=False),
    Column("record", Text, nullable=False),
    Column("signature", Text, nullable=False),
    Column("revoked_us", BigInteger, nullable=False),
)

consent_records = Table(
    "consent_records",
    metadata,
    Column("id", Text, primary_key=True),
    Column("challenge_id", Text, nullable=False),
    Column("customer_id", Text, nullable=False),
    Column("device_thumbprint", Text, nullable=False),
    Column("device_jwk", Text, nullable=False),
    Column("agent_thumbprint", Text, nullable=False),
    Column("record", Text, nullable=False),
    Column("signature", Text, nullable=False),
    Column("checkout_mandate", Text, nullable=False),
    Column("payment_mandate", Text, nullable=False),
    Column("checkout_open_digest", Text, nullable=False),
    Column("payment_open_digest", Text, nullable=False),
    Column("mandate_exp", BigInteger, nullable=False),
    Column("created_us", BigInteger, nullable=False),
)

open_mandates = Table(
    "open_mandates",
    metadata,
    Column("id", Text, primary_key=True),
    Column("checkout_identity", Text, nullable=False),
    Column("customer_id", Text, nullable=False),
    Column("consent_id", Text, nullable=False),
    Column("agent_thumbprint", Text, nullable=False),
    Column("ceiling_minor", BigInteger, nullable=False),
    Column("currency", Text, nullable=False),
    Column("exp", BigInteger, nullable=False),
    Column("created_us", BigInteger, nullable=False),
)

open_mandate_revocations = Table(
    "open_mandate_revocations",
    metadata,
    Column("payment_identity", Text, primary_key=True),
    Column("checkout_identity", Text, nullable=False),
    Column("customer_id", Text),
    Column("signer_thumbprint", Text),
    Column("challenge_id", Text),
    Column("record", Text),
    Column("signature", Text),
    Column("revoked_us", BigInteger, nullable=False),
)

agent_proposals = Table(
    "agent_proposals",
    metadata,
    Column("id", Text, primary_key=True),
    Column("challenge_id", Text, nullable=False),
    Column("agent_thumbprint", Text, nullable=False),
    Column("agent_jwk", Text, nullable=False),
    Column("terms", Text, nullable=False),
    Column("signature", Text, nullable=False),
    Column("created_us", BigInteger, nullable=False),
)

proposal_uses = Table(
    "proposal_uses",
    metadata,
    Column("proposal_id", Text, primary_key=True),
    Column("consent_id", Text, nullable=False),
    Column("used_us", BigInteger, nullable=False),
)

purchase_offers = Table(
    "purchase_offers",
    metadata,
    Column("id", Text, primary_key=True),
    Column("checkout_id", Text, nullable=False),
    Column("checkout_jwt", Text, nullable=False),
    Column("checkout_hash", Text, nullable=False),
    Column("terms", Text, nullable=False),
    Column("created_us", BigInteger, nullable=False),
)

purchase_consents = Table(
    "purchase_consents",
    metadata,
    Column("id", Text, primary_key=True),
    Column("offer_id", Text, nullable=False),
    Column("challenge_id", Text, nullable=False),
    Column("customer_id", Text, nullable=False),
    Column("device_thumbprint", Text, nullable=False),
    Column("device_jwk", Text, nullable=False),
    Column("record", Text, nullable=False),
    Column("signature", Text, nullable=False),
    Column("checkout_mandate", Text, nullable=False),
    Column("payment_mandate", Text, nullable=False),
    Column("created_us", BigInteger, nullable=False),
)

activity_sessions = Table(
    "activity_sessions",
    metadata,
    Column("token_hash", Text, primary_key=True),
    Column("customer_id", Text, nullable=False),
    Column("device_thumbprint", Text, nullable=False),
    Column("challenge_id", Text, nullable=False),
    Column("created_us", BigInteger, nullable=False),
)
