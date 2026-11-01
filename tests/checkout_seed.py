"""Seed the checkout row that a payment attempt belongs to, for tests that build attempts directly.

The capture gate re-reads the checkout (G-CHECKOUT) and fails closed when it is missing, so a test
that drives the Credential Provider and the gate without the UCP service needs the row the service
would have written: the checkout in `complete_in_progress`, unexpired.
"""

from __future__ import annotations

import os
import re
import time

from sqlalchemy import Engine, create_engine, select, text
from sqlalchemy.engine import make_url

from countersign.canonical.models import Checkout
from countersign.checkout import store
from countersign.checkout.state import Status

DAY_US = 24 * 3600 * 1_000_000
SHAPE = re.compile(r"chk_[A-Za-z0-9_-]{22}")
SHAPE_CHECK = "checkout_sessions_id_shape"
RESTORE_SHAPE_CHECK = (
    f"ALTER TABLE checkout_sessions ADD CONSTRAINT {SHAPE_CHECK} "
    "CHECK (id ~ '^chk_[A-Za-z0-9_-]{22}$') NOT VALID"
)
ADMIN_URL = "postgresql+psycopg://countersign:countersign@localhost:5432/countersign"


def seed_checkout(
    engine: Engine,
    checkout: Checkout,
    *,
    status: Status = Status.COMPLETE_IN_PROGRESS,
    expires_in_us: int = DAY_US,
) -> None:
    """Insert the checkout if there is no row for it yet (idempotent)."""
    now = time.time_ns() // 1000
    with engine.begin() as conn:
        found = conn.execute(
            select(store.checkout_sessions.c.id).where(store.checkout_sessions.c.id == checkout.id)
        ).first()
        if found is not None:
            return
        record = store.CheckoutRecord(
            checkout=checkout,
            status=status,
            version=1,
            next_line_seq=len(checkout.line_items) + 1,
            catalog_hash=bytes(32),
            created_us=now,
            updated_us=now,
            expires_us=now + expires_in_us,
        )
        if SHAPE.fullmatch(checkout.id):
            store.insert_record(conn, record)
            return
    _insert_unshaped(engine, record)


def _insert_unshaped(engine: Engine, record: store.CheckoutRecord) -> None:
    """Insert a row whose id the production shape check refuses (ids baked into recorded fixtures).

    Test only. The administrator drops the shape check, inserts and puts the check back as NOT
    VALID, which enforces it for every later insert exactly as before.
    """
    url = make_url(os.environ.get("DATABASE_URL", ADMIN_URL)).set(database=engine.url.database)
    admin = create_engine(url)
    try:
        with admin.begin() as conn:
            conn.execute(text(f"ALTER TABLE checkout_sessions DROP CONSTRAINT {SHAPE_CHECK}"))
        try:
            with admin.begin() as conn:
                store.insert_record(conn, record)
        finally:
            # On every path (a failed insert, a failing test, a teardown error) the check comes back.
            with admin.begin() as conn:
                conn.execute(text(RESTORE_SHAPE_CHECK))
    finally:
        admin.dispose()


def set_status(engine: Engine, checkout_id: str, status: Status) -> None:
    """Move the stored checkout to `status` directly, as a path that slipped past the entry guard."""
    with engine.begin() as conn:
        record = store.load(conn, checkout_id, lock=True)
        assert record is not None
        store.save(conn, record.advanced(status=status, now_us=time.time_ns() // 1000))
