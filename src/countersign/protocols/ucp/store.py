"""Checkout session storage in Postgres.

Security reasoning. The stored checkout is the exact JCS bytes of the canonical checkout, written
once per change together with its status, so the terms that were shown (and later signed) cannot
drift if the catalog changes. A row read back is parsed with the strict loader and re-validated by
the canonical model; a row that no longer validates raises `StoredCheckoutError` instead of being
served (INV-10). Writers take the row lock (`SELECT ... FOR UPDATE`) and write with a version
check, and the migration's trigger refuses any change to a final checkout, so concurrent updates
are serialized and a stale writer cannot overwrite a newer state.
"""

from __future__ import annotations

from dataclasses import dataclass, replace
from typing import Any

from sqlalchemy import (
    BigInteger,
    Column,
    Connection,
    Integer,
    LargeBinary,
    MetaData,
    Table,
    Text,
    insert,
    select,
    update,
)

from countersign.canonical.jcs import canonicalize
from countersign.canonical.jsonstrict import StrictJsonError, loads_strict
from countersign.canonical.models import Checkout
from countersign.protocols.ucp.checkout_state import Status

checkout_sessions = Table(
    "checkout_sessions",
    MetaData(),
    Column("id", Text, primary_key=True),
    Column("status", Text, nullable=False),
    Column("version", Integer, nullable=False),
    Column("checkout", LargeBinary, nullable=False),
    Column("next_line_seq", Integer, nullable=False),
    Column("catalog_hash", LargeBinary, nullable=False),
    Column("created_us", BigInteger, nullable=False),
    Column("updated_us", BigInteger, nullable=False),
    Column("expires_us", BigInteger, nullable=False),
)


class StoredCheckoutError(Exception):
    """A stored checkout row is not valid. It is never served."""

    code = "stored_checkout_invalid"


class VersionConflict(Exception):
    """The row changed since it was read (the writer did not hold the row lock)."""

    code = "version_conflict"


@dataclass(frozen=True)
class CheckoutRecord:
    checkout: Checkout
    status: Status
    version: int
    next_line_seq: int
    catalog_hash: bytes
    created_us: int
    updated_us: int
    expires_us: int

    @property
    def id(self) -> str:
        return self.checkout.id

    def advanced(
        self,
        *,
        status: Status | None = None,
        checkout: Checkout | None = None,
        next_line_seq: int | None = None,
        catalog_hash: bytes | None = None,
        now_us: int,
    ) -> CheckoutRecord:
        return replace(
            self,
            status=self.status if status is None else status,
            checkout=self.checkout if checkout is None else checkout,
            next_line_seq=self.next_line_seq if next_line_seq is None else next_line_seq,
            catalog_hash=self.catalog_hash if catalog_hash is None else catalog_hash,
            version=self.version + 1,
            updated_us=now_us,
        )


def _decode(row: Any) -> CheckoutRecord:
    try:
        checkout = Checkout.from_ucp(loads_strict(bytes(row.checkout)))  # type: ignore[arg-type]
        status = Status(row.status)
    except (StrictJsonError, ValueError, TypeError) as exc:
        raise StoredCheckoutError(f"stored checkout {row.id!r} is not valid") from exc
    if checkout.id != row.id:
        raise StoredCheckoutError(f"stored checkout {row.id!r} holds another id")
    return CheckoutRecord(
        checkout=checkout,
        status=status,
        version=row.version,
        next_line_seq=row.next_line_seq,
        catalog_hash=bytes(row.catalog_hash),
        created_us=row.created_us,
        updated_us=row.updated_us,
        expires_us=row.expires_us,
    )


def insert_record(conn: Connection, record: CheckoutRecord) -> None:
    conn.execute(
        insert(checkout_sessions).values(
            id=record.id,
            status=record.status.value,
            version=record.version,
            checkout=canonicalize(record.checkout.to_ucp()),
            next_line_seq=record.next_line_seq,
            catalog_hash=record.catalog_hash,
            created_us=record.created_us,
            updated_us=record.updated_us,
            expires_us=record.expires_us,
        )
    )


def load(conn: Connection, checkout_id: str, *, lock: bool = False) -> CheckoutRecord | None:
    """Read a checkout; with `lock` the row stays locked until the transaction ends."""
    stmt = select(checkout_sessions).where(checkout_sessions.c.id == checkout_id)
    if lock:
        stmt = stmt.with_for_update()
    row = conn.execute(stmt).first()
    return None if row is None else _decode(row)


def save(conn: Connection, record: CheckoutRecord) -> None:
    """Write a changed record. `record.version` is the new version; the old one must be current."""
    result = conn.execute(
        update(checkout_sessions)
        .where(
            checkout_sessions.c.id == record.id,
            checkout_sessions.c.version == record.version - 1,
        )
        .values(
            status=record.status.value,
            version=record.version,
            checkout=canonicalize(record.checkout.to_ucp()),
            next_line_seq=record.next_line_seq,
            catalog_hash=record.catalog_hash,
            updated_us=record.updated_us,
        )
    )
    if result.rowcount != 1:
        raise VersionConflict(record.id)
