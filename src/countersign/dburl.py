"""Database URL normalisation. Hosts hand out `postgres://` or `postgresql://` URLs; the app uses psycopg 3."""

from __future__ import annotations

import os
from collections.abc import Mapping

DEFAULT_DATABASE_URL = "postgresql+psycopg://countersign:countersign@localhost:5432/countersign"


def database_url(env: Mapping[str, str] | None = None) -> str:
    """`DATABASE_URL` with the scheme forced to `postgresql+psycopg`; the default local URL if unset."""
    source = os.environ if env is None else env
    raw = source.get("DATABASE_URL") or DEFAULT_DATABASE_URL
    for prefix in ("postgres://", "postgresql://"):
        if raw.startswith(prefix):
            return "postgresql+psycopg://" + raw[len(prefix) :]
    return raw
