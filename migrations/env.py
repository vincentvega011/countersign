"""Alembic environment. The URL is taken from the Alembic config or DATABASE_URL."""

import os

from alembic import context
from sqlalchemy import create_engine, pool

config = context.config


def database_url() -> str:
    url = config.get_main_option("sqlalchemy.url") or os.environ.get("DATABASE_URL")
    if not url:
        raise RuntimeError("set DATABASE_URL (or sqlalchemy.url) to run migrations")
    return url


def run_migrations_offline() -> None:
    context.configure(url=database_url(), literal_binds=True, target_metadata=None)
    with context.begin_transaction():
        context.run_migrations()


def run_migrations_online() -> None:
    engine = create_engine(database_url(), poolclass=pool.NullPool)
    with engine.connect() as connection:
        context.configure(connection=connection, target_metadata=None)
        with context.begin_transaction():
            context.run_migrations()


if context.is_offline_mode():
    run_migrations_offline()
else:
    run_migrations_online()
