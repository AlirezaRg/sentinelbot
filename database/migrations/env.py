"""Alembic environment. The database URL comes from SENTINEL_DATABASE_URL."""

from __future__ import annotations

import os

from alembic import context
from sqlalchemy import engine_from_config, pool

from sentinelbot_database.models import Base

config = context.config

url = os.environ.get("SENTINEL_DATABASE_URL")
if not url:
    raise RuntimeError("set SENTINEL_DATABASE_URL before running migrations")
config.set_main_option("sqlalchemy.url", url)

target_metadata = Base.metadata


def run_migrations_online() -> None:
    connectable = engine_from_config(
        config.get_section(config.config_ini_section, {}),
        prefix="sqlalchemy.",
        poolclass=pool.NullPool,
    )
    with connectable.connect() as connection:
        context.configure(connection=connection, target_metadata=target_metadata, compare_type=True)
        with context.begin_transaction():
            context.run_migrations()


run_migrations_online()
