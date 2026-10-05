"""The migration must build exactly the schema the models describe (no drift)."""

from __future__ import annotations

from pathlib import Path

import pytest
from alembic import command
from alembic.autogenerate import compare_metadata
from alembic.config import Config
from alembic.migration import MigrationContext
from sqlalchemy import inspect

from sentinelbot_database.models import Base
from sentinelbot_database.session import make_engine

ROOT = Path(__file__).resolve().parent.parent


def _alembic_config() -> Config:
    return Config(str(ROOT / "alembic.ini"))


@pytest.fixture
def migrated_url(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> str:
    url = f"sqlite:///{tmp_path / 'sentinel.db'}"
    monkeypatch.setenv("SENTINEL_DATABASE_URL", url)
    command.upgrade(_alembic_config(), "head")
    return url


def test_upgrade_creates_every_table(migrated_url: str) -> None:
    engine = make_engine(migrated_url)
    tables = set(inspect(engine).get_table_names())

    assert {"hosts", "events", "incidents", "detection_rules", "alerts"} <= tables


def test_migration_matches_models_without_drift(migrated_url: str) -> None:
    engine = make_engine(migrated_url)
    with engine.connect() as connection:
        context = MigrationContext.configure(connection, opts={"compare_type": True})
        differences = compare_metadata(context, Base.metadata)

    assert differences == []


def test_downgrade_removes_tables(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    url = f"sqlite:///{tmp_path / 'down.db'}"
    monkeypatch.setenv("SENTINEL_DATABASE_URL", url)
    config = _alembic_config()
    command.upgrade(config, "head")
    command.downgrade(config, "base")

    remaining = set(inspect(make_engine(url)).get_table_names()) - {"alembic_version"}

    assert remaining == set()


def test_url_is_required(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.delenv("SENTINEL_DATABASE_URL", raising=False)

    with pytest.raises(RuntimeError, match="SENTINEL_DATABASE_URL"):
        command.upgrade(_alembic_config(), "head")
