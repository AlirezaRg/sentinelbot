"""Engine and session helpers. The same code runs on PostgreSQL (production) and SQLite (tests)."""

from __future__ import annotations

from sqlalchemy import Engine, create_engine
from sqlalchemy.orm import Session, sessionmaker
from sqlalchemy.pool import StaticPool


def make_engine(url: str) -> Engine:
    if url.startswith("sqlite"):
        # SQLite is for tests and local runs only. StaticPool keeps one connection, which is
        # required for an in-memory database to survive between sessions.
        return create_engine(
            url,
            connect_args={"check_same_thread": False},
            poolclass=StaticPool,
        )
    return create_engine(url, pool_pre_ping=True)


def make_session_factory(engine: Engine) -> sessionmaker[Session]:
    return sessionmaker(bind=engine, expire_on_commit=False)
