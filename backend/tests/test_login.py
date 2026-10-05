"""Sign-in end to end: accounts in the database, token roles, and the failure cases."""

from __future__ import annotations

from pathlib import Path
from typing import Any

import pytest
from fastapi.testclient import TestClient
from sentinelbot_database.models import Base
from sentinelbot_database.session import make_engine, make_session_factory

from sentinelbot_backend.app import create_app
from sentinelbot_backend.auth import hash_password
from sentinelbot_backend.config import ApiSettings
from sentinelbot_backend.storage_sql import SqlUserStore

KEY = "k" * 32
SECRET = "s" * 40
PASSWORD = "correct horse battery"


@pytest.fixture
def db_url(tmp_path: Path) -> str:
    return f"sqlite:///{tmp_path / 'users.db'}"


@pytest.fixture
def client(db_url: str) -> TestClient:
    settings = ApiSettings(
        api_key=KEY,
        auth_secret=SECRET,
        database_url=db_url,
        auto_create_schema=True,
        rate_limit_per_minute=300,
    )
    return TestClient(create_app(settings))


def _users(db_url: str) -> SqlUserStore:
    engine = make_engine(db_url)
    Base.metadata.create_all(engine)  # idempotent; the app does the same when auto_create is on
    return SqlUserStore(make_session_factory(engine))


def _add_user(db_url: str, username: str, role: str) -> None:
    _users(db_url).create(username, hash_password(PASSWORD), role)


def _login(client: TestClient, username: str, password: str = PASSWORD) -> Any:
    return client.post("/api/v1/auth/login", json={"username": username, "password": password})


def _bearer(token: str) -> dict[str, str]:
    return {"Authorization": f"Bearer {token}"}


def _event_body() -> list[dict[str, Any]]:
    return []  # an empty batch is rejected by validation; we only test the role gate


def test_correct_password_returns_a_token_for_the_role(client: TestClient, db_url: str) -> None:
    _add_user(db_url, "alice", "analyst")

    response = _login(client, "alice")
    token = response.json()["access_token"]

    assert response.status_code == 200
    assert response.json()["role"] == "analyst"
    me = client.get("/api/v1/auth/me", headers=_bearer(token))
    assert me.json() == {"username": "alice", "role": "analyst"}


def test_wrong_password_is_refused(client: TestClient, db_url: str) -> None:
    _add_user(db_url, "alice", "viewer")

    assert _login(client, "alice", "not the password").status_code == 401


def test_unknown_user_gets_the_same_answer_as_a_wrong_password(
    client: TestClient, db_url: str
) -> None:
    _add_user(db_url, "alice", "viewer")

    unknown = _login(client, "nobody")
    wrong = _login(client, "alice", "not the password")

    assert unknown.status_code == wrong.status_code == 401
    assert unknown.json() == wrong.json()


def test_disabled_account_cannot_sign_in(client: TestClient, db_url: str) -> None:
    from sentinelbot_database.models import UserRow

    _add_user(db_url, "bob", "admin")
    with make_session_factory(make_engine(db_url))() as session, session.begin():
        session.get(UserRow, "bob").disabled = True  # type: ignore[union-attr]

    assert _login(client, "bob").status_code == 401


def test_viewer_token_cannot_ingest_events(client: TestClient, db_url: str) -> None:
    _add_user(db_url, "viewer1", "viewer")
    token = _login(client, "viewer1").json()["access_token"]

    response = client.post("/api/v1/events", json=_event_body(), headers=_bearer(token))

    assert response.status_code == 403


def test_viewer_token_can_read(client: TestClient, db_url: str) -> None:
    _add_user(db_url, "viewer1", "viewer")
    token = _login(client, "viewer1").json()["access_token"]

    assert client.get("/api/v1/metrics", headers=_bearer(token)).status_code == 200


def test_analyst_token_can_resolve_but_service_key_still_works(
    client: TestClient, db_url: str
) -> None:
    _add_user(db_url, "analyst1", "analyst")
    token = _login(client, "analyst1").json()["access_token"]

    # Unknown incident: the role check passes (404, not 403).
    assert client.post("/api/v1/incidents/INC-x/resolve", headers=_bearer(token)).status_code == 404
    assert client.get("/api/v1/metrics", headers={"X-API-Key": KEY}).status_code == 200


def test_forged_token_is_refused(client: TestClient, db_url: str) -> None:
    _add_user(db_url, "alice", "viewer")
    token = _login(client, "alice").json()["access_token"]
    payload, signature = token.split(".")
    forged = payload[:-1] + ("A" if payload[-1] != "A" else "B")

    response = client.get("/api/v1/metrics", headers=_bearer(f"{forged}.{signature}"))

    assert response.status_code == 401


def test_sign_in_is_unavailable_without_a_secret(db_url: str) -> None:
    client = TestClient(
        create_app(
            ApiSettings(
                api_key=KEY, database_url=db_url, auto_create_schema=True, rate_limit_per_minute=0
            )
        )
    )

    assert _login(client, "anyone").status_code == 503


def test_sign_in_attempts_are_rate_limited(client: TestClient, db_url: str) -> None:
    _add_user(db_url, "alice", "viewer")

    statuses = [_login(client, "alice", "wrong").status_code for _ in range(11)]

    assert statuses[-1] == 429


def test_password_is_not_stored_in_plain_text(db_url: str) -> None:
    from sentinelbot_database.models import UserRow

    _add_user(db_url, "carol", "viewer")  # creates the schema first, as the helper does
    with make_session_factory(make_engine(db_url))() as session:
        row = session.get(UserRow, "carol")

    assert row is not None
    assert PASSWORD not in row.password_hash
    assert row.password_hash.startswith("scrypt$")
