"""The API on a SQL database: data survives a restart, and the same behaviour holds.

Runs on SQLite (always) and on PostgreSQL when SENTINEL_TEST_DATABASE_URL is set. Example:
    SENTINEL_TEST_DATABASE_URL=postgresql+psycopg://sentinel:pw@127.0.0.1/sentinel_test pytest
"""

from __future__ import annotations

import os
from collections.abc import Iterator
from datetime import UTC, datetime, timedelta
from ipaddress import ip_address
from pathlib import Path
from typing import Any

import pytest
from fastapi.testclient import TestClient
from sentinelbot_agent.models import Event, EventType, Severity
from sentinelbot_database.models import Base
from sentinelbot_database.session import make_engine

from sentinelbot_backend.app import create_app
from sentinelbot_backend.config import ApiSettings

KEY = "k" * 32
AUTH = {"X-API-Key": KEY}
T0 = datetime(2026, 10, 4, 12, 0, tzinfo=UTC)


def _detection(seconds: float, ip: str = "203.0.113.50") -> Event:
    return Event(
        host_id="server-01",
        timestamp=T0 + timedelta(seconds=seconds),
        event_type=EventType.SSH_BRUTEFORCE_DETECTED,
        severity=Severity.HIGH,
        source="detection",
        message="synthetic detection",
        source_ip=ip_address(ip),
        metadata={"rule_id": "ssh_bruteforce", "risk_score": 40, "targeted_users": ["root"]},
    )


def _telemetry(seconds: float) -> Event:
    return Event(
        host_id="server-01",
        timestamp=T0 + timedelta(seconds=seconds),
        event_type=EventType.SSH_LOGIN_FAILED,
        severity=Severity.LOW,
        source="auth",
        message="synthetic",
        source_ip=ip_address("203.0.113.50"),
        username="root",
    )


def _body(events: list[Event]) -> list[dict[str, Any]]:
    return [e.model_dump(mode="json") for e in events]


@pytest.fixture(params=["sqlite", "postgresql"])
def database_url(request: pytest.FixtureRequest, tmp_path: Path) -> Iterator[str]:
    if request.param == "sqlite":
        yield f"sqlite:///{tmp_path / 'sentinel.db'}"
        return
    url = os.environ.get("SENTINEL_TEST_DATABASE_URL")
    if not url:
        pytest.skip("SENTINEL_TEST_DATABASE_URL is not set")
    engine = make_engine(url)
    Base.metadata.drop_all(engine)  # start from an empty schema
    yield url
    Base.metadata.drop_all(engine)


def _client(url: str) -> TestClient:
    return TestClient(
        create_app(ApiSettings(api_key=KEY, database_url=url, auto_create_schema=True))
    )


def test_status_reports_postgresql_backend(database_url: str) -> None:
    status = _client(database_url).get("/api/v1/system/status", headers=AUTH).json()

    assert status["persistence"] == "postgresql"


def test_events_and_hosts_are_stored(database_url: str) -> None:
    client = _client(database_url)
    client.post("/api/v1/events", json=_body([_telemetry(0), _telemetry(5)]), headers=AUTH)

    events = client.get("/api/v1/events", headers=AUTH).json()
    hosts = client.get("/api/v1/hosts", headers=AUTH).json()

    assert events["total"] == 2
    assert events["items"][0]["source_ip"] == "203.0.113.50"
    assert hosts["items"][0]["event_count"] == 2


def test_duplicate_event_is_rejected(database_url: str) -> None:
    client = _client(database_url)
    event = _telemetry(0)
    client.post("/api/v1/events", json=_body([event]), headers=AUTH)

    response = client.post("/api/v1/events", json=_body([event]), headers=AUTH)

    assert response.status_code == 409


def test_incident_survives_restart(database_url: str) -> None:
    first = _client(database_url)
    first.post("/api/v1/events", json=_body([_detection(0)]), headers=AUTH)
    incident_id = first.get("/api/v1/incidents", headers=AUTH).json()["items"][0]["incident_id"]

    restarted = _client(database_url)  # a new app instance reading the same database
    incident = restarted.get(f"/api/v1/incidents/{incident_id}", headers=AUTH).json()

    assert incident["status"] == "OPEN"
    assert incident["usernames"] == ["root"]
    assert incident["rules"] == ["ssh_bruteforce"]


def test_resolution_survives_restart(database_url: str) -> None:
    first = _client(database_url)
    first.post("/api/v1/events", json=_body([_detection(0)]), headers=AUTH)
    incident_id = first.get("/api/v1/incidents", headers=AUTH).json()["items"][0]["incident_id"]
    first.post(f"/api/v1/incidents/{incident_id}/resolve", headers=AUTH)

    restarted = _client(database_url)
    incident = restarted.get(f"/api/v1/incidents/{incident_id}", headers=AUTH).json()

    assert incident["status"] == "RESOLVED"


def test_event_filters_and_metrics_work_on_sql(database_url: str) -> None:
    client = _client(database_url)
    client.post("/api/v1/events", json=_body([_telemetry(0), _detection(1)]), headers=AUTH)

    by_type = client.get(
        "/api/v1/events", params={"event_type": "ssh_login_failed"}, headers=AUTH
    ).json()
    metrics = client.get("/api/v1/metrics", headers=AUTH).json()

    assert by_type["total"] == 1
    assert metrics["events_stored"] == 2
    assert metrics["events_by_severity"]["high"] == 1
    assert metrics["incidents_by_status"]["OPEN"] == 1
