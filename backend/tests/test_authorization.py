"""Least-privilege checks: what each kind of caller may do.

The service key belongs to agents. It must be able to send telemetry and read data, but it must
not change incident status, so a stolen agent key cannot close or hide an incident.
"""

from __future__ import annotations

import time

import pytest
from fastapi.testclient import TestClient

from sentinelbot_backend.app import create_app
from sentinelbot_backend.auth import Principal, has_role, issue_token
from sentinelbot_backend.config import ApiSettings

KEY = "k" * 32
SECRET = "s" * 40
EVENT = {
    "host_id": "host-a",
    "event_type": "system_info",
    "source": "agent",
    "message": "test event",
}


@pytest.fixture
def client() -> TestClient:
    settings = ApiSettings(api_key=KEY, auth_secret=SECRET, rate_limit_per_minute=0)
    return TestClient(create_app(settings))


def _token(role: str) -> dict[str, str]:
    token = issue_token("tester", role, SECRET, 300, int(time.time()))
    return {"Authorization": f"Bearer {token}"}


def test_service_key_can_ingest_events(client: TestClient) -> None:
    response = client.post("/api/v1/events", json=[EVENT], headers={"X-API-Key": KEY})
    assert response.status_code == 201


def test_service_key_can_read_incidents(client: TestClient) -> None:
    response = client.get("/api/v1/incidents", headers={"X-API-Key": KEY})
    assert response.status_code == 200


def test_service_key_cannot_change_incident_status(client: TestClient) -> None:
    response = client.post("/api/v1/incidents/INC-missing/resolve", headers={"X-API-Key": KEY})
    assert response.status_code == 403


def test_analyst_token_passes_the_status_check(client: TestClient) -> None:
    # The incident does not exist, so 404 proves the role check was passed.
    response = client.post("/api/v1/incidents/INC-missing/resolve", headers=_token("analyst"))
    assert response.status_code == 404


def test_viewer_token_cannot_change_incident_status(client: TestClient) -> None:
    response = client.post("/api/v1/incidents/INC-missing/resolve", headers=_token("viewer"))
    assert response.status_code == 403


def test_viewer_token_cannot_ingest_events(client: TestClient) -> None:
    response = client.post("/api/v1/events", json=[EVENT], headers=_token("viewer"))
    assert response.status_code == 403


@pytest.mark.parametrize(
    ("role", "required", "allowed"),
    [
        ("service", "viewer", True),
        ("service", "ingest", True),
        ("service", "analyst", False),
        ("service", "admin", False),
        ("viewer", "ingest", False),
        ("analyst", "ingest", True),
        ("admin", "ingest", True),
        ("viewer", "analyst", False),
        ("analyst", "analyst", True),
        ("admin", "admin", True),
    ],
)
def test_role_matrix(role: str, required: str, allowed: bool) -> None:
    assert has_role(Principal(username="x", role=role), required) is allowed
