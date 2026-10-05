"""API behaviour through the HTTP layer: auth, validation, pagination, ingestion, incidents."""

from __future__ import annotations

import time
from datetime import UTC, datetime, timedelta
from ipaddress import ip_address
from pathlib import Path
from typing import Any
from uuid import uuid4

import pytest
from fastapi.testclient import TestClient
from sentinelbot_agent.models import Event, EventType, Severity

from sentinelbot_backend.app import create_app
from sentinelbot_backend.auth import issue_token
from sentinelbot_backend.config import ApiSettings, SettingsError

KEY = "k" * 32
SECRET = "s" * 40
AUTH = {"X-API-Key": KEY}
# Only users can change incident status; the service key cannot (see auth.has_role).
ANALYST = {
    "Authorization": f"Bearer {issue_token('analyst', 'analyst', SECRET, 3600, int(time.time()))}"
}
T0 = datetime(2026, 10, 4, 12, 0, tzinfo=UTC)


def at(seconds: float) -> datetime:
    return T0 + timedelta(seconds=seconds)


def telemetry(
    seconds: float,
    *,
    ip: str = "203.0.113.50",
    user: str = "root",
    host: str = "server-01",
    event_type: EventType = EventType.SSH_LOGIN_FAILED,
    severity: Severity = Severity.LOW,
) -> Event:
    return Event(
        host_id=host,
        timestamp=at(seconds),
        event_type=event_type,
        severity=severity,
        source="auth",
        message="synthetic",
        source_ip=ip_address(ip),
        username=user,
    )


def detection(
    seconds: float,
    *,
    ip: str | None = "203.0.113.50",
    host: str = "server-01",
    rule: str = "ssh_bruteforce",
    score: int = 40,
    users: list[str] | None = None,
) -> Event:
    return Event(
        host_id=host,
        timestamp=at(seconds),
        event_type=EventType.SSH_BRUTEFORCE_DETECTED,
        severity=Severity.HIGH,
        source="detection",
        message="synthetic detection",
        source_ip=ip_address(ip) if ip else None,
        metadata={"rule_id": rule, "risk_score": score, "targeted_users": users or []},
    )


def _body(events: list[Event]) -> list[dict[str, Any]]:
    return [e.model_dump(mode="json") for e in events]


@pytest.fixture
def client() -> TestClient:
    return TestClient(create_app(ApiSettings(api_key=KEY, auth_secret=SECRET, event_capacity=1000)))


def test_health_needs_no_key(client: TestClient) -> None:
    response = client.get("/health")

    assert response.status_code == 200
    assert response.json() == {"status": "ok"}


@pytest.mark.parametrize("headers", [{}, {"X-API-Key": "wrong"}])
def test_protected_routes_reject_missing_or_wrong_key(
    client: TestClient, headers: dict[str, str]
) -> None:
    assert client.get("/api/v1/events", headers=headers).status_code == 401


def test_protected_routes_fail_closed_without_configured_key() -> None:
    open_client = TestClient(create_app(ApiSettings(api_key=None)))

    response = open_client.get("/api/v1/events", headers={"X-API-Key": "anything"})

    assert response.status_code == 503


def test_short_api_key_is_rejected() -> None:
    with pytest.raises(SettingsError):
        ApiSettings(api_key="short")


def test_ingest_then_list_newest_first(client: TestClient) -> None:
    response = client.post(
        "/api/v1/events", json=_body([telemetry(0), telemetry(10)]), headers=AUTH
    )
    listed = client.get("/api/v1/events", headers=AUTH).json()

    assert response.status_code == 201
    assert response.json() == {"accepted": 2, "incidents_touched": 0}
    assert listed["total"] == 2
    assert listed["items"][0]["timestamp"].startswith("2026-10-04T12:00:10")


def test_event_lookup_by_id_and_not_found(client: TestClient) -> None:
    event = telemetry(0)
    client.post("/api/v1/events", json=_body([event]), headers=AUTH)

    found = client.get(f"/api/v1/events/{event.event_id}", headers=AUTH)
    missing = client.get(f"/api/v1/events/{uuid4()}", headers=AUTH)

    assert found.status_code == 200
    assert found.json()["message"] == "synthetic"
    assert missing.status_code == 404


def test_event_filters(client: TestClient) -> None:
    client.post(
        "/api/v1/events",
        json=_body([telemetry(0, ip="203.0.113.1"), telemetry(5, ip="203.0.113.2", host="db-01")]),
        headers=AUTH,
    )

    by_host = client.get("/api/v1/events", params={"host_id": "db-01"}, headers=AUTH).json()
    by_ip = client.get("/api/v1/events", params={"source_ip": "203.0.113.1"}, headers=AUTH).json()
    by_severity = client.get("/api/v1/events", params={"severity": "high"}, headers=AUTH).json()

    assert by_host["total"] == 1
    assert by_ip["total"] == 1
    assert by_severity["total"] == 0


def test_invalid_filters_are_rejected(client: TestClient) -> None:
    bad_ip = client.get("/api/v1/events", params={"source_ip": "nope"}, headers=AUTH)
    reversed_range = client.get(
        "/api/v1/events",
        params={"since": at(10).isoformat(), "until": at(0).isoformat()},
        headers=AUTH,
    )

    assert bad_ip.status_code == 422
    assert reversed_range.status_code == 422


@pytest.mark.parametrize("params", [{"limit": 0}, {"limit": 501}, {"offset": -1}])
def test_pagination_bounds_are_enforced(client: TestClient, params: dict[str, int]) -> None:
    assert client.get("/api/v1/events", params=params, headers=AUTH).status_code == 422


def test_pagination_returns_requested_window(client: TestClient) -> None:
    client.post("/api/v1/events", json=_body([telemetry(s) for s in range(5)]), headers=AUTH)

    page = client.get(
        "/api/v1/events", params={"limit": 2, "offset": 2, "order": "asc"}, headers=AUTH
    ).json()

    # Five failed logins from one address trip the brute-force rule on the server, which
    # stores one extra detection event: 5 telemetry + 1 detection.
    assert page["total"] == 6
    assert [item["timestamp"][17:19] for item in page["items"]] == ["02", "03"]


def test_duplicate_event_id_is_rejected_without_partial_write(client: TestClient) -> None:
    event = telemetry(0)
    client.post("/api/v1/events", json=_body([event]), headers=AUTH)

    response = client.post("/api/v1/events", json=_body([telemetry(1), event]), headers=AUTH)
    total = client.get("/api/v1/events", headers=AUTH).json()["total"]

    assert response.status_code == 409
    assert total == 1  # the new event in the same batch was not stored


def test_empty_and_oversized_batches_are_rejected(client: TestClient) -> None:
    assert client.post("/api/v1/events", json=[], headers=AUTH).status_code == 422
    too_many = _body([telemetry(s) for s in range(501)])
    assert client.post("/api/v1/events", json=too_many, headers=AUTH).status_code == 422


def test_capacity_drops_oldest_events() -> None:
    small = TestClient(create_app(ApiSettings(api_key=KEY, event_capacity=3)))
    small.post("/api/v1/events", json=_body([telemetry(s) for s in range(5)]), headers=AUTH)

    status = small.get("/api/v1/system/status", headers=AUTH).json()

    assert status["events_stored"] == 3


def test_detection_creates_an_open_incident(client: TestClient) -> None:
    response = client.post(
        "/api/v1/events", json=_body([detection(0, users=["root"])]), headers=AUTH
    )
    incidents = client.get("/api/v1/incidents", headers=AUTH).json()

    assert response.json()["incidents_touched"] == 1
    assert incidents["total"] == 1
    incident = incidents["items"][0]
    assert incident["status"] == "OPEN"
    assert incident["usernames"] == ["root"]
    assert incident["title"].startswith("Possible SSH brute-force activity")


def test_incident_detail_and_filters(client: TestClient) -> None:
    client.post("/api/v1/events", json=_body([detection(0)]), headers=AUTH)
    client.post(
        "/api/v1/events", json=_body([detection(0, ip="198.51.100.9", score=80)]), headers=AUTH
    )
    incident_id = client.get("/api/v1/incidents", headers=AUTH).json()["items"][0]["incident_id"]

    detail = client.get(f"/api/v1/incidents/{incident_id}", headers=AUTH)
    by_status = client.get("/api/v1/incidents", params={"status": "RESOLVED"}, headers=AUTH).json()
    by_risk = client.get(
        "/api/v1/incidents", params={"sort": "risk_score", "order": "desc"}, headers=AUTH
    ).json()

    assert detail.status_code == 200
    assert by_status["total"] == 0
    assert by_risk["items"][0]["risk_score"] == 80
    assert client.get("/api/v1/incidents/INC-missing", headers=AUTH).status_code == 404


def test_resolve_incident_changes_status(client: TestClient) -> None:
    client.post("/api/v1/events", json=_body([detection(0)]), headers=AUTH)
    incident_id = client.get("/api/v1/incidents", headers=AUTH).json()["items"][0]["incident_id"]

    response = client.post(
        f"/api/v1/incidents/{incident_id}/resolve",
        json={"resolution": "FALSE_POSITIVE", "note": "our own test"},
        headers=ANALYST,
    )
    default = client.post(f"/api/v1/incidents/{incident_id}/resolve", headers=ANALYST)

    assert response.status_code == 200
    assert response.json()["status"] == "FALSE_POSITIVE"
    assert default.json()["status"] == "RESOLVED"


def test_resolve_rejects_bad_resolution_and_unknown_incident(client: TestClient) -> None:
    client.post("/api/v1/events", json=_body([detection(0)]), headers=AUTH)
    incident_id = client.get("/api/v1/incidents", headers=AUTH).json()["items"][0]["incident_id"]

    bad = client.post(
        f"/api/v1/incidents/{incident_id}/resolve", json={"resolution": "OPEN"}, headers=ANALYST
    )
    unknown = client.post("/api/v1/incidents/INC-nope/resolve", headers=ANALYST)

    assert bad.status_code == 422
    assert unknown.status_code == 404


def test_hosts_report_open_incidents(client: TestClient) -> None:
    client.post("/api/v1/events", json=_body([telemetry(0), detection(1)]), headers=AUTH)

    hosts = client.get("/api/v1/hosts", headers=AUTH).json()

    assert hosts["total"] == 1
    assert hosts["items"][0]["host_id"] == "server-01"
    assert hosts["items"][0]["open_incidents"] == 1


def test_metrics_summarise_stored_data(client: TestClient) -> None:
    client.post("/api/v1/events", json=_body([telemetry(0), detection(1)]), headers=AUTH)

    metrics = client.get("/api/v1/metrics", headers=AUTH).json()

    assert metrics["events_stored"] == 2
    assert metrics["events_by_type"]["ssh_login_failed"] == 1
    assert metrics["incidents_by_status"]["OPEN"] == 1


def test_system_status_reports_configuration(client: TestClient) -> None:
    status = client.get("/api/v1/system/status", headers=AUTH).json()

    assert status["status"] == "ok"
    assert status["persistence"] == "memory"
    assert status["api_key_configured"] is True
    assert status["event_capacity"] == 1000


def test_incidents_are_written_to_file_when_configured(tmp_path: Path) -> None:
    path = tmp_path / "incidents.json"
    app_client = TestClient(create_app(ApiSettings(api_key=KEY, incidents_path=path)))

    app_client.post("/api/v1/events", json=_body([detection(0)]), headers=AUTH)

    assert path.exists()
    assert "ssh_bruteforce" in path.read_text(encoding="utf-8")
    status = app_client.get("/api/v1/system/status", headers=AUTH).json()
    assert status["persistence"] == "file"
