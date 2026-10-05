"""The API runs detection on telemetry itself: plain agent events produce incidents."""

from __future__ import annotations

from datetime import UTC, datetime, timedelta
from ipaddress import ip_address
from typing import Any

from fastapi.testclient import TestClient
from sentinelbot_agent.models import Event, EventType, Severity

from sentinelbot_backend.app import create_app
from sentinelbot_backend.config import ApiSettings

KEY = "k" * 32
AUTH = {"X-API-Key": KEY}
T0 = datetime(2026, 10, 4, 12, 0, tzinfo=UTC)


def _failed_login(seconds: float, ip: str = "203.0.113.50") -> dict[str, Any]:
    event = Event(
        host_id="server-01",
        timestamp=T0 + timedelta(seconds=seconds),
        event_type=EventType.SSH_LOGIN_FAILED,
        severity=Severity.LOW,
        source="auth",
        message="Failed SSH authentication",
        source_ip=ip_address(ip),
        username="root",
        metadata={"targets_root": True},
    )
    return event.model_dump(mode="json")


def test_plain_failed_logins_create_an_incident_on_the_server() -> None:
    client = TestClient(create_app(ApiSettings(api_key=KEY, rate_limit_per_minute=0)))

    client.post("/api/v1/events", json=[_failed_login(s) for s in range(5)], headers=AUTH)
    incidents = client.get("/api/v1/incidents", headers=AUTH).json()

    assert incidents["total"] == 1
    assert incidents["items"][0]["title"].startswith("Possible SSH brute-force activity")
    assert incidents["items"][0]["rules"] == ["ssh_bruteforce"]


def test_server_detection_is_visible_as_an_event() -> None:
    client = TestClient(create_app(ApiSettings(api_key=KEY, rate_limit_per_minute=0)))

    client.post("/api/v1/events", json=[_failed_login(s) for s in range(5)], headers=AUTH)
    detections = client.get(
        "/api/v1/events", params={"event_type": "ssh_bruteforce_detected"}, headers=AUTH
    ).json()

    assert detections["total"] == 1
    assert detections["items"][0]["source"] == "detection"
    assert detections["items"][0]["metadata"]["risk_score"] >= 0


def test_four_failed_logins_do_not_create_an_incident() -> None:
    client = TestClient(create_app(ApiSettings(api_key=KEY, rate_limit_per_minute=0)))

    client.post("/api/v1/events", json=[_failed_login(s) for s in range(4)], headers=AUTH)

    assert client.get("/api/v1/incidents", headers=AUTH).json()["total"] == 0
