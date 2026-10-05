"""Prometheus metrics: values after real ingestion, the key requirement, and label hygiene."""

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
NOW = datetime.now(UTC)


def _client() -> TestClient:
    return TestClient(create_app(ApiSettings(api_key=KEY, rate_limit_per_minute=0)))


def _body(events: list[Event]) -> list[dict[str, Any]]:
    return [e.model_dump(mode="json") for e in events]


def _metrics_text(client: TestClient) -> str:
    response = client.get("/metrics", headers=AUTH)
    assert response.status_code == 200
    return str(response.text)


def _system_metrics(cpu: float) -> Event:
    return Event(
        host_id="server-01",
        timestamp=NOW,
        event_type=EventType.SYSTEM_METRICS,
        severity=Severity.INFO,
        source="system",
        message="synthetic",
        metadata={"cpu_percent": cpu, "memory_percent": 40.0},
    )


def _detection(seconds_ago: float = 0) -> Event:
    return Event(
        host_id="server-01",
        timestamp=NOW - timedelta(seconds=seconds_ago),
        event_type=EventType.SSH_BRUTEFORCE_DETECTED,
        severity=Severity.HIGH,
        source="detection",
        message="synthetic",
        source_ip=ip_address("203.0.113.50"),
        metadata={"rule_id": "ssh_bruteforce", "risk_score": 40},
    )


def test_metrics_endpoint_requires_the_api_key() -> None:
    client = _client()

    assert client.get("/metrics").status_code == 401
    assert client.get("/metrics", headers=AUTH).status_code == 200


def test_metrics_use_the_prometheus_text_format() -> None:
    text = _metrics_text(_client())

    assert "# HELP sentinel_events_total" in text
    assert "# TYPE sentinel_detection_latency_seconds histogram" in text


def test_event_counter_counts_by_type_and_severity() -> None:
    client = _client()
    client.post(
        "/api/v1/events", json=_body([_system_metrics(10.0), _system_metrics(20.0)]), headers=AUTH
    )

    text = _metrics_text(client)

    assert 'sentinel_events_total{event_type="system_metrics",severity="info"} 2.0' in text


def test_agent_gauges_show_the_latest_reported_values() -> None:
    client = _client()
    client.post("/api/v1/events", json=_body([_system_metrics(12.5)]), headers=AUTH)

    text = _metrics_text(client)

    assert 'sentinel_agent_cpu_usage{host="server-01"} 12.5' in text
    assert 'sentinel_agent_memory_usage{host="server-01"} 40.0' in text


def test_detection_increments_counter_incident_counter_and_latency() -> None:
    client = _client()
    client.post("/api/v1/events", json=_body([_detection(seconds_ago=4)]), headers=AUTH)

    text = _metrics_text(client)

    assert 'sentinel_detection_events_total{rule_id="ssh_bruteforce",severity="high"} 1.0' in text
    assert 'sentinel_incidents_total{severity="high"} 1.0' in text
    assert "sentinel_detection_latency_seconds_count 1.0" in text


def test_open_incidents_gauge_reflects_current_state() -> None:
    client = _client()
    client.post("/api/v1/events", json=_body([_detection()]), headers=AUTH)

    text = _metrics_text(client)

    assert 'sentinel_incident_status{status="OPEN"} 1.0' in text


def test_no_source_ip_or_username_appears_as_a_label() -> None:
    client = _client()
    client.post("/api/v1/events", json=_body([_detection()]), headers=AUTH)

    text = _metrics_text(client)

    assert "203.0.113.50" not in text
