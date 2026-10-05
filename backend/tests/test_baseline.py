"""The learned baseline survives a restart, and the port allowlist replaces learning."""

from __future__ import annotations

from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Any

from fastapi.testclient import TestClient
from sentinelbot_agent.models import Event, EventType, Severity

from sentinelbot_backend.app import create_app
from sentinelbot_backend.config import ApiSettings

KEY = "k" * 32
AUTH = {"X-API-Key": KEY}
T0 = datetime(2026, 10, 4, 12, 0, tzinfo=UTC)


def _snapshot(seconds: float, *ports: int) -> dict[str, Any]:
    records = [
        {
            "protocol": "tcp",
            "local_port": port,
            "local_address": "0.0.0.0",
            "process": "svc",
            "pid": 1,
        }
        for port in ports
    ]
    event = Event(
        host_id="server-01",
        timestamp=T0 + timedelta(seconds=seconds),
        event_type=EventType.NETWORK_SNAPSHOT,
        severity=Severity.INFO,
        source="network",
        message="synthetic",
        metadata={
            "listening_ports": records,
            "listening_port_count": len(records),
            "connection_count": 0,
        },
    )
    return event.model_dump(mode="json")


def _unexpected_ports(client: TestClient) -> list[int]:
    page = client.get(
        "/api/v1/events", params={"event_type": "unexpected_listening_port_detected"}, headers=AUTH
    ).json()
    return sorted(item["metadata"]["port"] for item in page["items"])


def test_baseline_survives_a_restart(tmp_path: Path) -> None:
    path = tmp_path / "baseline.json"
    settings = ApiSettings(api_key=KEY, rate_limit_per_minute=0, baseline_path=path)

    first = TestClient(create_app(settings))
    first.post("/api/v1/events", json=[_snapshot(0, 22)], headers=AUTH)  # learns port 22

    restarted = TestClient(create_app(settings))  # a new process, same baseline file
    restarted.post("/api/v1/events", json=[_snapshot(60, 22, 4444)], headers=AUTH)

    assert _unexpected_ports(restarted) == [4444]  # 22 was remembered, so it does not alert


def test_allowlist_flags_only_ports_outside_it(tmp_path: Path) -> None:
    settings = ApiSettings(
        api_key=KEY,
        rate_limit_per_minute=0,
        allowed_listening_ports=(22, 8000),
    )
    client = TestClient(create_app(settings))

    client.post("/api/v1/events", json=[_snapshot(0, 22, 8000, 4444)], headers=AUTH)

    assert _unexpected_ports(client) == [4444]


def test_invalid_allowlist_port_is_rejected() -> None:
    import pytest

    from sentinelbot_backend.config import SettingsError

    with pytest.raises(SettingsError):
        ApiSettings(api_key=KEY, allowed_listening_ports=(70000,))


def test_allowlist_is_read_from_env() -> None:
    settings = ApiSettings.from_env({"SENTINEL_ALLOWED_PORTS": "22, 443,8000"})

    assert settings.allowed_listening_ports == (22, 443, 8000)
