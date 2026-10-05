"""The analysis endpoint and the AI settings that control whether any data leaves the host."""

from __future__ import annotations

from datetime import UTC, datetime, timedelta
from ipaddress import ip_address
from typing import Any

import pytest
from fastapi.testclient import TestClient
from sentinelbot_agent.models import Event, EventType, Severity

from sentinelbot_backend.app import create_app
from sentinelbot_backend.config import ApiSettings, SettingsError

KEY = "k" * 32
AUTH = {"X-API-Key": KEY}
T0 = datetime(2026, 10, 4, 12, 0, tzinfo=UTC)


def _detection() -> Event:
    return Event(
        host_id="server-01",
        timestamp=T0,
        event_type=EventType.SSH_BRUTEFORCE_DETECTED,
        severity=Severity.HIGH,
        source="detection",
        message="synthetic",
        source_ip=ip_address("203.0.113.50"),
        metadata={"rule_id": "ssh_bruteforce", "risk_score": 40},
    )


def _incident_id(client: TestClient) -> str:
    body: list[dict[str, Any]] = [_detection().model_dump(mode="json")]
    client.post("/api/v1/events", json=body, headers=AUTH)
    return str(client.get("/api/v1/incidents", headers=AUTH).json()["items"][0]["incident_id"])


def test_analysis_endpoint_returns_offline_analysis_by_default() -> None:
    client = TestClient(create_app(ApiSettings(api_key=KEY, rate_limit_per_minute=0)))
    incident_id = _incident_id(client)

    response = client.get(f"/api/v1/incidents/{incident_id}/analysis", headers=AUTH)
    body = response.json()

    assert response.status_code == 200
    assert body["provider"] == "rules"
    assert body["fallback_reason"] is None
    assert 0.0 <= body["confidence"] <= 1.0
    assert body["investigation_steps"]


def test_analysis_for_unknown_incident_is_404() -> None:
    client = TestClient(create_app(ApiSettings(api_key=KEY, rate_limit_per_minute=0)))

    assert client.get("/api/v1/incidents/INC-missing/analysis", headers=AUTH).status_code == 404


def test_analysis_requires_the_api_key() -> None:
    client = TestClient(create_app(ApiSettings(api_key=KEY, rate_limit_per_minute=0)))

    assert client.get("/api/v1/incidents/INC-x/analysis").status_code == 401


def test_anthropic_provider_needs_a_key() -> None:
    with pytest.raises(SettingsError, match="SENTINEL_AI_API_KEY"):
        ApiSettings(api_key=KEY, ai_provider="anthropic")


def test_unknown_ai_provider_is_rejected() -> None:
    with pytest.raises(SettingsError):
        ApiSettings(api_key=KEY, ai_provider="openai")


def test_ai_api_key_is_not_shown_in_repr() -> None:
    settings = ApiSettings(api_key=KEY, ai_provider="anthropic", ai_api_key="sk-secret-value-123")

    assert "sk-secret-value-123" not in repr(settings)


def test_default_provider_sends_nothing_outside_the_host() -> None:
    settings = ApiSettings.from_env({})

    assert settings.ai_provider == "rules"
    assert settings.ai_api_key is None


def test_timestamp_helper_keeps_tests_deterministic() -> None:
    assert T0 + timedelta(seconds=1) > T0
