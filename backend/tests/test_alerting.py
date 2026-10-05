"""Alerting through the API: which detections notify, cooldown, metrics and settings checks."""

from __future__ import annotations

from datetime import UTC, datetime, timedelta
from ipaddress import ip_address
from typing import Any

import pytest
from fastapi.testclient import TestClient
from sentinelbot_agent.models import Event, EventType, Severity
from sentinelbot_alerts.channels import RecordingChannel

from sentinelbot_backend.app import create_app
from sentinelbot_backend.config import ApiSettings, SettingsError

KEY = "k" * 32
AUTH = {"X-API-Key": KEY}
T0 = datetime(2026, 10, 4, 12, 0, tzinfo=UTC)


def _detection(seconds: float, severity: Severity = Severity.HIGH) -> Event:
    return Event(
        host_id="server-01",
        timestamp=T0 + timedelta(seconds=seconds),
        event_type=EventType.SSH_BRUTEFORCE_DETECTED,
        severity=severity,
        source="detection",
        message="synthetic",
        source_ip=ip_address("203.0.113.50"),
        metadata={"rule_id": "ssh_bruteforce", "risk_score": 40},
    )


def _post(client: TestClient, events: list[Event]) -> None:
    body: list[dict[str, Any]] = [e.model_dump(mode="json") for e in events]
    response = client.post("/api/v1/events", json=body, headers=AUTH)
    assert response.status_code == 201


@pytest.fixture
def channel() -> RecordingChannel:
    return RecordingChannel()


@pytest.fixture
def client(channel: RecordingChannel) -> TestClient:
    settings = ApiSettings(api_key=KEY, rate_limit_per_minute=0)
    return TestClient(create_app(settings, alert_channels=[channel]))


def test_high_severity_incident_sends_one_alert(
    client: TestClient, channel: RecordingChannel
) -> None:
    _post(client, [_detection(0)])

    assert len(channel.sent) == 1
    subject, body = channel.sent[0]
    assert "HIGH" in subject
    assert "203.0.113.50" in body
    assert "HIGH SECURITY ALERT" in body


def test_repeat_inside_cooldown_does_not_resend(
    client: TestClient, channel: RecordingChannel
) -> None:
    _post(client, [_detection(0)])
    _post(client, [_detection(60)])

    assert len(channel.sent) == 1


def test_low_severity_detection_does_not_alert(
    client: TestClient, channel: RecordingChannel
) -> None:
    _post(client, [_detection(0, severity=Severity.LOW)])

    assert channel.sent == []


def test_alert_outcome_is_counted_in_metrics(client: TestClient) -> None:
    _post(client, [_detection(0)])

    text = client.get("/metrics", headers=AUTH).text

    assert 'sentinel_alerts_total{channel="recording",status="sent"} 1.0' in text


def test_failing_channel_does_not_block_ingestion() -> None:
    class BrokenChannel:
        name = "email"

        def send(self, subject: str, body: str) -> None:
            raise ConnectionError("smtp unreachable")

    settings = ApiSettings(api_key=KEY, rate_limit_per_minute=0)
    client = TestClient(create_app(settings, alert_channels=[BrokenChannel()]))

    _post(client, [_detection(0)])
    incidents = client.get("/api/v1/incidents", headers=AUTH).json()

    assert incidents["total"] == 1
    metrics = client.get("/metrics", headers=AUTH).text
    assert 'sentinel_alerts_total{channel="email",status="failed"} 1.0' in metrics


def test_smtp_host_without_sender_is_rejected() -> None:
    with pytest.raises(SettingsError, match="SENTINEL_SMTP_FROM"):
        ApiSettings(
            api_key=KEY, smtp_host="smtp.example.test", alert_recipients=("soc@example.test",)
        )


def test_smtp_password_is_not_shown_in_repr() -> None:
    settings = ApiSettings(api_key=KEY, smtp_password="very-secret-password-value")

    assert "very-secret-password-value" not in repr(settings)


def test_unknown_alert_severity_is_rejected() -> None:
    with pytest.raises(SettingsError):
        ApiSettings(api_key=KEY, alert_min_severity="urgent")


def test_recipients_and_smtp_settings_are_read_from_env() -> None:
    settings = ApiSettings.from_env(
        {
            "SENTINEL_SMTP_HOST": "smtp.example.test",
            "SENTINEL_SMTP_FROM": "sentinel@example.test",
            "SENTINEL_ALERT_RECIPIENTS": "soc@example.test, admin@example.test",
            "SENTINEL_SMTP_PASSWORD": "from-env-value",
        }
    )

    assert settings.alert_recipients == ("soc@example.test", "admin@example.test")
    assert settings.smtp_password == "from-env-value"
    assert settings.smtp_port == 587
