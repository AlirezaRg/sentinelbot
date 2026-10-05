"""Alert text, severity filter, cooldown and escalation, email delivery and failure isolation."""

from __future__ import annotations

from datetime import UTC, datetime, timedelta
from typing import Any

import pytest
from sentinelbot_agent.models import Severity
from sentinelbot_detection.correlation import Incident, IncidentStatus

from sentinelbot_alerts.channels import EmailChannel, RecordingChannel
from sentinelbot_alerts.message import format_alert
from sentinelbot_alerts.notifier import Notifier
from sentinelbot_alerts.policy import AlertPolicy

T0 = datetime(2026, 10, 4, 12, 0, tzinfo=UTC)


def incident(
    severity: Severity = Severity.HIGH,
    *,
    incident_id: str = "INC-1",
    last_seen_offset: float = 0,
    status: IncidentStatus = IncidentStatus.OPEN,
) -> Incident:
    return Incident(
        incident_id=incident_id,
        title="Possible SSH brute-force activity from 203.0.113.50",
        description="6 detection(s)",
        severity=severity,
        risk_score=75,
        host_id="server-01",
        source_ip="203.0.113.50",
        first_seen=T0,
        last_seen=T0 + timedelta(seconds=last_seen_offset),
        event_count=6,
        recommended_actions=["Review SSH authentication logs for this source address."],
        status=status,
    )


# --- message -----------------------------------------------------------------


def test_message_follows_the_spec_layout() -> None:
    subject, body = format_alert(incident())

    assert subject == "[SentinelBot] HIGH: Possible SSH brute-force activity from 203.0.113.50"
    assert body.startswith("HIGH SECURITY ALERT")
    for label in ("Incident:", "Host:", "Source:", "Risk:", "Severity:", "Recommended action:"):
        assert label in body
    assert "75/100" in body
    assert "server-01" in body
    assert "- Review SSH authentication logs" in body


def test_message_without_source_says_so() -> None:
    no_source = incident().model_copy(update={"source_ip": None})

    _, body = format_alert(no_source)

    assert "n/a" in body


# --- policy ------------------------------------------------------------------


def test_incidents_below_the_minimum_severity_do_not_alert() -> None:
    policy = AlertPolicy(min_severity=Severity.HIGH, cooldown_seconds=900)

    assert policy.should_alert(incident(Severity.MEDIUM)) is False


def test_new_incident_at_or_above_minimum_alerts_once() -> None:
    policy = AlertPolicy(min_severity=Severity.HIGH, cooldown_seconds=900)

    assert policy.should_alert(incident(Severity.HIGH)) is True


def test_repeat_within_cooldown_is_suppressed() -> None:
    policy = AlertPolicy(min_severity=Severity.HIGH, cooldown_seconds=900)
    policy.should_alert(incident(Severity.HIGH, last_seen_offset=0))

    assert policy.should_alert(incident(Severity.HIGH, last_seen_offset=60)) is False


def test_repeat_after_cooldown_alerts_again() -> None:
    policy = AlertPolicy(min_severity=Severity.HIGH, cooldown_seconds=900)
    policy.should_alert(incident(Severity.HIGH, last_seen_offset=0))

    assert policy.should_alert(incident(Severity.HIGH, last_seen_offset=1000)) is True


def test_escalation_alerts_even_inside_cooldown() -> None:
    policy = AlertPolicy(min_severity=Severity.HIGH, cooldown_seconds=900)
    policy.should_alert(incident(Severity.HIGH, last_seen_offset=0))

    assert policy.should_alert(incident(Severity.CRITICAL, last_seen_offset=60)) is True


def test_different_incidents_are_independent() -> None:
    policy = AlertPolicy(min_severity=Severity.HIGH, cooldown_seconds=900)
    policy.should_alert(incident(incident_id="INC-1"))

    assert policy.should_alert(incident(incident_id="INC-2")) is True


def test_negative_cooldown_is_rejected() -> None:
    with pytest.raises(ValueError):
        AlertPolicy(min_severity=Severity.HIGH, cooldown_seconds=-1)


# --- notifier ----------------------------------------------------------------


def test_notifier_sends_to_every_channel_and_reports_results() -> None:
    first, second = RecordingChannel(), RecordingChannel()
    results: list[tuple[str, str]] = []
    notifier = Notifier(
        AlertPolicy(Severity.HIGH, 900),
        [first, second],
        on_result=lambda channel, status: results.append((channel, status)),
    )

    notifier.notify([incident()])

    assert len(first.sent) == len(second.sent) == 1
    assert results == [("recording", "sent"), ("recording", "sent")]


class FailingChannel:
    name = "email"

    def send(self, subject: str, body: str) -> None:
        raise ConnectionError("smtp down")


def test_failing_channel_is_reported_and_does_not_raise() -> None:
    results: list[tuple[str, str]] = []
    notifier = Notifier(
        AlertPolicy(Severity.HIGH, 900),
        [FailingChannel()],
        on_result=lambda channel, status: results.append((channel, status)),
    )

    notifier.notify([incident()])

    assert results == [("email", "failed")]


# --- email -------------------------------------------------------------------


class FakeSMTP:
    instances: list[FakeSMTP] = []

    def __init__(self, host: str, port: int, timeout: float) -> None:
        self.host, self.port, self.timeout = host, port, timeout
        self.started_tls = False
        self.logged_in: tuple[str, str] | None = None
        self.sent: list[Any] = []
        FakeSMTP.instances.append(self)

    def __enter__(self) -> FakeSMTP:
        return self

    def __exit__(self, *args: object) -> None:
        return None

    def starttls(self, context: object) -> None:
        self.started_tls = True

    def login(self, user: str, password: str) -> None:
        self.logged_in = (user, password)

    def send_message(self, message: Any) -> None:
        self.sent.append(message)


def test_email_uses_starttls_login_and_the_recipients(monkeypatch: pytest.MonkeyPatch) -> None:
    FakeSMTP.instances.clear()
    monkeypatch.setattr("sentinelbot_alerts.channels.smtplib.SMTP", FakeSMTP)
    channel = EmailChannel(
        host="smtp.example.test",
        port=587,
        sender="sentinel@example.test",
        recipients=["soc@example.test", "admin@example.test"],
        username="sentinel",
        password="secret-value",
    )

    channel.send("Subject line", "Body text")

    smtp = FakeSMTP.instances[0]
    assert (smtp.host, smtp.port) == ("smtp.example.test", 587)
    assert smtp.started_tls is True
    assert smtp.logged_in == ("sentinel", "secret-value")
    message = smtp.sent[0]
    assert message["Subject"] == "Subject line"
    assert message["To"] == "soc@example.test, admin@example.test"
    assert message.get_content().strip() == "Body text"


def test_email_without_recipients_is_rejected() -> None:
    with pytest.raises(ValueError):
        EmailChannel(host="h", port=25, sender="s@x", recipients=[])
