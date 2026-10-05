"""Correlation into incidents: grouping, gaps, lifecycle, persistence and the CLI."""

from __future__ import annotations

import json
from datetime import UTC, datetime
from ipaddress import ip_address
from pathlib import Path

import pytest
from sentinelbot_agent.models import Event, EventType, Severity

from sentinelbot_detection.correlate_cli import main
from sentinelbot_detection.correlation import (
    CorrelationSettings,
    Correlator,
    IncidentStatus,
    IncidentStore,
    IncidentStoreError,
)
from tests.conftest import at

IP = "203.0.113.50"


def detection(
    seconds: float,
    *,
    rule: str = "ssh_bruteforce",
    ip: str | None = IP,
    host: str = "server-01",
    score: int = 40,
    severity: Severity = Severity.HIGH,
    username: str | None = None,
) -> Event:
    return Event(
        host_id=host,
        timestamp=at(seconds),
        event_type=EventType.SSH_BRUTEFORCE_DETECTED,
        severity=severity,
        source="detection",
        message=f"synthetic {rule}",
        source_ip=ip_address(ip) if ip else None,
        username=username,
        metadata={"rule_id": rule, "risk_score": score},
    )


def _correlator(tmp_path: Path, gap: int = 1800) -> tuple[Correlator, IncidentStore]:
    store = IncidentStore(tmp_path / "incidents.json")
    return Correlator(store, CorrelationSettings(gap_seconds=gap)), store


def test_first_detection_creates_open_incident_with_title_and_actions(tmp_path: Path) -> None:
    correlator, store = _correlator(tmp_path)

    incident = correlator.ingest(detection(0))

    assert incident.status is IncidentStatus.OPEN
    assert incident.title == f"Possible SSH brute-force activity from {IP}"
    assert incident.event_count == 1
    assert incident.risk_score == 40
    assert any("firewall" in action for action in incident.recommended_actions)
    assert len(store.incidents) == 1


def test_related_detections_within_gap_join_the_same_incident(tmp_path: Path) -> None:
    correlator, store = _correlator(tmp_path)

    first = correlator.ingest(detection(0))
    second = correlator.ingest(detection(600, rule="root_login", score=75, username="root"))

    assert second.incident_id == first.incident_id
    assert len(store.incidents) == 1
    assert second.event_count == 2
    assert second.rules == ["ssh_bruteforce", "root_login"]
    assert second.risk_score == 75  # maximum of the related scores
    assert second.severity is Severity.HIGH
    assert second.usernames == ["root"]
    assert second.last_seen == at(600)
    assert second.title.startswith(
        "Possible SSH brute-force activity"
    )  # brute-force outranks root_login


def test_targeted_users_from_detection_metadata_are_collected(tmp_path: Path) -> None:
    correlator, _ = _correlator(tmp_path)
    event = detection(0)
    event = event.model_copy(
        update={"metadata": {**event.metadata, "targeted_users": ["admin", "root"]}}
    )

    incident = correlator.ingest(event)

    assert incident.usernames == ["admin", "root"]


def test_title_follows_rule_priority(tmp_path: Path) -> None:
    correlator, _ = _correlator(tmp_path)
    correlator.ingest(detection(0, rule="root_login"))
    incident = correlator.ingest(detection(10, rule="ssh_bruteforce"))

    assert incident.title.startswith("Possible SSH brute-force activity")


def test_quiet_period_longer_than_gap_starts_new_incident(tmp_path: Path) -> None:
    correlator, store = _correlator(tmp_path, gap=100)

    first = correlator.ingest(detection(0))
    second = correlator.ingest(detection(500))

    assert second.incident_id != first.incident_id
    assert len(store.incidents) == 2


def test_different_sources_get_separate_incidents(tmp_path: Path) -> None:
    correlator, _ = _correlator(tmp_path)

    a = correlator.ingest(detection(0, ip="203.0.113.1"))
    b = correlator.ingest(detection(1, ip="203.0.113.2"))

    assert a.incident_id != b.incident_id


def test_detections_without_source_group_by_host(tmp_path: Path) -> None:
    correlator, _ = _correlator(tmp_path)

    first = correlator.ingest(
        detection(0, rule="privileged_process", ip=None, severity=Severity.MEDIUM)
    )
    second = correlator.ingest(
        detection(30, rule="unexpected_port", ip=None, severity=Severity.MEDIUM)
    )

    assert first.incident_id == second.incident_id
    assert first.source_ip is None
    assert first.title == "New root-owned process on server-01"  # higher-priority rule


def test_resolved_incident_is_not_reused(tmp_path: Path) -> None:
    correlator, store = _correlator(tmp_path)
    first = correlator.ingest(detection(0))
    store.set_status(first.incident_id, IncidentStatus.RESOLVED)

    second = correlator.ingest(detection(10))

    assert second.incident_id != first.incident_id
    assert second.status is IncidentStatus.OPEN


def test_investigating_incident_keeps_collecting(tmp_path: Path) -> None:
    correlator, store = _correlator(tmp_path)
    first = correlator.ingest(detection(0))
    store.set_status(first.incident_id, IncidentStatus.INVESTIGATING)

    assert correlator.ingest(detection(10)).incident_id == first.incident_id


def test_store_round_trips_through_json(tmp_path: Path) -> None:
    correlator, store = _correlator(tmp_path)
    incident = correlator.ingest(detection(0))
    store.save()

    reloaded = IncidentStore(tmp_path / "incidents.json")
    reloaded.load()

    assert reloaded.incidents[incident.incident_id] == incident


def test_corrupt_store_is_an_error_not_a_silent_reset(tmp_path: Path) -> None:
    path = tmp_path / "incidents.json"
    path.write_text("{broken", encoding="utf-8")

    with pytest.raises(IncidentStoreError):
        IncidentStore(path).load()


def test_related_event_ids_are_capped(tmp_path: Path) -> None:
    correlator, _ = _correlator(tmp_path)
    for second in range(250):
        incident = correlator.ingest(detection(second))

    assert incident.event_count == 250
    assert len(incident.related_event_ids) == 200


def test_cli_ingests_detections_and_prints_incident(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    events = tmp_path / "detections.jsonl"
    store = tmp_path / "incidents.json"
    events.write_text(
        "\n".join(detection(s).model_dump_json() for s in range(3)) + "\n", encoding="utf-8"
    )

    assert main(["--input", str(events), "--store", str(store), "--log-level", "ERROR"]) == 0

    printed = [json.loads(line) for line in capsys.readouterr().out.splitlines()]
    assert len(printed) == 1
    assert printed[0]["event_count"] == 3
    assert json.loads(store.read_text(encoding="utf-8"))["incidents"][0]["status"] == "OPEN"


def test_cli_status_change_persists(tmp_path: Path, capsys: pytest.CaptureFixture[str]) -> None:
    events = tmp_path / "detections.jsonl"
    store = tmp_path / "incidents.json"
    events.write_text(detection(0).model_dump_json() + "\n", encoding="utf-8")
    main(["--input", str(events), "--store", str(store), "--log-level", "ERROR"])
    incident_id = json.loads(capsys.readouterr().out)["incident_id"]

    code = main(
        ["--store", str(store), "--set-status", incident_id, "resolved", "--log-level", "ERROR"]
    )

    assert code == 0
    assert json.loads(store.read_text(encoding="utf-8"))["incidents"][0]["status"] == "RESOLVED"


def test_cli_rejects_unknown_status_and_incident(tmp_path: Path) -> None:
    store = tmp_path / "incidents.json"
    store.write_text('{"incidents": []}', encoding="utf-8")

    assert (
        main(["--store", str(store), "--set-status", "INC-x", "resolved", "--log-level", "ERROR"])
        == 2
    )
    assert (
        main(["--store", str(store), "--set-status", "INC-x", "bogus", "--log-level", "ERROR"]) == 2
    )


def test_cli_ignores_non_detection_events(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    events = tmp_path / "events.jsonl"
    telemetry = Event(
        host_id="server-01",
        timestamp=datetime(2026, 10, 4, tzinfo=UTC),
        event_type=EventType.SSH_LOGIN_FAILED,
        source="auth",
        message="telemetry only",
    )
    events.write_text(telemetry.model_dump_json() + "\n", encoding="utf-8")

    main(["--input", str(events), "--store", str(tmp_path / "i.json"), "--log-level", "ERROR"])

    assert capsys.readouterr().out == ""
