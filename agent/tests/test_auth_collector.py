"""Auth collector: event generation, source failure isolation, and restart without duplicates."""

from __future__ import annotations

import json
import shutil
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

from sentinelbot_agent.auth.sources import FileSource, JournalSource, SourceError
from sentinelbot_agent.auth.state import StateStore
from sentinelbot_agent.collectors.auth import AuthCollector
from sentinelbot_agent.config import AgentConfig
from sentinelbot_agent.models import EventType, Severity

FIXTURE = Path(__file__).parent / "fixtures" / "auth.log"
NOW = datetime(2026, 10, 4, 12, 0, tzinfo=UTC)


class BrokenSource:
    key = "broken"

    def read_new(self, state: dict[str, Any]) -> tuple[list[Any], dict[str, Any]]:
        raise SourceError("permission denied reading /var/log/secure")


def _config(tmp_path: Path) -> AgentConfig:
    return AgentConfig(host_id="server-01", state_path=tmp_path / "state" / "agent.json")


def _collector(config: AgentConfig, sources: list[Any]) -> AuthCollector:
    return AuthCollector(config, sources=sources, store=StateStore(config.state_path))


def test_fixture_produces_events_with_fields(tmp_path: Path) -> None:
    log = tmp_path / "auth.log"
    shutil.copy(FIXTURE, log)
    config = _config(tmp_path)

    events = _collector(config, [FileSource(log, now=lambda: NOW)]).collect()

    by_type = {event.event_type: event for event in events}
    assert len(events) == 6
    failed = next(e for e in events if e.event_type is EventType.SSH_LOGIN_FAILED)
    assert failed.source == "auth"
    assert failed.host_id == "server-01"
    assert failed.severity is Severity.LOW
    assert str(failed.source_ip) == "203.0.113.50"
    assert failed.timestamp.tzinfo is not None
    assert EventType.SSH_ROOT_LOGIN in by_type
    assert by_type[EventType.SSH_ROOT_LOGIN].username == "root"
    assert by_type[EventType.SUDO_COMMAND].username == "alice"


def test_restart_does_not_duplicate_events(tmp_path: Path) -> None:
    log = tmp_path / "auth.log"
    shutil.copy(FIXTURE, log)
    config = _config(tmp_path)

    first = _collector(config, [FileSource(log, now=lambda: NOW)]).collect()
    second = _collector(config, [FileSource(log, now=lambda: NOW)]).collect()

    assert len(first) == 6
    assert second == []


def test_new_lines_after_restart_are_collected_once(tmp_path: Path) -> None:
    log = tmp_path / "auth.log"
    shutil.copy(FIXTURE, log)
    config = _config(tmp_path)
    _collector(config, [FileSource(log, now=lambda: NOW)]).collect()

    with log.open("a", encoding="utf-8") as handle:
        handle.write(
            "Oct  4 09:10:00 server-01 sshd[9]: "
            "Failed password for root from 203.0.113.9 port 9 ssh2\n"
        )
    events = _collector(config, [FileSource(log, now=lambda: NOW)]).collect()

    assert [e.event_type for e in events] == [EventType.SSH_LOGIN_FAILED]


def test_failing_source_does_not_stop_others(tmp_path: Path) -> None:
    log = tmp_path / "auth.log"
    shutil.copy(FIXTURE, log)
    config = _config(tmp_path)

    events = _collector(config, [BrokenSource(), FileSource(log, now=lambda: NOW)]).collect()

    errors = [e for e in events if e.event_type is EventType.COLLECTOR_ERROR]
    assert len(errors) == 1
    assert errors[0].severity is Severity.LOW
    assert errors[0].metadata["source"] == "broken"
    assert "permission denied" in errors[0].metadata["error"]
    assert len(events) == 7


def test_corrupt_state_file_starts_fresh_instead_of_crashing(tmp_path: Path) -> None:
    log = tmp_path / "auth.log"
    shutil.copy(FIXTURE, log)
    config = _config(tmp_path)
    config.state_path.parent.mkdir(parents=True)
    config.state_path.write_text("{not json", encoding="utf-8")

    events = _collector(config, [FileSource(log, now=lambda: NOW)]).collect()

    assert len(events) == 6
    assert json.loads(config.state_path.read_text(encoding="utf-8"))


def test_state_is_written_atomically_and_round_trips(tmp_path: Path) -> None:
    store = StateStore(tmp_path / "deep" / "state.json")
    store.save({"journal": {"cursor": "c5"}})

    assert store.load() == {"journal": {"cursor": "c5"}}
    assert not (tmp_path / "deep" / "state.json.tmp").exists()


def test_journal_source_is_used_when_available(tmp_path: Path, monkeypatch: Any) -> None:
    from sentinelbot_agent.collectors import auth as auth_module

    monkeypatch.setattr(auth_module, "journalctl_available", lambda: True)
    collector = AuthCollector(_config(tmp_path))

    assert [type(s) for s in collector._sources] == [JournalSource]


def test_no_source_available_returns_nothing(tmp_path: Path, monkeypatch: Any) -> None:
    from sentinelbot_agent.collectors import auth as auth_module

    monkeypatch.setattr(auth_module, "journalctl_available", lambda: False)
    config = AgentConfig(
        host_id="h", auth_log_paths=(tmp_path / "missing.log",), state_path=tmp_path / "s.json"
    )

    assert AuthCollector(config).collect() == []
