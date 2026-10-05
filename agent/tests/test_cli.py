"""CLI end-to-end: runs the real collectors on this host and checks the JSON Lines output."""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from sentinelbot_agent.cli import EXIT_CONFIG_ERROR, EXIT_OK, main
from sentinelbot_agent.models import Event, EventType


@pytest.mark.integration
def test_once_writes_parseable_events_for_all_default_collectors(tmp_path: Path) -> None:
    output = tmp_path / "events.jsonl"

    exit_code = main(["--once", "--output", str(output), "--log-level", "ERROR"])

    assert exit_code == EXIT_OK
    events = [
        Event.model_validate_json(line) for line in output.read_text(encoding="utf-8").splitlines()
    ]
    event_types = {event.event_type for event in events}
    assert {
        EventType.SYSTEM_INFO,
        EventType.SYSTEM_METRICS,
        EventType.PROCESS_SNAPSHOT,
        EventType.NETWORK_SNAPSHOT,
    } <= event_types
    assert not [e for e in events if e.event_type is EventType.COLLECTOR_ERROR], (
        "a collector failed on this host"
    )


def test_collectors_flag_limits_output(tmp_path: Path) -> None:
    output = tmp_path / "events.jsonl"

    main(["--once", "--output", str(output), "--collectors", "system", "--log-level", "ERROR"])

    lines = output.read_text(encoding="utf-8").splitlines()
    sources = {json.loads(line)["source"] for line in lines}
    assert sources == {"system"}


def test_unknown_collector_exits_with_config_error(tmp_path: Path) -> None:
    exit_code = main(["--once", "--output", str(tmp_path / "x.jsonl"), "--collectors", "telepathy"])

    assert exit_code == EXIT_CONFIG_ERROR
    assert not (tmp_path / "x.jsonl").exists()


def test_invalid_interval_exits_with_config_error(tmp_path: Path) -> None:
    exit_code = main(["--once", "--output", str(tmp_path / "x.jsonl"), "--interval", "0"])

    assert exit_code == EXIT_CONFIG_ERROR
