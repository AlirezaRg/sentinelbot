"""System collector against the real local host (read-only psutil calls)."""

from __future__ import annotations

import socket
from typing import Any

from sentinelbot_agent.collectors.system import SystemCollector
from sentinelbot_agent.config import AgentConfig
from sentinelbot_agent.models import EventType


def _collect(config: AgentConfig) -> dict[EventType, dict[str, Any]]:
    events = SystemCollector(config).collect()
    return {event.event_type: event.metadata for event in events}


def test_emits_info_and_metrics_events(config: AgentConfig) -> None:
    events = SystemCollector(config).collect()

    assert [event.event_type for event in events] == [
        EventType.SYSTEM_INFO,
        EventType.SYSTEM_METRICS,
    ]
    assert all(event.host_id == "test-host" for event in events)
    assert all(event.source == "system" for event in events)


def test_system_info_contains_identity_fields(config: AgentConfig) -> None:
    info = _collect(config)[EventType.SYSTEM_INFO]

    assert info["hostname"] == socket.gethostname()
    assert info["kernel_version"]
    assert info["os_name"]
    assert info["boot_time"].endswith("+00:00")


def test_metrics_are_within_expected_ranges(config: AgentConfig) -> None:
    metrics = _collect(config)[EventType.SYSTEM_METRICS]

    assert 0 <= metrics["cpu_percent"] <= 100
    assert 0 <= metrics["memory_percent"] <= 100
    assert metrics["memory_total_bytes"] > metrics["memory_used_bytes"] >= 0
    assert 0 <= metrics["disk_percent"] <= 100
    assert metrics["disk_total_bytes"] > 0
    assert metrics["uptime_seconds"] > 0
    assert metrics["cpu_count"] is None or metrics["cpu_count"] >= 1


def test_load_average_is_none_or_three_values(config: AgentConfig) -> None:
    load = _collect(config)[EventType.SYSTEM_METRICS]["load_average"]

    if load is not None:
        assert set(load) == {"1m", "5m", "15m"}
