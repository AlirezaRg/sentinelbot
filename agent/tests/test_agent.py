"""Agent orchestration: ordering, failure isolation and sink output."""

from __future__ import annotations

import io
import json

from sentinelbot_agent.agent import Agent
from sentinelbot_agent.collectors.base import Collector
from sentinelbot_agent.config import AgentConfig
from sentinelbot_agent.models import Event, EventType, Severity
from sentinelbot_agent.output import JsonLinesSink


class StaticCollector(Collector):
    name = "static"

    def collect(self) -> list[Event]:
        return [self._event(EventType.SYSTEM_INFO, "hello")]


class BrokenCollector(Collector):
    name = "broken"

    def collect(self) -> list[Event]:
        raise RuntimeError("log file unreadable")


def _run(config: AgentConfig, collectors: list[Collector]) -> tuple[list[Event], io.StringIO]:
    buffer = io.StringIO()
    agent = Agent(config, collectors, JsonLinesSink(buffer))
    return agent.collect_once(), buffer


def test_collectors_run_in_order_and_events_are_written(config: AgentConfig) -> None:
    events, buffer = _run(config, [StaticCollector(config), StaticCollector(config)])

    assert len(events) == 2
    lines = buffer.getvalue().splitlines()
    assert len(lines) == 2
    assert all(json.loads(line)["message"] == "hello" for line in lines)


def test_failing_collector_does_not_stop_others(config: AgentConfig) -> None:
    events, _ = _run(config, [BrokenCollector(config), StaticCollector(config)])

    assert [e.event_type for e in events] == [EventType.COLLECTOR_ERROR, EventType.SYSTEM_INFO]


def test_failure_is_reported_as_low_severity_event(config: AgentConfig) -> None:
    events, _ = _run(config, [BrokenCollector(config), StaticCollector(config)])
    error_event = events[0]

    assert error_event.severity is Severity.LOW
    assert error_event.source == "broken"
    assert error_event.metadata["error_type"] == "RuntimeError"
    assert error_event.metadata["error"] == "log file unreadable"
    assert error_event.host_id == "test-host"


def test_empty_collector_list_produces_no_output(config: AgentConfig) -> None:
    events, buffer = _run(config, [])

    assert events == []
    assert buffer.getvalue() == ""
