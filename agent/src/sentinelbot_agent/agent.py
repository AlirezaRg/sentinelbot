"""Agent orchestration: run collectors, isolate their failures, and emit events."""

from __future__ import annotations

import logging
import threading
from collections.abc import Sequence

from sentinelbot_agent.collectors.base import Collector
from sentinelbot_agent.config import AgentConfig
from sentinelbot_agent.models import Event, EventType, Severity
from sentinelbot_agent.output import EventSink

logger = logging.getLogger(__name__)


class Agent:
    """Runs each collector once per cycle and writes the resulting events to a sink."""

    def __init__(
        self,
        config: AgentConfig,
        collectors: Sequence[Collector],
        sink: EventSink,
    ) -> None:
        self._config = config
        self._collectors = list(collectors)
        self._sink = sink

    def collect_once(self) -> list[Event]:
        """Run one collection cycle. A failing collector yields a ``collector_error`` event."""
        events: list[Event] = []
        for collector in self._collectors:
            events.extend(self._run_collector(collector))
        for event in events:
            self._sink.emit(event)
        self._sink.flush()
        logger.info("collection cycle complete", extra={"events": len(events)})
        return events

    def run_forever(self, stop: threading.Event | None = None) -> None:
        """Collect every ``interval_seconds`` until ``stop`` is set (or interrupted)."""
        stop_event = stop or threading.Event()
        logger.info("agent started", extra={"interval_seconds": self._config.interval_seconds})
        while not stop_event.is_set():
            self.collect_once()
            stop_event.wait(self._config.interval_seconds)

    def _run_collector(self, collector: Collector) -> list[Event]:
        try:
            return collector.collect()
        except Exception as exc:  # isolation boundary: one bad collector must not stop the agent
            logger.warning(
                "collector failed", extra={"collector": collector.name, "error": str(exc)}
            )
            return [
                Event(
                    host_id=self._config.host_id,
                    event_type=EventType.COLLECTOR_ERROR,
                    severity=Severity.LOW,
                    source=collector.name,
                    message=f"Collector '{collector.name}' failed",
                    metadata={
                        "collector": collector.name,
                        "error_type": type(exc).__name__,
                        "error": str(exc),
                    },
                )
            ]
