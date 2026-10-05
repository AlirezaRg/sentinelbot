"""Collector interface and helpers shared by all collectors."""

from __future__ import annotations

from abc import ABC, abstractmethod
from datetime import UTC, datetime
from ipaddress import IPv4Address, IPv6Address
from typing import Any

from sentinelbot_agent.config import AgentConfig
from sentinelbot_agent.models import Event, EventType, Severity


class Collector(ABC):
    """A telemetry source that turns host state into normalized events.

    Collectors must not keep long-lived state that affects correctness; the agent
    isolates failures, so a raising ``collect`` only drops that collector's events.
    """

    name: str

    def __init__(self, config: AgentConfig) -> None:
        self._config = config

    @abstractmethod
    def collect(self) -> list[Event]:
        """Return the events observed right now."""

    def _event(
        self,
        event_type: EventType,
        message: str,
        metadata: dict[str, Any] | None = None,
        severity: Severity = Severity.INFO,
        *,
        timestamp: datetime | None = None,
        username: str | None = None,
        source_ip: IPv4Address | IPv6Address | None = None,
    ) -> Event:
        fields: dict[str, Any] = {}
        if timestamp is not None:
            fields["timestamp"] = timestamp
        return Event(
            host_id=self._config.host_id,
            event_type=event_type,
            severity=severity,
            source=self.name,
            message=message,
            metadata=metadata or {},
            username=username,
            source_ip=source_ip,
            **fields,
        )


def to_iso(epoch_seconds: float | None) -> str | None:
    """Convert a Unix timestamp to an ISO-8601 UTC string, passing ``None`` through."""
    if epoch_seconds is None:
        return None
    return datetime.fromtimestamp(epoch_seconds, UTC).isoformat()
