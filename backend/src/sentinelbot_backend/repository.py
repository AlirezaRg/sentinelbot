"""Storage for events and incidents.

In-memory for Phase 6. Phase 7 replaces these with PostgreSQL repositories that expose the
same methods, so the routes do not change.
"""

from __future__ import annotations

from collections import OrderedDict
from collections.abc import Callable, Iterable
from dataclasses import dataclass
from datetime import datetime
from ipaddress import IPv4Address, IPv6Address
from uuid import UUID

from sentinelbot_agent.models import Event, EventType, Severity
from sentinelbot_detection.correlation import Incident, IncidentStatus, IncidentStore


class DuplicateEventError(Exception):
    """An event with the same ``event_id`` was already stored."""

    def __init__(self, event_ids: list[str]) -> None:
        super().__init__("duplicate event_id")
        self.event_ids = event_ids


@dataclass(frozen=True, slots=True)
class HostSummary:
    host_id: str
    first_seen: datetime
    last_seen: datetime
    event_count: int


class EventRepository:
    """Bounded event store. The oldest events are dropped once ``capacity`` is reached."""

    def __init__(self, capacity: int) -> None:
        self._capacity = capacity
        self._events: OrderedDict[UUID, Event] = OrderedDict()

    def __len__(self) -> int:
        return len(self._events)

    def get(self, event_id: UUID) -> Event | None:
        return self._events.get(event_id)

    def add_many(self, events: list[Event]) -> None:
        duplicates = [str(e.event_id) for e in events if e.event_id in self._events]
        if duplicates:
            raise DuplicateEventError(duplicates)
        for event in events:
            self._events[event.event_id] = event
        while len(self._events) > self._capacity:
            self._events.popitem(last=False)

    def query(
        self,
        *,
        event_type: EventType | None,
        severity: Severity | None,
        host_id: str | None,
        source_ip: IPv4Address | IPv6Address | None,
        since: datetime | None,
        until: datetime | None,
        descending: bool,
        offset: int,
        limit: int,
    ) -> tuple[list[Event], int]:
        matches = [
            e
            for e in self._events.values()
            if (event_type is None or e.event_type is event_type)
            and (severity is None or e.severity is severity)
            and (host_id is None or e.host_id == host_id)
            and (source_ip is None or e.source_ip == source_ip)
            and (since is None or e.timestamp >= since)
            and (until is None or e.timestamp <= until)
        ]
        matches.sort(key=lambda e: e.timestamp, reverse=descending)
        return matches[offset : offset + limit], len(matches)

    def counts_by_severity(self) -> dict[str, int]:
        counts = {severity.value: 0 for severity in Severity}
        for event in self._events.values():
            counts[event.severity.value] += 1
        return counts

    def counts_by_type(self) -> dict[str, int]:
        counts: dict[str, int] = {}
        for event in self._events.values():
            counts[event.event_type.value] = counts.get(event.event_type.value, 0) + 1
        return counts

    def hosts(self) -> list[HostSummary]:
        seen: dict[str, HostSummary] = {}
        for event in self._events.values():
            current = seen.get(event.host_id)
            if current is None:
                seen[event.host_id] = HostSummary(
                    event.host_id, event.timestamp, event.timestamp, 1
                )
            else:
                seen[event.host_id] = HostSummary(
                    event.host_id,
                    min(current.first_seen, event.timestamp),
                    max(current.last_seen, event.timestamp),
                    current.event_count + 1,
                )
        return list(seen.values())


class IncidentRepository:
    """Read and status-change access over the correlation store."""

    def __init__(
        self, store: IncidentStore, persist: Callable[[Incident], None] | None = None
    ) -> None:
        self._store = store
        self._persist = persist

    def persist_ids(self, incident_ids: Iterable[str]) -> None:
        """Write the given incidents to durable storage, if any is configured."""
        if self._persist is None:
            return
        for incident_id in incident_ids:
            incident = self._store.incidents.get(incident_id)
            if incident is not None:
                self._persist(incident)

    def get(self, incident_id: str) -> Incident | None:
        return self._store.incidents.get(incident_id)

    def query(
        self,
        *,
        status: IncidentStatus | None,
        severity: Severity | None,
        host_id: str | None,
        sort_by: str,
        descending: bool,
        offset: int,
        limit: int,
    ) -> tuple[list[Incident], int]:
        matches = [
            i
            for i in self._store.incidents.values()
            if (status is None or i.status is status)
            and (severity is None or i.severity is severity)
            and (host_id is None or i.host_id == host_id)
        ]
        matches.sort(key=lambda i: getattr(i, sort_by), reverse=descending)
        return matches[offset : offset + limit], len(matches)

    def counts_by_status(self) -> dict[str, int]:
        counts = {status.value: 0 for status in IncidentStatus}
        for incident in self._store.incidents.values():
            counts[incident.status.value] += 1
        return counts

    def set_status(self, incident_id: str, status: IncidentStatus) -> Incident:
        incident = self._store.set_status(incident_id, status)
        self._store.save()
        if self._persist is not None:
            self._persist(incident)
        return incident

    def total(self) -> int:
        return len(self._store.incidents)

    def open_for_host(self, host_id: str) -> int:
        return sum(
            1
            for i in self._store.incidents.values()
            if i.host_id == host_id
            and i.status in (IncidentStatus.OPEN, IncidentStatus.INVESTIGATING)
        )
