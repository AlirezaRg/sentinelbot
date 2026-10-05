"""PostgreSQL (or SQLite in tests) storage. Method names match the in-memory repositories."""

from __future__ import annotations

from dataclasses import dataclass
from datetime import UTC, datetime
from ipaddress import IPv4Address, IPv6Address, ip_address
from uuid import UUID

from sentinelbot_agent.models import Event, EventType, Severity
from sentinelbot_database.models import EventRow, HostRow, IncidentRow, UserRow
from sentinelbot_detection.correlation import Incident, IncidentStatus
from sqlalchemy import func, select
from sqlalchemy.orm import Session, sessionmaker

from sentinelbot_backend.repository import DuplicateEventError, HostSummary


def _utc(value: datetime) -> datetime:
    """SQLite returns naive datetimes; PostgreSQL returns aware ones. Normalize both to UTC."""
    return value.replace(tzinfo=UTC) if value.tzinfo is None else value.astimezone(UTC)


class SqlEventRepository:
    def __init__(self, session_factory: sessionmaker[Session]) -> None:
        self._sessions = session_factory

    def __len__(self) -> int:
        with self._sessions() as session:
            return int(session.scalar(select(func.count()).select_from(EventRow)) or 0)

    def get(self, event_id: UUID) -> Event | None:
        with self._sessions() as session:
            row = session.get(EventRow, event_id)
            return _event_from_row(row) if row is not None else None

    def add_many(self, events: list[Event]) -> None:
        ids = [event.event_id for event in events]
        if len(set(ids)) != len(ids):
            raise DuplicateEventError([str(i) for i in ids if ids.count(i) > 1])
        with self._sessions() as session, session.begin():
            existing = list(
                session.scalars(select(EventRow.event_id).where(EventRow.event_id.in_(ids)))
            )
            if existing:
                raise DuplicateEventError([str(i) for i in existing])
            session.add_all([_event_row(event) for event in events])
            _touch_hosts(session, events)

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
        conditions = []
        if event_type is not None:
            conditions.append(EventRow.event_type == event_type.value)
        if severity is not None:
            conditions.append(EventRow.severity == severity.value)
        if host_id is not None:
            conditions.append(EventRow.host_id == host_id)
        if source_ip is not None:
            conditions.append(EventRow.source_ip == str(source_ip))
        if since is not None:
            conditions.append(EventRow.timestamp >= since)
        if until is not None:
            conditions.append(EventRow.timestamp <= until)

        order = EventRow.timestamp.desc() if descending else EventRow.timestamp.asc()
        rows_stmt = select(EventRow).where(*conditions).order_by(order, EventRow.event_id)
        count_stmt = select(func.count()).select_from(EventRow).where(*conditions)
        with self._sessions() as session:
            total = int(session.scalar(count_stmt) or 0)
            rows = session.scalars(rows_stmt.offset(offset).limit(limit)).all()
        return [_event_from_row(row) for row in rows], total

    def counts_by_severity(self) -> dict[str, int]:
        counts = {severity.value: 0 for severity in Severity}
        with self._sessions() as session:
            rows = session.execute(
                select(EventRow.severity, func.count()).group_by(EventRow.severity)
            ).all()
        for severity, count in rows:
            counts[severity] = int(count)
        return counts

    def counts_by_type(self) -> dict[str, int]:
        with self._sessions() as session:
            rows = session.execute(
                select(EventRow.event_type, func.count()).group_by(EventRow.event_type)
            ).all()
        return {event_type: int(count) for event_type, count in rows}

    def hosts(self) -> list[HostSummary]:
        with self._sessions() as session:
            rows = session.scalars(select(HostRow)).all()
        return [
            HostSummary(row.host_id, _utc(row.first_seen), _utc(row.last_seen), row.event_count)
            for row in rows
        ]


class SqlIncidentStore:
    """Write-through persistence for incidents. The API keeps an in-memory copy for queries."""

    def __init__(self, session_factory: sessionmaker[Session]) -> None:
        self._sessions = session_factory

    def load_all(self) -> list[Incident]:
        with self._sessions() as session:
            rows = session.scalars(select(IncidentRow)).all()
        return [_incident_from_row(row) for row in rows]

    def upsert(self, incident: Incident) -> None:
        with self._sessions() as session, session.begin():
            row = session.get(IncidentRow, incident.incident_id)
            if row is None:
                row = IncidentRow(incident_id=incident.incident_id)
                session.add(row)
            _apply_incident(row, incident)


@dataclass(frozen=True, slots=True)
class UserRecord:
    username: str
    password_hash: str
    role: str
    disabled: bool


class SqlUserStore:
    """Dashboard accounts. Only password hashes are stored."""

    def __init__(self, session_factory: sessionmaker[Session]) -> None:
        self._sessions = session_factory

    def get(self, username: str) -> UserRecord | None:
        with self._sessions() as session:
            row = session.get(UserRow, username)
            if row is None:
                return None
            return UserRecord(row.username, row.password_hash, row.role, bool(row.disabled))

    def create(self, username: str, password_hash: str, role: str) -> None:
        with self._sessions() as session, session.begin():
            session.add(
                UserRow(
                    username=username,
                    password_hash=password_hash,
                    role=role,
                    disabled=False,
                    created_at=datetime.now(UTC),
                )
            )


def _touch_hosts(session: Session, events: list[Event]) -> None:
    seen_times: dict[str, list[datetime]] = {}
    for event in events:
        seen_times.setdefault(event.host_id, []).append(event.timestamp)
    for host_id, times in seen_times.items():
        row = session.get(HostRow, host_id)
        if row is None:
            session.add(
                HostRow(
                    host_id=host_id,
                    first_seen=min(times),
                    last_seen=max(times),
                    event_count=len(times),
                )
            )
        else:
            row.first_seen = min(_utc(row.first_seen), min(times))
            row.last_seen = max(_utc(row.last_seen), max(times))
            row.event_count += len(times)


def _event_row(event: Event) -> EventRow:
    return EventRow(
        event_id=event.event_id,
        timestamp=event.timestamp,
        host_id=event.host_id,
        event_type=event.event_type.value,
        severity=event.severity.value,
        source=event.source,
        source_ip=str(event.source_ip) if event.source_ip is not None else None,
        username=event.username,
        message=event.message,
        event_metadata=event.metadata,
    )


def _event_from_row(row: EventRow) -> Event:
    return Event(
        event_id=row.event_id,
        timestamp=_utc(row.timestamp),
        host_id=row.host_id,
        event_type=EventType(row.event_type),
        severity=Severity(row.severity),
        source=row.source,
        source_ip=ip_address(row.source_ip) if row.source_ip else None,
        username=row.username,
        message=row.message,
        metadata=dict(row.event_metadata),
    )


def _apply_incident(row: IncidentRow, incident: Incident) -> None:
    row.title = incident.title
    row.description = incident.description
    row.severity = incident.severity.value
    row.risk_score = incident.risk_score
    row.host_id = incident.host_id
    row.source_ip = incident.source_ip
    row.usernames = list(incident.usernames)
    row.first_seen = incident.first_seen
    row.last_seen = incident.last_seen
    row.rules = list(incident.rules)
    row.event_count = incident.event_count
    row.related_event_ids = list(incident.related_event_ids)
    row.recommended_actions = list(incident.recommended_actions)
    row.status = incident.status.value


def _incident_from_row(row: IncidentRow) -> Incident:
    return Incident(
        incident_id=row.incident_id,
        title=row.title,
        description=row.description,
        severity=Severity(row.severity),
        risk_score=row.risk_score,
        host_id=row.host_id,
        source_ip=row.source_ip,
        usernames=list(row.usernames),
        first_seen=_utc(row.first_seen),
        last_seen=_utc(row.last_seen),
        rules=list(row.rules),
        event_count=row.event_count,
        related_event_ids=list(row.related_event_ids),
        recommended_actions=list(row.recommended_actions),
        status=IncidentStatus(row.status),
    )
