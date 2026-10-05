"""HTTP routes under ``/api/v1``. Every route requires the API key."""

from __future__ import annotations

import logging
from datetime import datetime
from ipaddress import ip_address
from typing import Annotated, Literal
from uuid import UUID

from fastapi import APIRouter, Body, Depends, HTTPException, Query, status
from sentinelbot_agent.models import Event, EventType, Severity
from sentinelbot_ai.schemas import AnalysisResult
from sentinelbot_detection.correlation import Incident, IncidentStatus

from sentinelbot_backend import __version__
from sentinelbot_backend.container import Container
from sentinelbot_backend.repository import DuplicateEventError
from sentinelbot_backend.schemas import (
    HostOut,
    IngestResult,
    MetricsOut,
    Page,
    ResolveRequest,
    SystemStatusOut,
)
from sentinelbot_backend.security import get_container, require_analyst, require_viewer

logger = logging.getLogger("sentinelbot_backend.api")

MAX_BATCH = 500
MAX_PAGE = 500
UNPROCESSABLE = 422  # plain int: Starlette deprecated the named constant in newer releases

router = APIRouter(prefix="/api/v1", dependencies=[Depends(require_viewer)])

Limit = Annotated[int, Query(ge=1, le=MAX_PAGE)]
Offset = Annotated[int, Query(ge=0)]
Order = Literal["asc", "desc"]


def _parse_ip(raw: str | None) -> str | None:
    if raw is None:
        return None
    try:
        return str(ip_address(raw))
    except ValueError as exc:
        raise HTTPException(UNPROCESSABLE, "source_ip is not an IP address") from exc


@router.get("/hosts", response_model=Page[HostOut])
def list_hosts(
    limit: Limit = 50,
    offset: Offset = 0,
    container: Container = Depends(get_container),
) -> Page[HostOut]:
    with container.lock:
        summaries = sorted(container.events.hosts(), key=lambda h: h.last_seen, reverse=True)
        page = summaries[offset : offset + limit]
        items = [
            HostOut(
                host_id=h.host_id,
                first_seen=h.first_seen,
                last_seen=h.last_seen,
                event_count=h.event_count,
                open_incidents=container.incidents.open_for_host(h.host_id),
            )
            for h in page
        ]
    return Page(items=items, total=len(summaries), limit=limit, offset=offset)


@router.get("/events", response_model=Page[Event])
def list_events(
    event_type: EventType | None = None,
    severity: Severity | None = None,
    host_id: Annotated[str | None, Query(max_length=255)] = None,
    source_ip: Annotated[str | None, Query(max_length=45)] = None,
    since: datetime | None = None,
    until: datetime | None = None,
    order: Order = "desc",
    limit: Limit = 50,
    offset: Offset = 0,
    container: Container = Depends(get_container),
) -> Page[Event]:
    if since is not None and until is not None and since > until:
        raise HTTPException(UNPROCESSABLE, "since must not be after until")
    ip = _parse_ip(source_ip)
    with container.lock:
        items, total = container.events.query(
            event_type=event_type,
            severity=severity,
            host_id=host_id,
            source_ip=ip_address(ip) if ip else None,
            since=since,
            until=until,
            descending=order == "desc",
            offset=offset,
            limit=limit,
        )
    return Page(items=items, total=total, limit=limit, offset=offset)


@router.get("/events/{event_id}", response_model=Event)
def get_event(event_id: UUID, container: Container = Depends(get_container)) -> Event:
    with container.lock:
        event = container.events.get(event_id)
    if event is None:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "event not found")
    return event


@router.post(
    "/events",
    response_model=IngestResult,
    status_code=status.HTTP_201_CREATED,
    dependencies=[Depends(require_analyst)],
)
def ingest_events(
    batch: Annotated[list[Event], Body(min_length=1, max_length=MAX_BATCH)],
    container: Container = Depends(get_container),
) -> IngestResult:
    with container.lock:
        try:
            touched = container.ingest(batch)
        except DuplicateEventError as exc:
            raise HTTPException(
                status.HTTP_409_CONFLICT,
                {"message": "duplicate event_id", "event_ids": exc.event_ids},
            ) from exc
    logger.info("events ingested", extra={"accepted": len(batch), "incidents_touched": touched})
    return IngestResult(accepted=len(batch), incidents_touched=touched)


@router.get("/incidents", response_model=Page[Incident])
def list_incidents(
    status_filter: Annotated[IncidentStatus | None, Query(alias="status")] = None,
    severity: Severity | None = None,
    host_id: Annotated[str | None, Query(max_length=255)] = None,
    sort: Literal["last_seen", "risk_score", "event_count"] = "last_seen",
    order: Order = "desc",
    limit: Limit = 50,
    offset: Offset = 0,
    container: Container = Depends(get_container),
) -> Page[Incident]:
    with container.lock:
        items, total = container.incidents.query(
            status=status_filter,
            severity=severity,
            host_id=host_id,
            sort_by=sort,
            descending=order == "desc",
            offset=offset,
            limit=limit,
        )
    return Page(items=items, total=total, limit=limit, offset=offset)


@router.get("/incidents/{incident_id}", response_model=Incident)
def get_incident(incident_id: str, container: Container = Depends(get_container)) -> Incident:
    with container.lock:
        incident = container.incidents.get(incident_id)
    if incident is None:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "incident not found")
    return incident


@router.get("/incidents/{incident_id}/analysis", response_model=AnalysisResult)
def analyze_incident(
    incident_id: str, container: Container = Depends(get_container)
) -> AnalysisResult:
    """Explain an incident. Computed on request; the result is not stored."""
    with container.lock:
        incident = container.incidents.get(incident_id)
    if incident is None:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "incident not found")
    return container.analyst.analyze(incident)


@router.post(
    "/incidents/{incident_id}/resolve",
    response_model=Incident,
    dependencies=[Depends(require_analyst)],
)
def resolve_incident(
    incident_id: str,
    body: Annotated[ResolveRequest | None, Body()] = None,
    container: Container = Depends(get_container),
) -> Incident:
    request = body or ResolveRequest()
    with container.lock:
        if container.incidents.get(incident_id) is None:
            raise HTTPException(status.HTTP_404_NOT_FOUND, "incident not found")
        incident = container.incidents.set_status(incident_id, IncidentStatus(request.resolution))
    logger.info(
        "incident status changed",
        extra={"incident_id": incident_id, "status": incident.status.value, "note": request.note},
    )
    return incident


@router.get("/metrics", response_model=MetricsOut)
def metrics(container: Container = Depends(get_container)) -> MetricsOut:
    with container.lock:
        return MetricsOut(
            events_stored=len(container.events),
            events_by_severity=container.events.counts_by_severity(),
            events_by_type=container.events.counts_by_type(),
            incidents_total=container.incidents.total(),
            incidents_by_status=container.incidents.counts_by_status(),
        )


@router.get("/system/status", response_model=SystemStatusOut)
def system_status(container: Container = Depends(get_container)) -> SystemStatusOut:
    now = datetime.now(container.started_at.tzinfo)
    with container.lock:
        events_stored = len(container.events)
        incidents_stored = container.incidents.total()
    return SystemStatusOut(
        status="ok",
        version=__version__,
        started_at=container.started_at,
        uptime_seconds=round((now - container.started_at).total_seconds(), 1),
        events_stored=events_stored,
        event_capacity=container.settings.event_capacity,
        incidents_stored=incidents_stored,
        persistence=container.backend,
        api_key_configured=container.settings.api_key is not None,
    )
