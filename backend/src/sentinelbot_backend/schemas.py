"""Request and response models for the API. Event and Incident are reused from their packages."""

from __future__ import annotations

from datetime import datetime
from typing import Generic, Literal, TypeVar

from pydantic import BaseModel, ConfigDict, Field

T = TypeVar("T")


class Page(BaseModel, Generic[T]):  # noqa: UP046 - Generic keeps Page[T] working on Pydantic 2.5
    items: list[T]
    total: int
    limit: int
    offset: int


class HostOut(BaseModel):
    host_id: str
    first_seen: datetime
    last_seen: datetime
    event_count: int
    open_incidents: int


class MetricsOut(BaseModel):
    events_stored: int
    events_by_severity: dict[str, int]
    events_by_type: dict[str, int]
    incidents_total: int
    incidents_by_status: dict[str, int]


class SystemStatusOut(BaseModel):
    status: Literal["ok"]
    version: str
    started_at: datetime
    uptime_seconds: float
    events_stored: int
    event_capacity: int
    incidents_stored: int
    persistence: Literal["memory", "file", "postgresql"]
    api_key_configured: bool


class IngestResult(BaseModel):
    accepted: int
    incidents_touched: int


class ResolveRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")

    resolution: Literal["RESOLVED", "FALSE_POSITIVE"] = "RESOLVED"
    note: str | None = Field(default=None, max_length=500)
