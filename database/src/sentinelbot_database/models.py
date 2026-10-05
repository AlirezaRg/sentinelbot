"""SQLAlchemy 2.x models. Enum-like fields are stored as strings so migrations stay simple.

Indexes cover the query paths the API uses: time, event type, severity, host, source IP and
incident status.
"""

from __future__ import annotations

import uuid
from datetime import datetime
from typing import Any

from sqlalchemy import JSON, Boolean, DateTime, ForeignKey, Index, Integer, String, Text, Uuid
from sqlalchemy.orm import DeclarativeBase, Mapped, mapped_column


class Base(DeclarativeBase):
    pass


class HostRow(Base):
    __tablename__ = "hosts"

    host_id: Mapped[str] = mapped_column(String(255), primary_key=True)
    first_seen: Mapped[datetime] = mapped_column(DateTime(timezone=True))
    last_seen: Mapped[datetime] = mapped_column(DateTime(timezone=True), index=True)
    event_count: Mapped[int] = mapped_column(Integer, default=0)


class EventRow(Base):
    __tablename__ = "events"

    event_id: Mapped[uuid.UUID] = mapped_column(Uuid, primary_key=True)
    timestamp: Mapped[datetime] = mapped_column(DateTime(timezone=True), index=True)
    host_id: Mapped[str] = mapped_column(String(255), index=True)
    event_type: Mapped[str] = mapped_column(String(64), index=True)
    severity: Mapped[str] = mapped_column(String(16), index=True)
    source: Mapped[str] = mapped_column(String(64))
    source_ip: Mapped[str | None] = mapped_column(String(45), index=True, nullable=True)
    username: Mapped[str | None] = mapped_column(String(255), nullable=True)
    message: Mapped[str] = mapped_column(Text)
    # Attribute is named event_metadata because "metadata" is reserved by SQLAlchemy.
    event_metadata: Mapped[dict[str, Any]] = mapped_column("metadata", JSON, default=dict)

    __table_args__ = (Index("ix_events_host_timestamp", "host_id", "timestamp"),)


class IncidentRow(Base):
    __tablename__ = "incidents"

    incident_id: Mapped[str] = mapped_column(String(64), primary_key=True)
    title: Mapped[str] = mapped_column(String(255))
    description: Mapped[str] = mapped_column(Text)
    severity: Mapped[str] = mapped_column(String(16), index=True)
    risk_score: Mapped[int] = mapped_column(Integer, index=True)
    host_id: Mapped[str] = mapped_column(String(255), index=True)
    source_ip: Mapped[str | None] = mapped_column(String(45), index=True, nullable=True)
    usernames: Mapped[list[str]] = mapped_column(JSON, default=list)
    first_seen: Mapped[datetime] = mapped_column(DateTime(timezone=True))
    last_seen: Mapped[datetime] = mapped_column(DateTime(timezone=True), index=True)
    rules: Mapped[list[str]] = mapped_column(JSON, default=list)
    event_count: Mapped[int] = mapped_column(Integer, default=0)
    related_event_ids: Mapped[list[str]] = mapped_column(JSON, default=list)
    recommended_actions: Mapped[list[str]] = mapped_column(JSON, default=list)
    status: Mapped[str] = mapped_column(String(16), index=True)


class DetectionRuleRow(Base):
    __tablename__ = "detection_rules"

    rule_id: Mapped[str] = mapped_column(String(64), primary_key=True)
    enabled: Mapped[bool] = mapped_column(Boolean, default=True)
    settings: Mapped[dict[str, Any]] = mapped_column(JSON, default=dict)
    updated_at: Mapped[datetime] = mapped_column(DateTime(timezone=True))


class UserRow(Base):
    """A dashboard user. Passwords are stored only as scrypt hashes."""

    __tablename__ = "users"

    username: Mapped[str] = mapped_column(String(64), primary_key=True)
    password_hash: Mapped[str] = mapped_column(String(255))
    role: Mapped[str] = mapped_column(String(16))
    disabled: Mapped[bool] = mapped_column(Boolean, default=False)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True))


class AlertRow(Base):
    """Delivery record for an alert. Filled by the alerting module (Phase 11)."""

    __tablename__ = "alerts"

    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    incident_id: Mapped[str] = mapped_column(
        String(64), ForeignKey("incidents.incident_id"), index=True
    )
    channel: Mapped[str] = mapped_column(String(32))
    status: Mapped[str] = mapped_column(String(16))
    detail: Mapped[str | None] = mapped_column(Text, nullable=True)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True))
