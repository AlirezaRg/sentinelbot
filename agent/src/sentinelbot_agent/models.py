"""Normalized event schema shared by every SentinelBot component."""

from __future__ import annotations

from datetime import UTC, datetime
from enum import StrEnum
from typing import Any
from uuid import UUID, uuid4

from pydantic import BaseModel, ConfigDict, Field, IPvAnyAddress, field_validator


class Severity(StrEnum):
    """Severity levels, ordered from least to most severe."""

    INFO = "info"
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"


class EventType(StrEnum):
    """Event types emitted by the agent (telemetry) and the detection engine (``*_detected``).

    Docker event types are added in a later phase.
    """

    SYSTEM_INFO = "system_info"
    SYSTEM_METRICS = "system_metrics"
    PROCESS_SNAPSHOT = "process_snapshot"
    NETWORK_SNAPSHOT = "network_snapshot"
    COLLECTOR_ERROR = "collector_error"
    SSH_LOGIN_FAILED = "ssh_login_failed"
    SSH_LOGIN_SUCCESS = "ssh_login_success"
    SSH_ROOT_LOGIN = "ssh_root_login"
    SUDO_COMMAND = "sudo_command"
    SSH_BRUTEFORCE_DETECTED = "ssh_bruteforce_detected"
    SUSPICIOUS_ROOT_LOGIN_DETECTED = "suspicious_root_login_detected"
    AUTH_BURST_DETECTED = "auth_burst_detected"
    PRIVILEGED_PROCESS_DETECTED = "privileged_process_detected"
    UNEXPECTED_LISTENING_PORT_DETECTED = "unexpected_listening_port_detected"


def utc_now() -> datetime:
    """Return the current time as a timezone-aware UTC datetime."""
    return datetime.now(UTC)


class Event(BaseModel):
    """A single normalized telemetry or security event.

    Serialized with ``model_dump_json`` this becomes one JSON object per line.
    """

    model_config = ConfigDict(frozen=True, extra="forbid")

    event_id: UUID = Field(default_factory=uuid4)
    timestamp: datetime = Field(default_factory=utc_now)
    host_id: str = Field(min_length=1, max_length=255)
    event_type: EventType
    severity: Severity = Severity.INFO
    source: str = Field(min_length=1, max_length=64)
    source_ip: IPvAnyAddress | None = None
    username: str | None = Field(default=None, max_length=255)
    message: str = Field(min_length=1, max_length=2000)
    metadata: dict[str, Any] = Field(default_factory=dict)

    @field_validator("timestamp")
    @classmethod
    def _require_utc(cls, value: datetime) -> datetime:
        """Reject naive timestamps and normalize aware ones to UTC."""
        if value.tzinfo is None:
            raise ValueError("timestamp must be timezone-aware")
        return value.astimezone(UTC)
