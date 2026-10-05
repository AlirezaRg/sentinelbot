"""Shared helpers. All events are synthetic; documentation IP ranges only (RFC 5737)."""

from __future__ import annotations

from datetime import UTC, datetime, timedelta
from ipaddress import ip_address
from typing import Any

from sentinelbot_agent.models import Event, EventType, Severity

T0 = datetime(2026, 10, 4, 12, 0, tzinfo=UTC)


def at(seconds: float) -> datetime:
    """A timestamp ``seconds`` after the shared test origin."""
    return T0 + timedelta(seconds=seconds)


def make_event(
    event_type: EventType,
    *,
    seconds: float = 0,
    source_ip: str | None = None,
    username: str | None = None,
    severity: Severity = Severity.INFO,
    **metadata: Any,
) -> Event:
    return Event(
        host_id="server-01",
        timestamp=at(seconds),
        event_type=event_type,
        severity=severity,
        source="auth",
        message=f"synthetic {event_type.value}",
        source_ip=ip_address(source_ip) if source_ip is not None else None,
        username=username,
        metadata=metadata,
    )


def failed_login(seconds: float, ip: str = "203.0.113.50", user: str = "root") -> Event:
    return make_event(
        EventType.SSH_LOGIN_FAILED,
        seconds=seconds,
        source_ip=ip,
        username=user,
        targets_root=user == "root",
    )


def process_snapshot(seconds: float, *processes: dict[str, Any]) -> Event:
    return make_event(
        EventType.PROCESS_SNAPSHOT,
        seconds=seconds,
        processes=list(processes),
        total_processes=len(processes),
        returned=len(processes),
        truncated=False,
    )


def proc(name: str, *, user: str = "root", exe: str | None = None, pid: int = 1) -> dict[str, Any]:
    return {"pid": pid, "ppid": 1, "name": name, "username": user, "exe": exe}


def network_snapshot(seconds: float, *listening: tuple[str, int, str]) -> Event:
    records = [
        {"protocol": proto, "local_port": port, "process": name, "pid": 100}
        for proto, port, name in listening
    ]
    return make_event(
        EventType.NETWORK_SNAPSHOT,
        seconds=seconds,
        listening_ports=records,
        listening_port_count=len(records),
        connections=[],
        connection_count=0,
        connections_truncated=False,
    )
