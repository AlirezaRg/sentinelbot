"""Correlation: groups scored detections into incidents.

Detections are grouped by ``(host, source IP)``. A detection with no source IP (for example a
new root process) groups by host alone. A detection joins the open incident for its group when
it arrives within ``gap_seconds`` of that incident's last activity. Otherwise it starts a new
incident. Incidents stay OPEN until an analyst changes their status; a RESOLVED or
FALSE_POSITIVE incident is never reused, so a later attack gets its own incident.
"""

from __future__ import annotations

import json
import os
import uuid
from dataclasses import dataclass
from datetime import datetime, timedelta
from enum import StrEnum
from pathlib import Path
from typing import Any

from pydantic import BaseModel, ConfigDict, Field
from sentinelbot_agent.models import Event, Severity

MAX_RELATED_EVENTS = 200
MAX_USERNAMES = 50
ACTIVE_STATUSES = frozenset({"OPEN", "INVESTIGATING"})

# Highest-priority rule decides the title. Order is also the order of recommended actions.
RULE_PRIORITY = (
    "ssh_bruteforce",
    "root_login",
    "auth_burst",
    "privileged_process",
    "unexpected_port",
)

RULE_TITLES: dict[str, str] = {
    "ssh_bruteforce": "Possible SSH brute-force activity",
    "root_login": "Direct root SSH login",
    "auth_burst": "Authentication burst",
    "privileged_process": "New root-owned process",
    "unexpected_port": "Unexpected listening port",
}

RULE_ACTIONS: dict[str, tuple[str, ...]] = {
    "ssh_bruteforce": (
        "Review SSH authentication logs for this source address.",
        "Verify whether the source address is authorized to reach this host.",
        "Check whether any attempt from this source succeeded.",
        "After confirmation, consider blocking the source at the firewall.",
    ),
    "root_login": (
        "Verify that the direct root login was expected.",
        "Review the commands run in that session.",
        "Consider disabling direct root SSH login (PermitRootLogin no).",
    ),
    "auth_burst": ("Review the authentication activity on this host for the same period.",),
    "privileged_process": (
        "Identify the executable and its parent process.",
        "Confirm that the process belongs to a known, authorized service.",
    ),
    "unexpected_port": (
        "Identify the process that owns the port and confirm it is authorized.",
        "Add the port to the allowlist only if it is expected.",
    ),
}


class IncidentStatus(StrEnum):
    OPEN = "OPEN"
    INVESTIGATING = "INVESTIGATING"
    RESOLVED = "RESOLVED"
    FALSE_POSITIVE = "FALSE_POSITIVE"


class Incident(BaseModel):
    """A group of related detections, with enough context to act on it."""

    model_config = ConfigDict(extra="forbid")

    incident_id: str
    title: str
    description: str
    severity: Severity = Severity.INFO
    risk_score: int = Field(default=0, ge=0, le=100)
    host_id: str
    source_ip: str | None = None
    usernames: list[str] = Field(default_factory=list)
    first_seen: datetime
    last_seen: datetime
    rules: list[str] = Field(default_factory=list)
    event_count: int = 0
    related_event_ids: list[str] = Field(default_factory=list)
    recommended_actions: list[str] = Field(default_factory=list)
    status: IncidentStatus = IncidentStatus.OPEN


class IncidentStoreError(ValueError):
    """The incident store file cannot be read safely."""


class IncidentStore:
    """Incidents persisted as one JSON file, or kept only in memory when ``path`` is None.

    Phase 7 replaces the file with PostgreSQL.
    """

    def __init__(self, path: Path | None) -> None:
        self._path = path
        self.incidents: dict[str, Incident] = {}

    @property
    def persistent(self) -> bool:
        return self._path is not None

    def load(self) -> None:
        if self._path is None or not self._path.exists():
            return
        try:
            data: dict[str, Any] = json.loads(self._path.read_text(encoding="utf-8"))
            self.incidents = {
                item["incident_id"]: Incident.model_validate(item) for item in data["incidents"]
            }
        except (OSError, ValueError, KeyError, TypeError) as exc:
            raise IncidentStoreError(
                f"incident store {self._path} is unreadable or corrupt: {exc}"
            ) from exc

    def save(self) -> None:
        if self._path is None:
            return
        payload = {"incidents": [i.model_dump(mode="json") for i in self.incidents.values()]}
        self._path.parent.mkdir(parents=True, exist_ok=True)
        temporary = self._path.with_name(self._path.name + ".tmp")
        temporary.write_text(json.dumps(payload, indent=2), encoding="utf-8")
        os.replace(temporary, self._path)

    def set_status(self, incident_id: str, status: IncidentStatus) -> Incident:
        incident = self.incidents.get(incident_id)
        if incident is None:
            raise KeyError(incident_id)
        incident.status = status
        return incident


@dataclass(frozen=True, slots=True)
class CorrelationSettings:
    gap_seconds: int = 1800

    def __post_init__(self) -> None:
        if self.gap_seconds <= 0:
            raise ValueError("gap_seconds must be greater than 0")


class Correlator:
    """Assigns each detection to an incident. Call ``store.save()`` when the run finishes."""

    def __init__(self, store: IncidentStore, settings: CorrelationSettings) -> None:
        self._store = store
        self._gap = timedelta(seconds=settings.gap_seconds)

    def ingest(self, detection: Event) -> Incident:
        source = str(detection.source_ip) if detection.source_ip is not None else None
        rule_id = str(detection.metadata.get("rule_id", "unknown"))
        incident = self._find_active(detection.host_id, source, detection.timestamp)
        if incident is None:
            incident = self._new_incident(detection, source)

        incident.event_count += 1
        incident.related_event_ids = (incident.related_event_ids + [str(detection.event_id)])[
            -MAX_RELATED_EVENTS:
        ]
        incident.first_seen = min(incident.first_seen, detection.timestamp)
        incident.last_seen = max(incident.last_seen, detection.timestamp)
        if rule_id not in incident.rules:
            incident.rules.append(rule_id)
        users = [detection.username, *detection.metadata.get("targeted_users", [])]
        for user in users:
            if user and user not in incident.usernames and len(incident.usernames) < MAX_USERNAMES:
                incident.usernames.append(user)
        incident.severity = max(incident.severity, detection.severity, key=_rank)
        incident.risk_score = max(incident.risk_score, int(detection.metadata.get("risk_score", 0)))
        _refresh_text(incident)
        return incident

    def _find_active(self, host: str, source: str | None, when: datetime) -> Incident | None:
        candidates = [
            incident
            for incident in self._store.incidents.values()
            if incident.host_id == host
            and incident.source_ip == source
            and incident.status.value in ACTIVE_STATUSES
            and abs(when - incident.last_seen) <= self._gap
        ]
        return max(candidates, key=lambda i: i.last_seen, default=None)

    def _new_incident(self, detection: Event, source: str | None) -> Incident:
        incident = Incident(
            incident_id=f"INC-{uuid.uuid4().hex[:12]}",
            title="",
            description="",
            host_id=detection.host_id,
            source_ip=source,
            first_seen=detection.timestamp,
            last_seen=detection.timestamp,
        )
        self._store.incidents[incident.incident_id] = incident
        return incident


def _rank(severity: Severity) -> int:
    return list(Severity).index(severity)


def _refresh_text(incident: Incident) -> None:
    """Rebuild title, description and actions from the rules seen so far."""
    seen = set(incident.rules)
    primary = next((rule for rule in RULE_PRIORITY if rule in seen), None)
    base_title = RULE_TITLES.get(primary or "", "Suspicious host activity")
    where = f"from {incident.source_ip}" if incident.source_ip else f"on {incident.host_id}"
    incident.title = f"{base_title} {where}"

    window = (
        f"{incident.first_seen:%Y-%m-%d %H:%M:%S} to {incident.last_seen:%Y-%m-%d %H:%M:%S} UTC"
    )
    rules = ", ".join(sorted(seen))
    incident.description = f"{incident.event_count} detection(s) between {window}. Rules: {rules}."

    actions: list[str] = []
    for rule in RULE_PRIORITY:
        if rule in seen:
            actions.extend(a for a in RULE_ACTIONS[rule] if a not in actions)
    incident.recommended_actions = actions
