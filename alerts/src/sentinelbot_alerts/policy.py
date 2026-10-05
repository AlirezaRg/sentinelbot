"""Which incidents deserve a notification, and how often.

An incident alerts when it is new and at least ``min_severity``. After that it stays quiet for
``cooldown_seconds`` of event time, unless its severity went up, which always alerts. Times come
from the incident's ``last_seen``, so replayed data behaves the same as live data.

State is per process. With several API processes each one alerts once; Redis-backed state can
replace this later.
"""

from __future__ import annotations

from datetime import datetime, timedelta

from sentinelbot_agent.models import Severity
from sentinelbot_detection.correlation import Incident

_RANK: dict[Severity, int] = {
    Severity.INFO: 0,
    Severity.LOW: 1,
    Severity.MEDIUM: 2,
    Severity.HIGH: 3,
    Severity.CRITICAL: 4,
}


class AlertPolicy:
    def __init__(self, min_severity: Severity, cooldown_seconds: int) -> None:
        if cooldown_seconds < 0:
            raise ValueError("cooldown_seconds must not be negative")
        self._min = min_severity
        self._cooldown = timedelta(seconds=cooldown_seconds)
        self._last_alert: dict[str, tuple[Severity, datetime]] = {}

    def should_alert(self, incident: Incident) -> bool:
        if _RANK[incident.severity] < _RANK[self._min]:
            return False
        previous = self._last_alert.get(incident.incident_id)
        if previous is None:
            return self._record(incident)
        last_severity, last_time = previous
        escalated = _RANK[incident.severity] > _RANK[last_severity]
        quiet_long_enough = incident.last_seen - last_time >= self._cooldown
        if escalated or quiet_long_enough:
            return self._record(incident)
        return False

    def _record(self, incident: Incident) -> bool:
        self._last_alert[incident.incident_id] = (incident.severity, incident.last_seen)
        return True
