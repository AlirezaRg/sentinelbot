"""Alert text. The layout follows the project spec: headline, incident, host, source, risk."""

from __future__ import annotations

from sentinelbot_detection.correlation import Incident


def format_alert(incident: Incident) -> tuple[str, str]:
    """Return ``(subject, body)`` for one incident."""
    severity = incident.severity.value.upper()
    subject = f"[SentinelBot] {severity}: {incident.title}"
    actions = [f"  - {action}" for action in incident.recommended_actions]
    body = "\n".join(
        [
            f"{severity} SECURITY ALERT",
            "",
            "Incident:",
            f"  {incident.title}",
            "",
            "Host:",
            f"  {incident.host_id}",
            "",
            "Source:",
            f"  {incident.source_ip or 'n/a'}",
            "",
            "Detections:",
            f"  {incident.event_count}",
            "",
            "Risk:",
            f"  {incident.risk_score}/100",
            "",
            "Severity:",
            f"  {severity}",
            "",
            "Recommended action:",
            *actions,
            "",
            f"Incident ID: {incident.incident_id}",
            f"Status: {incident.status.value}",
        ]
    )
    return subject, body
