"""Offline analysis built from the incident's own facts. No model, no network.

It is the default, and it is the fallback whenever a model is missing or returns something that
does not validate. It states only what the data shows.
"""

from __future__ import annotations

from sentinelbot_detection.correlation import Incident

from sentinelbot_ai.schemas import AnalysisDraft

_FALSE_POSITIVES = [
    "An authorised administrator, scanner or monitoring tool may have produced these events.",
    "A user may have mistyped a password, which is common and not an attack by itself.",
]


def build_rule_analysis(incident: Incident) -> AnalysisDraft:
    source = incident.source_ip or "an unknown source"
    rules = ", ".join(sorted(incident.rules)) or "none"
    evidence = [
        f"{incident.event_count} detection(s) between {incident.first_seen:%Y-%m-%d %H:%M} "
        f"and {incident.last_seen:%Y-%m-%d %H:%M} UTC.",
        f"Rules that fired: {rules}.",
        f"Risk score {incident.risk_score}/100 and severity {incident.severity.value}.",
    ]
    if incident.usernames:
        evidence.append(f"Accounts named in the detections: {', '.join(incident.usernames)}.")
    if incident.source_ip:
        evidence.append(f"Source address: {incident.source_ip}.")

    confidence, note = _confidence(incident)
    return AnalysisDraft(
        summary=f"{incident.title}. {incident.description}",
        why_suspicious=[
            f"The rules {rules} fired for {source}.",
            "Repeated or unexpected authentication or network activity can indicate an attack, "
            "but the data alone does not confirm one.",
        ],
        severity_assessment=(
            f"Rated {incident.severity.value} by the highest rule severity and a risk score of "
            f"{incident.risk_score}/100."
        ),
        evidence=evidence,
        false_positive_explanations=list(_FALSE_POSITIVES),
        investigation_steps=list(incident.recommended_actions),
        remediation=[
            "Confirm whether the activity was expected before changing anything.",
            "If it was not, block the source at the firewall and review the targeted accounts.",
        ],
        confidence=confidence,
        confidence_note=note,
    )


def _confidence(incident: Incident) -> tuple[float, str]:
    if incident.event_count >= 5:
        return 0.6, "Several detections support this, but they still need human confirmation."
    return 0.4, "Few detections so far; the evidence is limited."
