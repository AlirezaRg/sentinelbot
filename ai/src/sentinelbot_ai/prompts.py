"""Prompts. The model sees only the structured incident fields listed below, never raw logs."""

from __future__ import annotations

import json

from sentinelbot_detection.correlation import Incident

SYSTEM_PROMPT = """You are a defensive security analyst assisting a human SOC analyst.

Rules you must follow:
- You only analyse the structured incident given to you. You cannot run commands, change the
  host, or contact anything.
- Base every statement on the input. If the input does not show something, say it is unknown.
- Never claim certainty. Use "possible", "likely" or "unclear" where the evidence is limited.
- Always list plausible benign explanations (false positives), such as an authorised scanner,
  a monitoring tool, or a user who mistyped a password.
- Give investigation steps and conservative remediation only. Never suggest destructive actions.
- Set confidence between 0 and 1 and explain it in confidence_note.

Respond with one JSON object and nothing else, with exactly these keys:
summary (string), why_suspicious (list of strings), severity_assessment (string),
evidence (list of strings), false_positive_explanations (list of strings),
investigation_steps (list of strings), remediation (list of strings),
confidence (number from 0 to 1), confidence_note (string)."""


def build_user_prompt(incident: Incident) -> str:
    """Only fields needed for the analysis. Ids and raw event text are left out."""
    facts = {
        "title": incident.title,
        "description": incident.description,
        "severity": incident.severity.value,
        "risk_score": incident.risk_score,
        "host": incident.host_id,
        "source_ip": incident.source_ip,
        "usernames": incident.usernames,
        "rules_triggered": incident.rules,
        "detection_count": incident.event_count,
        "first_seen": incident.first_seen.isoformat(),
        "last_seen": incident.last_seen.isoformat(),
        "status": incident.status.value,
    }
    return "Incident to analyse (JSON):\n" + json.dumps(facts, indent=2, ensure_ascii=False)
