"""The analyst: asks a model (if configured), validates the answer, and falls back to rules.

Rules enforced here, whatever the model says:
- the reply must be one JSON object that validates against ``AnalysisDraft``;
- confidence is capped by the amount of evidence (a few detections cannot be "certain");
- any failure falls back to the offline analysis and records why.
"""

from __future__ import annotations

import json
import logging

from pydantic import ValidationError
from sentinelbot_detection.correlation import Incident

from sentinelbot_ai.prompts import SYSTEM_PROMPT, build_user_prompt
from sentinelbot_ai.providers import LLMProvider
from sentinelbot_ai.rules import build_rule_analysis
from sentinelbot_ai.schemas import AnalysisDraft, AnalysisResult

logger = logging.getLogger(__name__)

LOW_EVIDENCE_CONFIDENCE_CAP = 0.5
LOW_EVIDENCE_EVENT_THRESHOLD = 3


class Analyst:
    def __init__(self, provider: LLMProvider | None = None) -> None:
        self._provider = provider

    def analyze(self, incident: Incident) -> AnalysisResult:
        if self._provider is None:
            return _result(build_rule_analysis(incident), "rules", None)
        try:
            raw = self._provider.complete(SYSTEM_PROMPT, build_user_prompt(incident))
            draft = parse_draft(raw)
        except (ValidationError, ValueError) as exc:
            logger.warning("model reply rejected, using rules", extra={"error": type(exc).__name__})
            return _result(build_rule_analysis(incident), "rules", "model reply failed validation")
        except Exception as exc:  # isolation boundary: an API outage must not break the endpoint
            logger.warning("model unavailable, using rules", extra={"error": type(exc).__name__})
            return _result(build_rule_analysis(incident), "rules", "model unavailable")
        return _result(_cap_confidence(draft, incident), "anthropic", None)


def parse_draft(raw: str) -> AnalysisDraft:
    """Extract the single JSON object from a reply and validate it."""
    start, end = raw.find("{"), raw.rfind("}")
    if start == -1 or end <= start:
        raise ValueError("no JSON object in reply")
    data = json.loads(raw[start : end + 1])
    return AnalysisDraft.model_validate(data)


def _cap_confidence(draft: AnalysisDraft, incident: Incident) -> AnalysisDraft:
    if incident.event_count >= LOW_EVIDENCE_EVENT_THRESHOLD:
        return draft
    capped = min(draft.confidence, LOW_EVIDENCE_CONFIDENCE_CAP)
    if capped == draft.confidence:
        return draft
    note = (
        f"{draft.confidence_note} Confidence limited to {capped:.1f}: only "
        f"{incident.event_count} detection(s) so far."
    )
    return draft.model_copy(update={"confidence": capped, "confidence_note": note})


def _result(draft: AnalysisDraft, provider: str, fallback: str | None) -> AnalysisResult:
    fields = draft.model_dump()
    return AnalysisResult(**fields, provider=provider, fallback_reason=fallback)  # type: ignore[arg-type]
