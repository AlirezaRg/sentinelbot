"""The analyst: offline rules, validated model replies, fallbacks and the confidence cap."""

from __future__ import annotations

import json
from datetime import UTC, datetime
from typing import Any

import httpx
import pytest
from sentinelbot_agent.models import Severity
from sentinelbot_detection.correlation import Incident, IncidentStatus

from sentinelbot_ai.analyst import Analyst
from sentinelbot_ai.prompts import SYSTEM_PROMPT, build_user_prompt
from sentinelbot_ai.providers import AnthropicProvider
from sentinelbot_ai.rules import build_rule_analysis

T0 = datetime(2026, 10, 4, 12, 0, tzinfo=UTC)


def incident(event_count: int = 6, usernames: list[str] | None = None) -> Incident:
    return Incident(
        incident_id="INC-1",
        title="Possible SSH brute-force activity from 203.0.113.50",
        description=f"{event_count} detection(s).",
        severity=Severity.HIGH,
        risk_score=75,
        host_id="server-01",
        source_ip="203.0.113.50",
        usernames=usernames or ["root"],
        first_seen=T0,
        last_seen=T0,
        rules=["ssh_bruteforce"],
        event_count=event_count,
        recommended_actions=["Review SSH authentication logs for this source address."],
        status=IncidentStatus.OPEN,
    )


def _reply(**overrides: Any) -> str:
    draft: dict[str, Any] = {
        "summary": "Repeated failed SSH logins for root from one address.",
        "why_suspicious": ["Many failures for a privileged account."],
        "severity_assessment": "High, consistent with the rule severity.",
        "evidence": ["6 failed attempts", "Target: root"],
        "false_positive_explanations": ["A mistyped password by an administrator."],
        "investigation_steps": ["Check whether any attempt succeeded."],
        "remediation": ["Block the source if it is not authorised."],
        "confidence": 0.7,
        "confidence_note": "Limited to the logged attempts.",
    }
    draft.update(overrides)
    return "Here is the analysis:\n" + json.dumps(draft) + "\nEnd."


class FakeProvider:
    name = "anthropic"

    def __init__(self, reply: str | Exception) -> None:
        self._reply = reply
        self.calls: list[tuple[str, str]] = []

    def complete(self, system: str, user: str) -> str:
        self.calls.append((system, user))
        if isinstance(self._reply, Exception):
            raise self._reply
        return self._reply


# --- offline rules ------------------------------------------------------------


def test_rule_analysis_uses_only_incident_facts() -> None:
    result = build_rule_analysis(incident())

    assert "ssh_bruteforce" in " ".join(result.evidence)
    assert "203.0.113.50" in " ".join(result.evidence)
    assert result.false_positive_explanations  # benign explanations are always listed
    assert result.investigation_steps == incident().recommended_actions


def test_low_evidence_rule_analysis_has_low_confidence() -> None:
    assert build_rule_analysis(incident(event_count=1)).confidence <= 0.5


def test_no_provider_means_offline_analysis_and_no_network() -> None:
    result = Analyst(None).analyze(incident())

    assert result.provider == "rules"
    assert result.fallback_reason is None


# --- model replies ------------------------------------------------------------


def test_valid_model_reply_is_used() -> None:
    result = Analyst(FakeProvider(_reply())).analyze(incident())

    assert result.provider == "anthropic"
    assert result.summary.startswith("Repeated failed SSH logins")
    assert result.confidence == pytest.approx(0.7)


def test_invalid_json_falls_back_to_rules() -> None:
    result = Analyst(FakeProvider("I cannot help with that.")).analyze(incident())

    assert result.provider == "rules"
    assert result.fallback_reason == "model reply failed validation"


def test_reply_missing_a_required_field_falls_back() -> None:
    reply = _reply()
    broken = json.loads(reply[reply.index("{") : reply.rindex("}") + 1])
    del broken["confidence"]

    result = Analyst(FakeProvider(json.dumps(broken))).analyze(incident())

    assert result.provider == "rules"


def test_reply_with_extra_keys_is_rejected() -> None:
    result = Analyst(FakeProvider(_reply(run_command="rm -rf /"))).analyze(incident())

    assert result.provider == "rules"


def test_model_outage_falls_back_to_rules() -> None:
    result = Analyst(FakeProvider(ConnectionError("network down"))).analyze(incident())

    assert result.provider == "rules"
    assert result.fallback_reason == "model unavailable"


def test_confidence_is_capped_when_evidence_is_thin() -> None:
    result = Analyst(FakeProvider(_reply(confidence=0.95))).analyze(incident(event_count=1))

    assert result.confidence == pytest.approx(0.5)
    assert "limited" in result.confidence_note


def test_confidence_is_not_capped_with_enough_evidence() -> None:
    result = Analyst(FakeProvider(_reply(confidence=0.95))).analyze(incident(event_count=6))

    assert result.confidence == pytest.approx(0.95)


# --- prompt and provider ------------------------------------------------------


def test_prompt_forbids_actions_and_certainty() -> None:
    assert "cannot run commands" in SYSTEM_PROMPT
    assert "Never claim certainty" in SYSTEM_PROMPT


def test_prompt_contains_structured_facts_but_no_event_ids() -> None:
    prompt = build_user_prompt(incident())

    assert '"detection_count": 6' in prompt
    assert "INC-1" not in prompt


def test_anthropic_provider_sends_key_model_and_system_prompt() -> None:
    seen: dict[str, Any] = {}

    def handler(request: httpx.Request) -> httpx.Response:
        seen["headers"] = request.headers
        seen["body"] = json.loads(request.content)
        return httpx.Response(200, json={"content": [{"type": "text", "text": _reply()}]})

    provider = AnthropicProvider(
        "test-key",
        "claude-sonnet-5-5",
        client=httpx.Client(transport=httpx.MockTransport(handler)),
    )

    text = provider.complete(SYSTEM_PROMPT, "question")

    assert seen["headers"]["x-api-key"] == "test-key"
    assert seen["body"]["model"] == "claude-sonnet-5-5"
    assert seen["body"]["system"] == SYSTEM_PROMPT
    assert "summary" in text


def test_anthropic_http_error_propagates_so_the_analyst_can_fall_back() -> None:
    provider = AnthropicProvider(
        "bad",
        "m",
        client=httpx.Client(transport=httpx.MockTransport(lambda r: httpx.Response(401))),
    )

    result = Analyst(provider).analyze(incident())

    assert result.provider == "rules"
    assert result.fallback_reason == "model unavailable"
