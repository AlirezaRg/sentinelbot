"""Detection engine: routes each telemetry event to the rules that subscribe to its type."""

from __future__ import annotations

import logging
from collections.abc import Sequence

from sentinelbot_agent.models import Event

from sentinelbot_detection.rules import Rule

logger = logging.getLogger(__name__)


class DetectionEngine:
    """Runs rules over a stream of events. Detection events are never fed back in.

    Rules only subscribe to telemetry types, so detections cannot trigger further
    detections. A failing rule is logged and skipped, and the other rules still run.
    """

    def __init__(self, rules: Sequence[Rule]) -> None:
        self._rules = list(rules)

    def process(self, event: Event) -> list[Event]:
        detections: list[Event] = []
        for rule in self._rules:
            if event.event_type not in rule.event_types:
                continue
            try:
                detections.extend(rule.evaluate(event))
            except Exception:  # isolation boundary: one bad rule must not stop detection
                logger.exception("rule failed", extra={"rule": rule.rule_id})
        return detections
