"""Glue between incidents, the policy and the channels."""

from __future__ import annotations

import logging
from collections.abc import Callable, Iterable, Sequence

from sentinelbot_detection.correlation import Incident

from sentinelbot_alerts.channels import AlertChannel
from sentinelbot_alerts.message import format_alert
from sentinelbot_alerts.policy import AlertPolicy

logger = logging.getLogger(__name__)

ResultCallback = Callable[[str, str], None]


class Notifier:
    """Sends an alert for each incident the policy approves, on every channel.

    A failing channel is logged and reported through ``on_result`` with status ``failed``. It
    never raises into the caller, so a dead mail server cannot stop event ingestion.
    """

    def __init__(
        self,
        policy: AlertPolicy,
        channels: Sequence[AlertChannel],
        on_result: ResultCallback | None = None,
    ) -> None:
        self._policy = policy
        self._channels = list(channels)
        self._on_result = on_result

    def notify(self, incidents: Iterable[Incident]) -> None:
        for incident in incidents:
            if not self._policy.should_alert(incident):
                continue
            subject, body = format_alert(incident)
            for channel in self._channels:
                status = self._deliver(channel, subject, body, incident.incident_id)
                if self._on_result is not None:
                    self._on_result(channel.name, status)

    @staticmethod
    def _deliver(channel: AlertChannel, subject: str, body: str, incident_id: str) -> str:
        try:
            channel.send(subject, body)
        except Exception:  # isolation boundary: a channel failure must not stop ingestion
            logger.exception(
                "alert delivery failed", extra={"channel": channel.name, "incident_id": incident_id}
            )
            return "failed"
        return "sent"
