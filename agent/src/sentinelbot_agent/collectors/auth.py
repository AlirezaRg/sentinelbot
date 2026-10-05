"""Auth collector: turns new sshd and sudo log lines into authentication events."""

from __future__ import annotations

import logging
from collections.abc import Sequence

from sentinelbot_agent.auth.parsers import parse_auth_message
from sentinelbot_agent.auth.sources import (
    FileSource,
    JournalSource,
    LogSource,
    SourceError,
    journalctl_available,
)
from sentinelbot_agent.auth.state import StateStore
from sentinelbot_agent.collectors.base import Collector
from sentinelbot_agent.config import AgentConfig
from sentinelbot_agent.models import Event, EventType, Severity

logger = logging.getLogger(__name__)


def discover_sources(config: AgentConfig) -> list[LogSource]:
    """Prefer the systemd journal; fall back to whichever auth log files exist."""
    if journalctl_available():
        return [JournalSource(bootstrap_lines=config.journal_bootstrap_lines)]
    return [FileSource(path) for path in config.auth_log_paths if path.is_file()]


class AuthCollector(Collector):
    """Emits ``ssh_*`` and ``sudo_command`` events from newly written log lines.

    A source that fails produces one ``collector_error`` event and the other sources
    still run. Resume state is saved after each cycle, so a restart continues where it
    stopped. Events are emitted by the agent after ``collect`` returns, so a crash in
    between can lose that cycle's events (at-most-once delivery).
    """

    name = "auth"

    def __init__(
        self,
        config: AgentConfig,
        sources: Sequence[LogSource] | None = None,
        store: StateStore | None = None,
    ) -> None:
        super().__init__(config)
        self._sources = list(sources) if sources is not None else discover_sources(config)
        self._store = store or StateStore(config.state_path)

    def collect(self) -> list[Event]:
        if not self._sources:
            logger.info("no auth log source available on this host")
            return []

        state = self._store.load()
        events: list[Event] = []
        for source in self._sources:
            try:
                lines, state[source.key] = source.read_new(state.get(source.key, {}))
            except SourceError as exc:
                logger.warning(
                    "auth source unavailable", extra={"source": source.key, "error": str(exc)}
                )
                events.append(self._source_error(source.key, str(exc)))
                continue

            for line in lines:
                record = parse_auth_message(line.program, line.message)
                if record is None:
                    continue
                events.append(
                    self._event(
                        record.event_type,
                        record.message,
                        record.metadata,
                        record.severity,
                        timestamp=line.timestamp,
                        username=record.username,
                        source_ip=record.source_ip,
                    )
                )

        self._store.save(state)
        return events

    def _source_error(self, source_key: str, error: str) -> Event:
        return self._event(
            EventType.COLLECTOR_ERROR,
            f"Auth source '{source_key}' unavailable",
            {"collector": self.name, "source": source_key, "error": error},
            Severity.LOW,
        )
