"""Application state and its dependency wiring, created once per app instance."""

from __future__ import annotations

import threading
from collections.abc import Sequence
from contextlib import AbstractContextManager
from dataclasses import dataclass
from datetime import UTC, datetime
from pathlib import Path
from typing import Literal

import redis
from sentinelbot_agent.models import Event, Severity
from sentinelbot_ai.analyst import Analyst
from sentinelbot_ai.providers import AnthropicProvider, LLMProvider
from sentinelbot_alerts.channels import AlertChannel, EmailChannel
from sentinelbot_alerts.notifier import Notifier
from sentinelbot_alerts.policy import AlertPolicy
from sentinelbot_database.models import Base
from sentinelbot_database.session import make_engine, make_session_factory
from sentinelbot_detection.baseline import Baseline, load_baseline, save_baseline
from sentinelbot_detection.correlation import CorrelationSettings, Correlator, IncidentStore
from sentinelbot_detection.engine import DetectionEngine
from sentinelbot_detection.rules import build_rules
from sentinelbot_detection.scoring import RiskScorer, RiskSettings
from sentinelbot_detection.settings import DetectionSettings
from sentinelbot_detection.state import MemoryState, RedisState, StateStore

from sentinelbot_backend.config import ApiSettings
from sentinelbot_backend.metrics import ApiMetrics
from sentinelbot_backend.ratelimit import MemoryRateLimiter, RateLimiter, RedisRateLimiter
from sentinelbot_backend.repository import EventRepository, IncidentRepository
from sentinelbot_backend.storage_sql import SqlEventRepository, SqlIncidentStore, SqlUserStore


@dataclass(slots=True)
class Container:
    settings: ApiSettings
    events: EventRepository | SqlEventRepository
    incidents: IncidentRepository
    store: IncidentStore
    correlator: Correlator
    lock: AbstractContextManager[bool]  # serializes access; the API runs in a thread pool
    started_at: datetime
    backend: Literal["memory", "file", "postgresql"]
    rate_limiter: RateLimiter | None
    metrics: ApiMetrics
    notifier: Notifier
    analyst: Analyst
    users: SqlUserStore | None
    detection: DetectionEngine
    scorer: RiskScorer
    baseline: Baseline
    baseline_path: Path | None

    def ingest(self, batch: list[Event]) -> int:
        """Store events, run detection on telemetry, correlate, and alert.

        Telemetry from agents is checked against the detection rules here, so the API
        produces detections even when nothing else runs the rules. Detections sent by a client
        are stored as they are. Returns the number of incidents touched.
        """
        derived = [
            self.scorer.score(detection)
            for event in batch
            if event.source != "detection"
            for detection in self.detection.process(event)
        ]
        accepted = [*batch, *derived]
        self.events.add_many(accepted)
        existing = set(self.store.incidents)
        touched: set[str] = set()
        for event in accepted:
            if event.source == "detection":
                touched.add(self.correlator.ingest(event).incident_id)
        self.incidents.persist_ids(touched)
        self.store.save()
        created = [self.store.incidents[i].severity.value for i in touched - existing]
        self.metrics.record_events(accepted, created)
        if self.baseline_path is not None:
            # Persist what "normal" looks like, so a restart does not re-learn it as new.
            save_baseline(self.baseline_path, self.baseline)
        # Alerts go out after persistence, so a failed mail never loses an incident.
        self.notifier.notify(self.store.incidents[i] for i in sorted(touched))
        return len(touched)


def build_container(
    settings: ApiSettings,
    alert_channels: Sequence[AlertChannel] | None = None,
) -> Container:
    store = IncidentStore(settings.incidents_path)
    backend: Literal["memory", "file", "postgresql"]
    users_store: SqlUserStore | None = None
    if settings.database_url:
        engine = make_engine(settings.database_url)
        if settings.auto_create_schema:
            # Tests and local runs only. Real deployments run `alembic upgrade head`.
            Base.metadata.create_all(engine)
        sessions = make_session_factory(engine)
        durable = SqlIncidentStore(sessions)
        users_store = SqlUserStore(sessions)
        for incident in durable.load_all():
            store.incidents[incident.incident_id] = incident
        events: EventRepository | SqlEventRepository = SqlEventRepository(sessions)
        incidents = IncidentRepository(store, persist=durable.upsert)
        backend = "postgresql"
    else:
        store.load()
        events = EventRepository(settings.event_capacity)
        incidents = IncidentRepository(store)
        backend = "file" if settings.incidents_path else "memory"

    rate_limiter: RateLimiter | None = None
    if settings.rate_limit_per_minute > 0:
        if settings.redis_url:
            rate_limiter = RedisRateLimiter(redis.Redis.from_url(settings.redis_url))
        else:
            rate_limiter = MemoryRateLimiter()

    state: StateStore = (
        RedisState.from_url(settings.redis_url) if settings.redis_url else MemoryState()
    )
    baseline = load_baseline(settings.baseline_path)
    detection_settings = DetectionSettings(
        allowed_listening_ports=frozenset(settings.allowed_listening_ports)
    )
    detection = DetectionEngine(build_rules(detection_settings, baseline, state))

    metrics = ApiMetrics()
    channels = list(alert_channels) if alert_channels is not None else _email_channels(settings)
    notifier = Notifier(
        AlertPolicy(Severity(settings.alert_min_severity), settings.alert_cooldown_seconds),
        channels,
        on_result=lambda channel, status: metrics.alerts_total.labels(channel, status).inc(),
    )

    container = Container(
        settings=settings,
        events=events,
        incidents=incidents,
        store=store,
        correlator=Correlator(store, CorrelationSettings(settings.correlation_gap_seconds)),
        lock=threading.RLock(),
        started_at=datetime.now(UTC),
        backend=backend,
        rate_limiter=rate_limiter,
        metrics=metrics,
        notifier=notifier,
        analyst=Analyst(_ai_provider(settings)),
        users=users_store,
        detection=detection,
        scorer=RiskScorer(RiskSettings(), state),
        baseline=baseline,
        baseline_path=settings.baseline_path,
    )
    container.metrics.attach_state(lambda: _incident_counts(container))
    return container


def _email_channels(settings: ApiSettings) -> list[AlertChannel]:
    """Email is enabled only when an SMTP host is configured."""
    if not settings.smtp_host:
        return []
    return [
        EmailChannel(
            host=settings.smtp_host,
            port=settings.smtp_port,
            sender=settings.smtp_sender or "",
            recipients=list(settings.alert_recipients),
            username=settings.smtp_username,
            password=settings.smtp_password,
            starttls=settings.smtp_starttls,
        )
    ]


def _ai_provider(settings: ApiSettings) -> LLMProvider | None:
    """No model unless explicitly configured: incident data then stays on this host."""
    if settings.ai_provider == "anthropic" and settings.ai_api_key:
        return AnthropicProvider(settings.ai_api_key, settings.ai_model)
    return None


def _incident_counts(container: Container) -> dict[str, int]:
    with container.lock:
        return container.incidents.counts_by_status()
