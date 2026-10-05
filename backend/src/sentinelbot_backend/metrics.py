"""Prometheus metrics for the API, served at ``GET /metrics``.

Label values are kept to small, fixed sets (event type, severity, rule, status) plus the host
name, so the number of time series grows with the number of agents, not with traffic. Source
IPs and user names are never labels.

Agent gauges (CPU, memory, connections, processes) are read from the ``system_metrics``,
``network_snapshot`` and ``process_snapshot`` events the agent sends, so no separate scrape of
each agent is needed.
"""

from __future__ import annotations

from collections.abc import Callable, Iterable
from datetime import UTC, datetime

from prometheus_client import CollectorRegistry, Counter, Gauge, Histogram
from prometheus_client.core import GaugeMetricFamily
from sentinelbot_agent.models import Event, EventType

LATENCY_BUCKETS = (0.1, 0.5, 1, 5, 15, 60, 300, 1800, 3600)


class ApiMetrics:
    def __init__(self) -> None:
        self.registry = CollectorRegistry(auto_describe=True)
        self.events_total = Counter(
            "sentinel_events_total",
            "Events accepted by the API, by type and severity.",
            ["event_type", "severity"],
            registry=self.registry,
        )
        self.detections_total = Counter(
            "sentinel_detection_events_total",
            "Detections received, by rule and severity.",
            ["rule_id", "severity"],
            registry=self.registry,
        )
        self.incidents_total = Counter(
            "sentinel_incidents_total",
            "Incidents created, by severity.",
            ["severity"],
            registry=self.registry,
        )
        self.alerts_total = Counter(
            "sentinel_alerts_total",
            "Alert deliveries, by channel and status (filled by the alerting module).",
            ["channel", "status"],
            registry=self.registry,
        )
        self.detection_latency = Histogram(
            "sentinel_detection_latency_seconds",
            "Seconds from a detection's event time to its ingestion by the API.",
            buckets=LATENCY_BUCKETS,
            registry=self.registry,
        )
        self.agent_cpu = Gauge(
            "sentinel_agent_cpu_usage",
            "Latest CPU percent reported by an agent.",
            ["host"],
            registry=self.registry,
        )
        self.agent_memory = Gauge(
            "sentinel_agent_memory_usage",
            "Latest memory percent reported by an agent.",
            ["host"],
            registry=self.registry,
        )
        self.active_connections = Gauge(
            "sentinel_active_connections",
            "Active (non-listening) connections in the latest network snapshot.",
            ["host"],
            registry=self.registry,
        )
        self.running_processes = Gauge(
            "sentinel_running_processes",
            "Running processes in the latest process snapshot.",
            ["host"],
            registry=self.registry,
        )

    def attach_state(self, snapshot: StateSnapshot) -> None:
        """Expose incident counts computed from ``snapshot`` on every scrape."""
        self.registry.register(IncidentStateCollector(snapshot))

    def record_events(self, events: Iterable[Event], new_incident_severities: list[str]) -> None:
        """Update counters and gauges for one accepted batch."""
        now = datetime.now(UTC)
        for event in events:
            self.events_total.labels(event.event_type.value, event.severity.value).inc()
            if event.source == "detection":
                rule = str(event.metadata.get("rule_id", "unknown"))
                self.detections_total.labels(rule, event.severity.value).inc()
                latency = (now - event.timestamp).total_seconds()
                self.detection_latency.observe(max(0.0, latency))
            self._update_agent_gauges(event)
        for severity in new_incident_severities:
            self.incidents_total.labels(severity).inc()

    def _update_agent_gauges(self, event: Event) -> None:
        host = event.host_id
        meta = event.metadata
        if event.event_type is EventType.SYSTEM_METRICS:
            if "cpu_percent" in meta:
                self.agent_cpu.labels(host).set(float(meta["cpu_percent"]))
            if "memory_percent" in meta:
                self.agent_memory.labels(host).set(float(meta["memory_percent"]))
        elif event.event_type is EventType.NETWORK_SNAPSHOT and "connection_count" in meta:
            self.active_connections.labels(host).set(float(meta["connection_count"]))
        elif event.event_type is EventType.PROCESS_SNAPSHOT and "total_processes" in meta:
            self.running_processes.labels(host).set(float(meta["total_processes"]))


StateSnapshot = Callable[[], dict[str, int]]


class IncidentStateCollector:
    """Computed at scrape time, so the values are always the current state."""

    def __init__(self, snapshot: StateSnapshot) -> None:
        self._snapshot = snapshot

    def collect(self) -> Iterable[GaugeMetricFamily]:
        # Not "sentinel_incidents": that name collides with the counter sentinel_incidents_total.
        incidents = GaugeMetricFamily(
            "sentinel_incident_status",
            "Stored incidents by status.",
            labels=["status"],
        )
        for status, count in self._snapshot().items():
            incidents.add_metric([status], count)
        yield incidents
