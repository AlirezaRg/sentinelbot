"""Collector registry. Add new collectors here so they can be enabled by name."""

from __future__ import annotations

from sentinelbot_agent.collectors.auth import AuthCollector
from sentinelbot_agent.collectors.base import Collector
from sentinelbot_agent.collectors.network import NetworkCollector
from sentinelbot_agent.collectors.processes import ProcessCollector
from sentinelbot_agent.collectors.system import SystemCollector
from sentinelbot_agent.config import AgentConfig, ConfigError

REGISTRY: dict[str, type[Collector]] = {
    SystemCollector.name: SystemCollector,
    ProcessCollector.name: ProcessCollector,
    NetworkCollector.name: NetworkCollector,
    AuthCollector.name: AuthCollector,
}


def build_collectors(config: AgentConfig) -> list[Collector]:
    """Instantiate the collectors named in ``config.collectors``, in order."""
    unknown = [name for name in config.collectors if name not in REGISTRY]
    if unknown:
        known = ", ".join(sorted(REGISTRY))
        raise ConfigError(f"unknown collector(s): {', '.join(unknown)} (known: {known})")
    return [REGISTRY[name](config) for name in config.collectors]


__all__ = ["REGISTRY", "Collector", "build_collectors"]
