"""Shared fixtures. Tests never touch real attack surface; they read only local host state."""

from __future__ import annotations

import pytest

from sentinelbot_agent.config import AgentConfig


@pytest.fixture
def config() -> AgentConfig:
    """A config with no CPU sampling delay so tests run quickly."""
    return AgentConfig(
        host_id="test-host", cpu_sample_seconds=0.0, max_processes=50, max_connections=50
    )
