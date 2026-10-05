"""Configuration parsing and validation."""

from __future__ import annotations

from pathlib import Path

import pytest

from sentinelbot_agent.collectors import build_collectors
from sentinelbot_agent.config import (
    DEFAULT_COLLECTORS,
    DEFAULT_MAX_PROCESSES,
    AgentConfig,
    ConfigError,
)


def test_defaults_when_environment_is_empty() -> None:
    config = AgentConfig.from_env({})

    assert config.host_id
    assert config.collectors == DEFAULT_COLLECTORS
    assert config.max_processes == DEFAULT_MAX_PROCESSES
    assert config.output_path is None


def test_environment_overrides_are_applied() -> None:
    env = {
        "SENTINEL_HOST_ID": "server-01",
        "SENTINEL_INTERVAL_SECONDS": "15",
        "SENTINEL_MAX_PROCESSES": "25",
        "SENTINEL_COLLECTORS": " system , network ",
        "SENTINEL_OUTPUT_PATH": "events.jsonl",
    }

    config = AgentConfig.from_env(env)

    assert config.host_id == "server-01"
    assert config.interval_seconds == 15.0
    assert config.max_processes == 25
    assert config.collectors == ("system", "network")
    assert config.output_path == Path("events.jsonl")


@pytest.mark.parametrize(
    ("key", "value"),
    [
        ("SENTINEL_INTERVAL_SECONDS", "soon"),
        ("SENTINEL_MAX_PROCESSES", "many"),
        ("SENTINEL_COLLECTORS", " , "),
    ],
)
def test_malformed_environment_values_raise(key: str, value: str) -> None:
    with pytest.raises(ConfigError):
        AgentConfig.from_env({key: value})


@pytest.mark.parametrize(
    "kwargs",
    [
        {"interval_seconds": 0},
        {"cpu_sample_seconds": -1},
        {"max_processes": -1},
        {"collectors": ()},
        {"host_id": "   "},
    ],
)
def test_invalid_values_are_rejected(kwargs: dict[str, object]) -> None:
    with pytest.raises(ConfigError):
        AgentConfig(**{"host_id": "h", **kwargs})  # type: ignore[arg-type]


def test_unknown_collector_name_is_reported() -> None:
    config = AgentConfig(host_id="h", collectors=("system", "telepathy"))

    with pytest.raises(ConfigError, match="telepathy"):
        build_collectors(config)
