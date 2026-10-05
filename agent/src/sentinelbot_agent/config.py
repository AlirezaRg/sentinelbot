"""Agent configuration, loaded from environment variables and CLI overrides."""

from __future__ import annotations

import os
import socket
from collections.abc import Mapping
from dataclasses import dataclass, field
from pathlib import Path

ENV_PREFIX = "SENTINEL_"

DEFAULT_INTERVAL_SECONDS = 60.0
DEFAULT_CPU_SAMPLE_SECONDS = 0.5
DEFAULT_MAX_PROCESSES = 200
DEFAULT_MAX_CONNECTIONS = 500
DEFAULT_COLLECTORS: tuple[str, ...] = ("system", "processes", "network")
DEFAULT_AUTH_LOG_PATHS: tuple[Path, ...] = (Path("/var/log/auth.log"), Path("/var/log/secure"))
DEFAULT_STATE_PATH = Path.home() / ".local" / "state" / "sentinelbot" / "agent-state.json"
DEFAULT_JOURNAL_BOOTSTRAP_LINES = 500


class ConfigError(ValueError):
    """Raised when the agent configuration is invalid."""


def parse_collectors(raw: str) -> tuple[str, ...]:
    """Parse a comma-separated collector list such as ``"system,network"``."""
    names = tuple(part.strip() for part in raw.split(",") if part.strip())
    if not names:
        raise ConfigError("collector list must name at least one collector")
    return names


@dataclass(frozen=True, slots=True)
class AgentConfig:
    """Validated runtime settings for one agent process."""

    host_id: str
    interval_seconds: float = DEFAULT_INTERVAL_SECONDS
    cpu_sample_seconds: float = DEFAULT_CPU_SAMPLE_SECONDS
    max_processes: int = DEFAULT_MAX_PROCESSES
    max_connections: int = DEFAULT_MAX_CONNECTIONS
    collectors: tuple[str, ...] = DEFAULT_COLLECTORS
    output_path: Path | None = None
    api_url: str | None = None
    api_key: str | None = field(default=None, repr=False)
    auth_log_paths: tuple[Path, ...] = DEFAULT_AUTH_LOG_PATHS
    state_path: Path = DEFAULT_STATE_PATH
    journal_bootstrap_lines: int = DEFAULT_JOURNAL_BOOTSTRAP_LINES

    def __post_init__(self) -> None:
        if self.journal_bootstrap_lines < 0:
            raise ConfigError("journal_bootstrap_lines must not be negative")
        if not self.host_id.strip():
            raise ConfigError("host_id must not be empty")
        if self.interval_seconds <= 0:
            raise ConfigError("interval_seconds must be greater than 0")
        if self.cpu_sample_seconds < 0:
            raise ConfigError("cpu_sample_seconds must not be negative")
        if self.max_processes < 0 or self.max_connections < 0:
            raise ConfigError("max_processes and max_connections must not be negative")
        if not self.collectors:
            raise ConfigError("at least one collector must be enabled")

    @classmethod
    def from_env(cls, env: Mapping[str, str] | None = None) -> AgentConfig:
        """Build a config from ``SENTINEL_*`` environment variables.

        Unset variables fall back to the defaults above.
        """
        source = os.environ if env is None else env

        def read(name: str) -> str | None:
            value = source.get(ENV_PREFIX + name)
            return value.strip() if value and value.strip() else None

        raw_collectors = read("COLLECTORS")
        raw_output = read("OUTPUT_PATH")
        return cls(
            host_id=read("HOST_ID") or socket.gethostname(),
            interval_seconds=_parse_float(
                read("INTERVAL_SECONDS"), DEFAULT_INTERVAL_SECONDS, "INTERVAL_SECONDS"
            ),
            cpu_sample_seconds=_parse_float(
                read("CPU_SAMPLE_SECONDS"), DEFAULT_CPU_SAMPLE_SECONDS, "CPU_SAMPLE_SECONDS"
            ),
            max_processes=_parse_int(read("MAX_PROCESSES"), DEFAULT_MAX_PROCESSES, "MAX_PROCESSES"),
            max_connections=_parse_int(
                read("MAX_CONNECTIONS"), DEFAULT_MAX_CONNECTIONS, "MAX_CONNECTIONS"
            ),
            collectors=parse_collectors(raw_collectors) if raw_collectors else DEFAULT_COLLECTORS,
            output_path=Path(raw_output) if raw_output else None,
            api_url=read("API_URL"),
            api_key=source.get(ENV_PREFIX + "API_KEY") or None,
            auth_log_paths=_parse_paths(read("AUTH_LOG_PATHS")) or DEFAULT_AUTH_LOG_PATHS,
            state_path=Path(read("STATE_PATH") or DEFAULT_STATE_PATH),
            journal_bootstrap_lines=_parse_int(
                read("JOURNAL_BOOTSTRAP_LINES"),
                DEFAULT_JOURNAL_BOOTSTRAP_LINES,
                "JOURNAL_BOOTSTRAP_LINES",
            ),
        )


def _parse_paths(raw: str | None) -> tuple[Path, ...]:
    """Parse a comma-separated path list; ``None`` means 'use the default'."""
    if raw is None:
        return ()
    return tuple(Path(part.strip()) for part in raw.split(",") if part.strip())


def _parse_float(raw: str | None, default: float, name: str) -> float:
    if raw is None:
        return default
    try:
        return float(raw)
    except ValueError as exc:
        raise ConfigError(f"{ENV_PREFIX}{name} must be a number, got {raw!r}") from exc


def _parse_int(raw: str | None, default: int, name: str) -> int:
    if raw is None:
        return default
    try:
        return int(raw)
    except ValueError as exc:
        raise ConfigError(f"{ENV_PREFIX}{name} must be an integer, got {raw!r}") from exc
