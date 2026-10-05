"""API settings from environment variables. Secrets are never given defaults."""

from __future__ import annotations

import os
from collections.abc import Mapping
from dataclasses import dataclass, field
from pathlib import Path

ENV_PREFIX = "SENTINEL_"
DEFAULT_EVENT_CAPACITY = 100_000
DEFAULT_GAP_SECONDS = 1800
MIN_API_KEY_LENGTH = 24
DEFAULT_RATE_LIMIT_PER_MINUTE = 300
DEFAULT_ALERT_COOLDOWN_SECONDS = 900
DEFAULT_TOKEN_TTL_SECONDS = 8 * 3600
MIN_AUTH_SECRET_LENGTH = 32
ALERT_SEVERITIES = ("info", "low", "medium", "high", "critical")


class SettingsError(ValueError):
    """Raised when API settings are invalid."""


@dataclass(frozen=True, slots=True)
class ApiSettings:
    api_key: str | None = None
    event_capacity: int = DEFAULT_EVENT_CAPACITY
    incidents_path: Path | None = None
    correlation_gap_seconds: int = DEFAULT_GAP_SECONDS
    database_url: str | None = None
    auto_create_schema: bool = False
    redis_url: str | None = None
    rate_limit_per_minute: int = DEFAULT_RATE_LIMIT_PER_MINUTE
    alert_min_severity: str = "high"
    alert_cooldown_seconds: int = DEFAULT_ALERT_COOLDOWN_SECONDS
    smtp_host: str | None = None
    smtp_port: int = 587
    smtp_username: str | None = None
    smtp_password: str | None = field(default=None, repr=False)
    smtp_sender: str | None = None
    smtp_starttls: bool = True
    alert_recipients: tuple[str, ...] = ()
    auth_secret: str | None = field(default=None, repr=False)
    token_ttl_seconds: int = DEFAULT_TOKEN_TTL_SECONDS
    ai_provider: str = "rules"
    ai_api_key: str | None = field(default=None, repr=False)
    ai_model: str = "claude-sonnet-5-5"
    baseline_path: Path | None = None
    allowed_listening_ports: tuple[int, ...] = ()

    def __post_init__(self) -> None:
        if self.rate_limit_per_minute < 0:
            raise SettingsError("rate_limit_per_minute must not be negative (0 disables it)")
        if self.alert_min_severity not in ALERT_SEVERITIES:
            raise SettingsError(f"alert_min_severity must be one of {', '.join(ALERT_SEVERITIES)}")
        if self.auth_secret is not None and len(self.auth_secret) < MIN_AUTH_SECRET_LENGTH:
            raise SettingsError(
                f"SENTINEL_AUTH_SECRET must be at least {MIN_AUTH_SECRET_LENGTH} characters"
            )
        bad_ports = [p for p in self.allowed_listening_ports if not 0 < p < 65536]
        if bad_ports:
            raise SettingsError(f"invalid port(s) in SENTINEL_ALLOWED_PORTS: {bad_ports}")
        if self.token_ttl_seconds <= 0:
            raise SettingsError("token_ttl_seconds must be greater than 0")
        if self.ai_provider not in ("rules", "anthropic"):
            raise SettingsError("SENTINEL_AI_PROVIDER must be 'rules' or 'anthropic'")
        if self.ai_provider == "anthropic" and not self.ai_api_key:
            raise SettingsError("SENTINEL_AI_API_KEY is required when the AI provider is anthropic")
        if self.alert_cooldown_seconds < 0:
            raise SettingsError("alert_cooldown_seconds must not be negative")
        if self.smtp_host and (not self.smtp_sender or not self.alert_recipients):
            raise SettingsError(
                "SENTINEL_SMTP_FROM and SENTINEL_ALERT_RECIPIENTS are required with SMTP"
            )
        if self.database_url and self.incidents_path:
            raise SettingsError(
                "set either SENTINEL_DATABASE_URL or SENTINEL_INCIDENTS_PATH, not both"
            )
        if self.api_key is not None and len(self.api_key) < MIN_API_KEY_LENGTH:
            raise SettingsError(
                f"SENTINEL_API_KEY must be at least {MIN_API_KEY_LENGTH} characters"
            )
        if self.event_capacity <= 0:
            raise SettingsError("event_capacity must be greater than 0")
        if self.correlation_gap_seconds <= 0:
            raise SettingsError("correlation_gap_seconds must be greater than 0")

    @classmethod
    def from_env(cls, env: Mapping[str, str] | None = None) -> ApiSettings:
        source = os.environ if env is None else env

        def read(name: str) -> str | None:
            value = source.get(ENV_PREFIX + name, "").strip()
            return value or None

        incidents_raw = read("INCIDENTS_PATH")
        baseline_raw = read("BASELINE_PATH")
        return cls(
            api_key=read("API_KEY"),
            event_capacity=_int(read("EVENT_CAPACITY"), DEFAULT_EVENT_CAPACITY, "EVENT_CAPACITY"),
            incidents_path=Path(incidents_raw) if incidents_raw else None,
            database_url=read("DATABASE_URL"),
            auto_create_schema=(read("AUTO_CREATE_SCHEMA") or "").lower() in ("1", "true", "yes"),
            redis_url=read("REDIS_URL"),
            alert_min_severity=(read("ALERT_MIN_SEVERITY") or "high").lower(),
            alert_cooldown_seconds=_int(
                read("ALERT_COOLDOWN_SECONDS"),
                DEFAULT_ALERT_COOLDOWN_SECONDS,
                "ALERT_COOLDOWN_SECONDS",
            ),
            auth_secret=source.get(ENV_PREFIX + "AUTH_SECRET") or None,
            token_ttl_seconds=_int(
                read("TOKEN_TTL_SECONDS"), DEFAULT_TOKEN_TTL_SECONDS, "TOKEN_TTL_SECONDS"
            ),
            baseline_path=Path(baseline_raw) if baseline_raw else None,
            allowed_listening_ports=_parse_ports(read("ALLOWED_PORTS")),
            ai_provider=(read("AI_PROVIDER") or "rules").lower(),
            ai_api_key=source.get(ENV_PREFIX + "AI_API_KEY") or None,
            ai_model=read("AI_MODEL") or "claude-sonnet-5-5",
            smtp_host=read("SMTP_HOST"),
            smtp_port=_int(read("SMTP_PORT"), 587, "SMTP_PORT"),
            smtp_username=read("SMTP_USERNAME"),
            smtp_password=source.get(ENV_PREFIX + "SMTP_PASSWORD") or None,
            smtp_sender=read("SMTP_FROM"),
            smtp_starttls=(read("SMTP_STARTTLS") or "true").lower() in ("1", "true", "yes"),
            alert_recipients=tuple(
                part.strip() for part in (read("ALERT_RECIPIENTS") or "").split(",") if part.strip()
            ),
            rate_limit_per_minute=_int(
                read("RATE_LIMIT_PER_MINUTE"),
                DEFAULT_RATE_LIMIT_PER_MINUTE,
                "RATE_LIMIT_PER_MINUTE",
            ),
            correlation_gap_seconds=_int(
                read("CORRELATION_GAP_SECONDS"), DEFAULT_GAP_SECONDS, "CORRELATION_GAP_SECONDS"
            ),
        )


def _parse_ports(raw: str | None) -> tuple[int, ...]:
    """Parse "22,80,443" into a tuple. An empty value means no allowlist (baseline mode)."""
    if not raw:
        return ()
    try:
        return tuple(int(part) for part in raw.split(",") if part.strip())
    except ValueError as exc:
        raise SettingsError(f"{ENV_PREFIX}ALLOWED_PORTS must be comma-separated numbers") from exc


def _int(raw: str | None, default: int, name: str) -> int:
    if raw is None:
        return default
    try:
        return int(raw)
    except ValueError as exc:
        raise SettingsError(f"{ENV_PREFIX}{name} must be an integer") from exc
