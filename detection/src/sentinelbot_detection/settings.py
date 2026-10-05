"""Detection thresholds and rule switches, loaded from an optional TOML file."""

from __future__ import annotations

import tomllib
from dataclasses import dataclass
from pathlib import Path
from typing import Any

ALL_RULES = frozenset(
    {"ssh_bruteforce", "root_login", "auth_burst", "privileged_process", "unexpected_port"}
)


class DetectionConfigError(ValueError):
    """Raised when detection settings are invalid."""


@dataclass(frozen=True, slots=True)
class DetectionSettings:
    """All thresholds are configurable. Defaults match the examples in the project spec."""

    bruteforce_threshold: int = 5
    bruteforce_window_seconds: int = 300
    auth_burst_threshold: int = 30
    auth_burst_window_seconds: int = 300
    cooldown_seconds: int = 900
    privileged_process_max_per_event: int = 20
    allowed_listening_ports: frozenset[int] = frozenset()
    max_tracked_keys: int = 10_000
    enabled_rules: frozenset[str] = ALL_RULES

    def __post_init__(self) -> None:
        positive = {
            "bruteforce_threshold": self.bruteforce_threshold,
            "bruteforce_window_seconds": self.bruteforce_window_seconds,
            "auth_burst_threshold": self.auth_burst_threshold,
            "auth_burst_window_seconds": self.auth_burst_window_seconds,
            "cooldown_seconds": self.cooldown_seconds,
            "privileged_process_max_per_event": self.privileged_process_max_per_event,
            "max_tracked_keys": self.max_tracked_keys,
        }
        for name, value in positive.items():
            if value <= 0:
                raise DetectionConfigError(f"{name} must be greater than 0")
        unknown = self.enabled_rules - ALL_RULES
        if unknown:
            raise DetectionConfigError(f"unknown rule(s): {', '.join(sorted(unknown))}")
        bad_ports = [p for p in self.allowed_listening_ports if not 0 < p < 65536]
        if bad_ports:
            raise DetectionConfigError(f"invalid port(s) in allowlist: {bad_ports}")


def load_settings(path: Path | None) -> DetectionSettings:
    """Read ``[detection]`` keys from a TOML file. Unknown keys are errors, not ignored."""
    if path is None:
        return DetectionSettings()
    try:
        with path.open("rb") as handle:
            data: dict[str, Any] = tomllib.load(handle)
    except OSError as exc:
        raise DetectionConfigError(f"cannot read {path}: {exc}") from exc
    except tomllib.TOMLDecodeError as exc:
        raise DetectionConfigError(f"invalid TOML in {path}: {exc}") from exc

    section = data.get("detection", {})
    if not isinstance(section, dict):
        raise DetectionConfigError("[detection] must be a table")
    known = set(DetectionSettings.__dataclass_fields__)
    unknown = set(section) - known
    if unknown:
        raise DetectionConfigError(f"unknown setting(s): {', '.join(sorted(unknown))}")

    values = dict(section)
    if "allowed_listening_ports" in values:
        values["allowed_listening_ports"] = frozenset(values["allowed_listening_ports"])
    if "enabled_rules" in values:
        values["enabled_rules"] = frozenset(values["enabled_rules"])
    try:
        return DetectionSettings(**values)
    except TypeError as exc:
        raise DetectionConfigError(str(exc)) from exc
