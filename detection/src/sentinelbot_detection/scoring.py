"""Risk scoring: turns each detection into a 0-100 score and a severity band.

Score = base points for the rule
      + repetition (more detections from the same source in the window)
      + privilege (root is targeted or acquired)
      + combination (several different rules fired for the same source)
      + local reputation (only from the operator's own trusted/blocked lists)
clamped to 0-100. Every point is listed in ``risk_factors`` so the score can be explained.

All weights and band edges are configurable in the ``[risk]`` table of the TOML config.
"""

from __future__ import annotations

import tomllib
from dataclasses import dataclass, field
from ipaddress import ip_address
from pathlib import Path
from typing import Any

from sentinelbot_agent.models import Event, Severity

from sentinelbot_detection.settings import ALL_RULES, DetectionConfigError
from sentinelbot_detection.state import MemoryState, StateStore, WindowLike

MAX_SCORE = 100
MAX_TRACKED_SOURCES = 10_000

DEFAULT_BASE_POINTS: dict[str, int] = {
    "ssh_bruteforce": 40,
    "root_login": 35,
    "auth_burst": 20,
    "privileged_process": 25,
    "unexpected_port": 20,
}


@dataclass(frozen=True, slots=True)
class RiskSettings:
    base_points: dict[str, int] = field(default_factory=lambda: dict(DEFAULT_BASE_POINTS))
    repeat_points: int = 10
    repeat_cap: int = 30
    privileged_points: int = 15
    combination_points: int = 10
    combination_cap: int = 20
    trusted_penalty: int = 30
    known_bad_bonus: int = 25
    trusted_ips: frozenset[str] = frozenset()
    known_bad_ips: frozenset[str] = frozenset()
    window_seconds: int = 900
    # Exclusive upper bounds for INFO, LOW, MEDIUM and HIGH. Scores at or above the last edge
    # are CRITICAL.
    band_edges: tuple[int, int, int, int] = (20, 40, 60, 80)

    def __post_init__(self) -> None:
        unknown = set(self.base_points) - ALL_RULES
        if unknown:
            raise DetectionConfigError(f"base_points has unknown rule(s): {sorted(unknown)}")
        for name in (
            "repeat_points",
            "repeat_cap",
            "privileged_points",
            "combination_points",
            "combination_cap",
            "trusted_penalty",
            "known_bad_bonus",
        ):
            if getattr(self, name) < 0:
                raise DetectionConfigError(f"{name} must not be negative")
        if any(points < 0 for points in self.base_points.values()):
            raise DetectionConfigError("base_points must not be negative")
        if self.window_seconds <= 0:
            raise DetectionConfigError("window_seconds must be greater than 0")
        edges = self.band_edges
        if not (0 < edges[0] < edges[1] < edges[2] < edges[3] < MAX_SCORE):
            raise DetectionConfigError("band_edges must be strictly increasing within 1..99")
        for raw in (*self.trusted_ips, *self.known_bad_ips):
            try:
                ip_address(raw)
            except ValueError as exc:
                raise DetectionConfigError(f"invalid IP in reputation list: {raw!r}") from exc


def load_risk_settings(path: Path | None) -> RiskSettings:
    """Read the ``[risk]`` table. Unknown keys are errors, so typos are caught."""
    if path is None:
        return RiskSettings()
    try:
        data: dict[str, Any] = tomllib.loads(path.read_text(encoding="utf-8"))
    except OSError as exc:
        raise DetectionConfigError(f"cannot read {path}: {exc}") from exc
    except tomllib.TOMLDecodeError as exc:
        raise DetectionConfigError(f"invalid TOML in {path}: {exc}") from exc

    section = data.get("risk", {})
    if not isinstance(section, dict):
        raise DetectionConfigError("[risk] must be a table")
    unknown = set(section) - set(RiskSettings.__dataclass_fields__)
    if unknown:
        raise DetectionConfigError(f"unknown risk setting(s): {', '.join(sorted(unknown))}")

    values = dict(section)
    if "trusted_ips" in values:
        values["trusted_ips"] = frozenset(values["trusted_ips"])
    if "known_bad_ips" in values:
        values["known_bad_ips"] = frozenset(values["known_bad_ips"])
    if "band_edges" in values:
        values["band_edges"] = tuple(values["band_edges"])
    try:
        return RiskSettings(**values)
    except TypeError as exc:
        raise DetectionConfigError(str(exc)) from exc


_SEVERITY_RANK: dict[Severity, int] = {
    Severity.INFO: 0,
    Severity.LOW: 1,
    Severity.MEDIUM: 2,
    Severity.HIGH: 3,
    Severity.CRITICAL: 4,
}


def _band(score: int, edges: tuple[int, int, int, int]) -> Severity:
    if score < edges[0]:
        return Severity.INFO
    if score < edges[1]:
        return Severity.LOW
    if score < edges[2]:
        return Severity.MEDIUM
    if score < edges[3]:
        return Severity.HIGH
    return Severity.CRITICAL


class RiskScorer:
    """Scores detections in order. Repetition and combination use per-source history."""

    def __init__(self, settings: RiskSettings, state: StateStore | None = None) -> None:
        self._settings = settings
        self._history: WindowLike = (state if state is not None else MemoryState()).window(
            "risk.history", settings.window_seconds, MAX_TRACKED_SOURCES
        )

    def score(self, detection: Event) -> Event:
        """Return the detection with ``severity`` set from the score and the score explained."""
        settings = self._settings
        rule_id = str(detection.metadata.get("rule_id", ""))
        source = str(detection.source_ip) if detection.source_ip is not None else detection.host_id
        history = self._history.add(source, detection.timestamp, rule_id)

        factors: list[dict[str, Any]] = []
        base = settings.base_points.get(rule_id, 0)
        if base:
            factors.append({"factor": f"base:{rule_id}", "points": base})

        # Repetition counts the same rule firing again; different rules count as combination.
        repeats = sum(1 for seen in history if seen == rule_id) - 1
        if repeats > 0:
            factors.append(
                {
                    "factor": "repetition",
                    "points": min(repeats * settings.repeat_points, settings.repeat_cap),
                }
            )

        extra_rules = len(set(history)) - 1
        if extra_rules > 0:
            factors.append(
                {
                    "factor": "combination",
                    "points": min(
                        extra_rules * settings.combination_points, settings.combination_cap
                    ),
                }
            )

        privileged = detection.username == "root" or bool(detection.metadata.get("targets_root"))
        if privileged and settings.privileged_points:
            factors.append({"factor": "privilege", "points": settings.privileged_points})

        if detection.source_ip is not None:
            ip = str(detection.source_ip)
            if ip in settings.trusted_ips:
                factors.append(
                    {"factor": "reputation:trusted", "points": -settings.trusted_penalty}
                )
            if ip in settings.known_bad_ips:
                factors.append(
                    {"factor": "reputation:known_bad", "points": settings.known_bad_bonus}
                )

        total = sum(f["points"] for f in factors)
        score = max(0, min(MAX_SCORE, total))
        updated = detection.model_dump()
        # A rule's own severity is a floor: the score can raise it but never lower it.
        updated["severity"] = max(
            detection.severity, _band(score, settings.band_edges), key=_SEVERITY_RANK.__getitem__
        )
        updated["metadata"] = {
            **detection.metadata,
            "risk_score": score,
            "risk_factors": factors,
            "base_severity": detection.severity.value,
        }
        return Event.model_validate(updated)
