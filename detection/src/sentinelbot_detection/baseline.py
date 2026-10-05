"""Learned baseline for the process and port rules, persisted as JSON between runs.

The first run that sees a snapshot records it as "normal" instead of alerting. Later runs
alert on anything not in the baseline. A corrupt baseline is an error, not a silent reset:
resetting would learn whatever is running at that moment, including an attacker's process.
"""

from __future__ import annotations

import json
import os
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from sentinelbot_detection.settings import DetectionConfigError

ProcessKey = tuple[str, str | None]
PortKey = tuple[str, int]


@dataclass(slots=True)
class Baseline:
    processes: set[ProcessKey] = field(default_factory=set)
    listening_ports: set[PortKey] = field(default_factory=set)
    processes_learned: bool = False
    ports_learned: bool = False


def load_baseline(path: Path | None) -> Baseline:
    if path is None or not path.exists():
        return Baseline()
    try:
        data: dict[str, Any] = json.loads(path.read_text(encoding="utf-8"))
        return Baseline(
            processes={(name, exe) for name, exe in data["processes"]},
            listening_ports={(proto, int(port)) for proto, port in data["listening_ports"]},
            processes_learned=bool(data["processes_learned"]),
            ports_learned=bool(data["ports_learned"]),
        )
    except (OSError, ValueError, KeyError, TypeError) as exc:
        raise DetectionConfigError(
            f"baseline file {path} is unreadable or corrupt; delete it to re-learn: {exc}"
        ) from exc


def save_baseline(path: Path, baseline: Baseline) -> None:
    payload = {
        "processes": sorted([list(key) for key in baseline.processes], key=str),
        "listening_ports": sorted([list(key) for key in baseline.listening_ports]),
        "processes_learned": baseline.processes_learned,
        "ports_learned": baseline.ports_learned,
    }
    path.parent.mkdir(parents=True, exist_ok=True)
    temporary = path.with_name(path.name + ".tmp")
    temporary.write_text(json.dumps(payload, indent=2), encoding="utf-8")
    os.replace(temporary, path)
