"""Process collector: a bounded snapshot of running processes."""

from __future__ import annotations

import time
from collections.abc import Callable, Iterable
from typing import Any

import psutil

from sentinelbot_agent.collectors.base import Collector, to_iso
from sentinelbot_agent.config import AgentConfig
from sentinelbot_agent.models import Event, EventType

ProcessSource = Callable[[], Iterable[psutil.Process]]


def _iter_processes() -> Iterable[psutil.Process]:
    return psutil.process_iter()


class ProcessCollector(Collector):
    """Emits one ``process_snapshot`` event holding the top processes by CPU and memory.

    Processes that exit during collection are skipped. Fields the current user may not
    read (``AccessDenied``, common for root-owned processes) are reported as ``None``.
    """

    name = "processes"

    def __init__(
        self,
        config: AgentConfig,
        process_source: ProcessSource = _iter_processes,
        sleep: Callable[[float], None] = time.sleep,
    ) -> None:
        super().__init__(config)
        self._process_source = process_source
        self._sleep = sleep

    def collect(self) -> list[Event]:
        processes = list(self._process_source())
        # psutil measures CPU as a delta, so prime every process, wait, then read.
        for proc in processes:
            try:
                proc.cpu_percent(interval=None)
            except psutil.Error:
                continue
        if self._config.cpu_sample_seconds > 0:
            self._sleep(self._config.cpu_sample_seconds)

        snapshots: list[dict[str, Any]] = []
        for proc in processes:
            try:
                snapshots.append(_snapshot(proc))
            except psutil.NoSuchProcess:
                continue

        snapshots.sort(
            key=lambda s: (s["cpu_percent"] or 0.0, s["memory_percent"] or 0.0), reverse=True
        )
        limited = snapshots[: self._config.max_processes]
        total = len(snapshots)
        metadata: dict[str, Any] = {
            "total_processes": total,
            "returned": len(limited),
            "truncated": len(limited) < total,
            "processes": limited,
        }
        return [
            self._event(
                EventType.PROCESS_SNAPSHOT,
                f"Observed {total} running processes",
                metadata,
            )
        ]


def _snapshot(proc: psutil.Process) -> dict[str, Any]:
    """Read one process. Raises ``NoSuchProcess`` if it exited mid-collection."""
    return {
        "pid": proc.pid,
        "ppid": _read(proc.ppid),
        "name": _read(proc.name),
        "username": _read(proc.username),
        "cpu_percent": _read(lambda: proc.cpu_percent(interval=None)),
        "memory_percent": _read(lambda: round(proc.memory_percent(), 2)),
        "rss_bytes": _read(lambda: proc.memory_info().rss),
        "exe": _read(proc.exe),
        "create_time": to_iso(_read(proc.create_time)),
    }


def _read[T](getter: Callable[[], T]) -> T | None:
    """Call a psutil getter, returning ``None`` for permission and zombie errors only."""
    try:
        return getter()
    except (psutil.AccessDenied, psutil.ZombieProcess):
        return None
