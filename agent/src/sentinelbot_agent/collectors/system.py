"""System collector: host identity, OS/kernel, CPU, RAM, disk, load and uptime."""

from __future__ import annotations

import os
import platform
import socket
import time
from typing import Any

import psutil

from sentinelbot_agent.collectors.base import Collector, to_iso
from sentinelbot_agent.models import Event, EventType


class SystemCollector(Collector):
    """Emits one ``system_info`` event (static identity) and one ``system_metrics`` event."""

    name = "system"

    def collect(self) -> list[Event]:
        return [self._system_info(), self._system_metrics()]

    def _system_info(self) -> Event:
        uname = platform.uname()
        metadata: dict[str, Any] = {
            "hostname": socket.gethostname(),
            "os_name": uname.system,
            "os_version": uname.version,
            "kernel_version": uname.release,
            "machine": uname.machine,
            "boot_time": to_iso(psutil.boot_time()),
        }
        metadata.update(_distribution_info())
        return self._event(EventType.SYSTEM_INFO, "System information collected", metadata)

    def _system_metrics(self) -> Event:
        cpu_percent = psutil.cpu_percent(interval=self._config.cpu_sample_seconds or None)
        memory = psutil.virtual_memory()
        disk_path = os.path.abspath(os.sep)
        disk = psutil.disk_usage(disk_path)
        metadata: dict[str, Any] = {
            "cpu_percent": cpu_percent,
            "cpu_count": psutil.cpu_count(logical=True),
            "memory_percent": memory.percent,
            "memory_used_bytes": memory.used,
            "memory_total_bytes": memory.total,
            "disk_path": disk_path,
            "disk_percent": disk.percent,
            "disk_used_bytes": disk.used,
            "disk_total_bytes": disk.total,
            "load_average": _load_average(),
            "uptime_seconds": round(time.time() - psutil.boot_time(), 1),
        }
        message = f"CPU {cpu_percent:.1f}%, memory {memory.percent:.1f}%, disk {disk.percent:.1f}%"
        return self._event(EventType.SYSTEM_METRICS, message, metadata)


def _load_average() -> dict[str, float] | None:
    """Return 1/5/15-minute load averages, or ``None`` where the platform has none (Windows)."""
    if not hasattr(os, "getloadavg"):
        return None
    one, five, fifteen = os.getloadavg()
    return {"1m": round(one, 2), "5m": round(five, 2), "15m": round(fifteen, 2)}


def _distribution_info() -> dict[str, str]:
    """Return the Linux distribution name from ``/etc/os-release`` when available."""
    if not hasattr(platform, "freedesktop_os_release"):
        return {}
    try:
        release = platform.freedesktop_os_release()
    except OSError:
        return {}
    pretty = release.get("PRETTY_NAME")
    return {"os_pretty_name": pretty} if pretty else {}
