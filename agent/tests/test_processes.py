"""Process collector using fake process objects, so no real process state is required."""

from __future__ import annotations

from dataclasses import replace
from types import SimpleNamespace
from typing import Any

import psutil

from sentinelbot_agent.collectors.processes import ProcessCollector
from sentinelbot_agent.config import AgentConfig
from sentinelbot_agent.models import EventType


class FakeProcess:
    """Minimal stand-in for ``psutil.Process`` with injectable failures."""

    def __init__(
        self,
        pid: int,
        name: str,
        *,
        cpu: float = 0.0,
        memory: float = 1.0,
        exe_error: Exception | None = None,
        vanish: bool = False,
    ) -> None:
        self.pid = pid
        self._name = name
        self._cpu = cpu
        self._memory = memory
        self._exe_error = exe_error
        self._vanish = vanish

    def cpu_percent(self, interval: float | None = None) -> float:
        if self._vanish:
            raise psutil.NoSuchProcess(self.pid, name=self._name)
        return self._cpu

    def memory_percent(self) -> float:
        return self._memory

    def memory_info(self) -> Any:
        return SimpleNamespace(rss=4096)

    def name(self) -> str:
        return self._name

    def username(self) -> str:
        return "alice"

    def ppid(self) -> int:
        return 1

    def exe(self) -> str:
        if self._exe_error is not None:
            raise self._exe_error
        return f"/usr/bin/{self._name}"

    def create_time(self) -> float:
        return 1_700_000_000.0


def _collector(config: AgentConfig, processes: list[Any], sleeps: list[float]) -> ProcessCollector:
    return ProcessCollector(config, process_source=lambda: processes, sleep=sleeps.append)


def test_snapshot_fields_and_sorting(config: AgentConfig) -> None:
    processes = [
        FakeProcess(10, "idle", cpu=0.0, memory=1.0),
        FakeProcess(11, "busy", cpu=80.0, memory=2.0),
        FakeProcess(12, "medium", cpu=5.0, memory=9.0),
    ]

    (event,) = _collector(config, processes, []).collect()

    assert event.event_type is EventType.PROCESS_SNAPSHOT
    assert event.metadata["total_processes"] == 3
    assert event.metadata["truncated"] is False
    pids = [p["pid"] for p in event.metadata["processes"]]
    assert pids == [11, 12, 10]
    first = event.metadata["processes"][0]
    assert first["name"] == "busy"
    assert first["exe"] == "/usr/bin/busy"
    assert first["username"] == "alice"
    assert first["create_time"].endswith("+00:00")


def test_access_denied_fields_become_none(config: AgentConfig) -> None:
    processes = [FakeProcess(20, "rootd", exe_error=psutil.AccessDenied(pid=20, name="rootd"))]

    (event,) = _collector(config, processes, []).collect()

    (record,) = event.metadata["processes"]
    assert record["exe"] is None
    assert record["name"] == "rootd"


def test_process_that_exits_mid_collection_is_skipped(config: AgentConfig) -> None:
    processes = [FakeProcess(30, "stable"), FakeProcess(31, "gone", vanish=True)]

    (event,) = _collector(config, processes, []).collect()

    assert [p["pid"] for p in event.metadata["processes"]] == [30]
    assert event.metadata["total_processes"] == 1


def test_output_is_truncated_to_max_processes(config: AgentConfig) -> None:
    small = replace(config, max_processes=2)
    processes = [FakeProcess(pid, f"p{pid}", cpu=float(pid)) for pid in range(40, 44)]

    (event,) = _collector(small, processes, []).collect()

    assert event.metadata["total_processes"] == 4
    assert event.metadata["returned"] == 2
    assert event.metadata["truncated"] is True
    assert [p["pid"] for p in event.metadata["processes"]] == [43, 42]


def test_waits_for_cpu_sample_window_between_priming_and_reading(config: AgentConfig) -> None:
    sampled = replace(config, cpu_sample_seconds=0.5)
    sleeps: list[float] = []

    _collector(sampled, [FakeProcess(50, "x")], sleeps).collect()

    assert sleeps == [0.5]


def test_no_sleep_when_sampling_disabled(config: AgentConfig) -> None:
    sleeps: list[float] = []

    _collector(config, [FakeProcess(51, "x")], sleeps).collect()

    assert sleeps == []
