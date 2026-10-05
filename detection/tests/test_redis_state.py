"""Redis-backed state: windows and cooldowns, and sharing across runs.

Uses fakeredis, so no server is needed. Set SENTINEL_TEST_REDIS_URL to run the same checks
against a real Redis.
"""

from __future__ import annotations

import os
from datetime import datetime
from typing import Any

import fakeredis
import pytest
import redis
from sentinelbot_agent.models import EventType

from sentinelbot_detection.baseline import Baseline
from sentinelbot_detection.engine import DetectionEngine
from sentinelbot_detection.rules import build_rules
from sentinelbot_detection.settings import DetectionSettings
from sentinelbot_detection.state import RedisState
from tests.conftest import at, failed_login


@pytest.fixture
def server() -> fakeredis.FakeServer:
    return fakeredis.FakeServer()


def _client(server: fakeredis.FakeServer) -> redis.Redis:
    return fakeredis.FakeRedis(server=server, decode_responses=True)


def _state(server: fakeredis.FakeServer) -> RedisState:
    return RedisState(_client(server), prefix="test:detect")


def test_window_returns_payloads_inside_the_window(server: fakeredis.FakeServer) -> None:
    window = _state(server).window("attempts", window_seconds=100, max_keys=10)

    window.add("ip", at(0), ["alice", False])
    window.add("ip", at(10), ["root", True])
    entries = window.add("ip", at(20), ["bob", False])

    assert sorted(entries) == sorted([["alice", False], ["root", True], ["bob", False]])


def test_window_forgets_entries_older_than_the_window(server: fakeredis.FakeServer) -> None:
    window = _state(server).window("attempts", window_seconds=100, max_keys=10)

    window.add("ip", at(0), "old")
    entries = window.add("ip", at(150), "new")

    assert entries == ["new"]


def test_identical_payloads_are_counted_separately(server: fakeredis.FakeServer) -> None:
    window = _state(server).window("attempts", window_seconds=100, max_keys=10)

    window.add("ip", at(0), "same")
    entries = window.add("ip", at(1), "same")

    assert entries == ["same", "same"]


def test_cooldown_blocks_until_the_period_passes(server: fakeredis.FakeServer) -> None:
    cooldown = _state(server).cooldown("alerts", period_seconds=60, max_keys=10)

    assert cooldown.allow("ip", at(0)) is True
    assert cooldown.allow("ip", at(30)) is False
    assert cooldown.allow("ip", at(61)) is True


def test_state_is_shared_between_runs(server: fakeredis.FakeServer) -> None:
    """Two runs with fresh objects but the same Redis: the attack is counted across both."""
    settings = DetectionSettings(bruteforce_threshold=5)

    first_run = DetectionEngine(build_rules(settings, Baseline(), _state(server)))
    for second in range(3):
        assert first_run.process(failed_login(second)) == []

    second_run = DetectionEngine(build_rules(settings, Baseline(), _state(server)))
    detections: list[Any] = []
    for second in range(3, 5):
        detections.extend(second_run.process(failed_login(second)))

    assert [d.event_type for d in detections] == [EventType.SSH_BRUTEFORCE_DETECTED]
    assert detections[0].metadata["failed_attempts"] == 5


def test_memory_and_redis_agree_on_the_same_stream(server: fakeredis.FakeServer) -> None:
    from sentinelbot_detection.state import MemoryState

    settings = DetectionSettings(bruteforce_threshold=4)
    events = [failed_login(s) for s in range(4)]

    memory = DetectionEngine(build_rules(settings, Baseline(), MemoryState()))
    shared = DetectionEngine(build_rules(settings, Baseline(), _state(server)))

    memory_types = [d.event_type for e in events for d in memory.process(e)]
    shared_types = [d.event_type for e in events for d in shared.process(e)]

    assert memory_types == shared_types


def test_real_redis_when_configured() -> None:
    url = os.environ.get("SENTINEL_TEST_REDIS_URL")
    if not url:
        pytest.skip("SENTINEL_TEST_REDIS_URL is not set")
    state = RedisState.from_url(url)
    state.ping()
    window = state.window("test.real", window_seconds=100, max_keys=10)

    window.add("probe", datetime.fromisoformat("2026-10-04T12:00:00+00:00"), "x")

    assert window.add("probe", at(1), "y")
