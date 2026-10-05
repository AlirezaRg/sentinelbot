"""Batched HTTP delivery: batching, retry without loss or reordering, and duplicate handling."""

from __future__ import annotations

import io
import json
import urllib.error
from email.message import Message
from typing import Any

import pytest

from sentinelbot_agent.models import Event, EventType, Severity
from sentinelbot_agent.output import HttpBatchSink, JsonLinesSink


def _event(n: int) -> Event:
    return Event(
        host_id="server-01",
        event_type=EventType.SYSTEM_INFO,
        severity=Severity.INFO,
        source="system",
        message=f"event {n}",
    )


class FakeApi:
    """Stands in for ``urllib.request.urlopen``. Each queued result is returned in order."""

    def __init__(self, *results: int | Exception) -> None:
        self.results = list(results)
        self.received: list[list[str]] = []
        self.headers: list[dict[str, str]] = []

    def __call__(self, request: Any, timeout: float) -> Any:
        self.headers.append({k.lower(): v for k, v in request.headers.items()})
        self.received.append([item["message"] for item in json.loads(request.data)])
        result = self.results.pop(0) if self.results else 201
        if isinstance(result, Exception):
            raise result
        if result >= 400:
            raise urllib.error.HTTPError(
                request.full_url, result, "err", Message(), io.BytesIO(b"")
            )
        return _Response(result)


class _Response:
    def __init__(self, status: int) -> None:
        self.status = status

    def __enter__(self) -> _Response:
        return self

    def __exit__(self, *args: object) -> None:
        return None


@pytest.fixture
def api(monkeypatch: pytest.MonkeyPatch) -> FakeApi:
    fake = FakeApi()
    monkeypatch.setattr("sentinelbot_agent.output.urllib.request.urlopen", fake)
    return fake


def test_events_are_sent_in_batches_with_the_key(api: FakeApi) -> None:
    sink = HttpBatchSink("https://sentinel.example", "k" * 32, batch_size=2)
    for n in range(5):
        sink.emit(_event(n))

    sink.flush()

    assert [len(batch) for batch in api.received] == [2, 2, 1]
    assert api.headers[0]["x-api-key"] == "k" * 32
    assert sink.pending == 0


def test_transient_failure_keeps_events_in_order_for_the_next_flush(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    fake = FakeApi(urllib.error.URLError("network down"), 201)
    monkeypatch.setattr("sentinelbot_agent.output.urllib.request.urlopen", fake)
    sink = HttpBatchSink("http://api.test", "k" * 32, batch_size=10)
    for n in range(3):
        sink.emit(_event(n))

    sink.flush()
    assert sink.pending == 3

    sink.flush()

    assert fake.received[0] == ["event 0", "event 1", "event 2"]
    assert fake.received[1] == ["event 0", "event 1", "event 2"]
    assert sink.pending == 0


def test_duplicate_batch_is_dropped_not_retried(api: FakeApi) -> None:
    api.results = [409]
    sink = HttpBatchSink("http://api.test", "k" * 32)
    sink.emit(_event(0))

    sink.flush()

    assert sink.pending == 0
    assert len(api.received) == 1


def test_server_error_keeps_the_batch(api: FakeApi) -> None:
    api.results = [500]
    sink = HttpBatchSink("http://api.test", "k" * 32)
    sink.emit(_event(0))

    sink.flush()

    assert sink.pending == 1


def test_queue_drops_the_oldest_events_when_full(api: FakeApi) -> None:
    api.results = [urllib.error.URLError("down")] * 5
    sink = HttpBatchSink("http://api.test", "k" * 32, queue_limit=3)
    for n in range(5):
        sink.emit(_event(n))

    sink.flush()

    assert sink.pending == 3
    assert api.received[0] == ["event 2", "event 3", "event 4"]  # the two oldest were dropped


def test_json_lines_sink_flush_is_harmless() -> None:
    stream = io.StringIO()
    sink = JsonLinesSink(stream)

    sink.emit(_event(0))
    sink.flush()

    assert json.loads(stream.getvalue())["message"] == "event 0"
