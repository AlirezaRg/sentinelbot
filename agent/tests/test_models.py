"""Event schema validation and JSON round-tripping."""

from __future__ import annotations

from datetime import UTC, datetime, timedelta, timezone

import pytest
from pydantic import ValidationError

from sentinelbot_agent.models import Event, EventType, Severity


def _valid_kwargs() -> dict[str, object]:
    return {
        "host_id": "server-01",
        "event_type": EventType.SYSTEM_INFO,
        "source": "system",
        "message": "System information collected",
    }


def test_defaults_are_filled() -> None:
    event = Event(**_valid_kwargs())  # type: ignore[arg-type]

    assert event.severity is Severity.INFO
    assert event.timestamp.tzinfo is not None
    assert event.metadata == {}
    assert event.event_id is not None


def test_json_round_trip_preserves_event() -> None:
    event = Event(**_valid_kwargs(), metadata={"cpu_percent": 12.5})  # type: ignore[arg-type]

    restored = Event.model_validate_json(event.model_dump_json())

    assert restored == event


def test_naive_timestamp_is_rejected() -> None:
    with pytest.raises(ValidationError, match="timezone-aware"):
        Event(**_valid_kwargs(), timestamp=datetime(2026, 1, 1, 12, 0))  # type: ignore[arg-type]


def test_aware_timestamp_is_normalized_to_utc() -> None:
    offset = timezone(timedelta(hours=3, minutes=30))
    event = Event(**_valid_kwargs(), timestamp=datetime(2026, 1, 1, 12, 0, tzinfo=offset))  # type: ignore[arg-type]

    assert event.timestamp == datetime(2026, 1, 1, 8, 30, tzinfo=UTC)
    assert event.timestamp.utcoffset() == timedelta(0)


def test_unknown_event_type_is_rejected() -> None:
    kwargs = _valid_kwargs()
    kwargs["event_type"] = "not_a_real_type"
    with pytest.raises(ValidationError):
        Event(**kwargs)  # type: ignore[arg-type]


def test_invalid_severity_is_rejected() -> None:
    with pytest.raises(ValidationError):
        Event(**_valid_kwargs(), severity="catastrophic")  # type: ignore[arg-type]


def test_unexpected_field_is_rejected() -> None:
    with pytest.raises(ValidationError):
        Event(**_valid_kwargs(), surprise=True)  # type: ignore[arg-type, call-arg]


def test_source_ip_is_validated() -> None:
    event = Event(**_valid_kwargs(), source_ip="192.168.1.50")  # type: ignore[arg-type]
    assert str(event.source_ip) == "192.168.1.50"

    with pytest.raises(ValidationError):
        Event(**_valid_kwargs(), source_ip="not-an-ip")  # type: ignore[arg-type]
