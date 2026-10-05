"""Parsing of sshd and sudo messages from synthetic log lines."""

from __future__ import annotations

from datetime import UTC, datetime
from pathlib import Path

import pytest

from sentinelbot_agent.auth.parsers import (
    MAX_FIELD_LENGTH,
    parse_auth_message,
    parse_syslog_line,
    resolve_syslog_timestamp,
)
from sentinelbot_agent.models import EventType, Severity

FIXTURE = Path(__file__).parent / "fixtures" / "auth.log"


def test_failed_root_password_is_low_severity_and_targets_root() -> None:
    record = parse_auth_message(
        "sshd", "Failed password for root from 203.0.113.50 port 51514 ssh2"
    )

    assert record is not None
    assert record.event_type is EventType.SSH_LOGIN_FAILED
    assert record.severity is Severity.LOW
    assert record.username == "root"
    assert str(record.source_ip) == "203.0.113.50"
    assert record.metadata["targets_root"] is True
    assert record.metadata["invalid_user"] is False
    assert record.metadata["port"] == 51514


def test_failed_login_for_unknown_user_is_marked_invalid() -> None:
    record = parse_auth_message(
        "sshd", "Failed password for invalid user admin from 203.0.113.50 port 51515 ssh2"
    )

    assert record is not None
    assert record.username == "admin"
    assert record.metadata["invalid_user"] is True
    assert record.metadata["targets_root"] is False


def test_invalid_user_line_is_ignored_to_avoid_double_counting() -> None:
    assert parse_auth_message("sshd", "Invalid user admin from 203.0.113.50 port 51515") is None


def test_successful_key_login_is_info() -> None:
    record = parse_auth_message(
        "sshd", "Accepted publickey for alice from 198.51.100.7 port 40022 ssh2: ED25519 SHA256:x"
    )

    assert record is not None
    assert record.event_type is EventType.SSH_LOGIN_SUCCESS
    assert record.severity is Severity.INFO
    assert record.metadata["auth_method"] == "publickey"


def test_successful_root_login_is_root_login_event() -> None:
    record = parse_auth_message(
        "sshd", "Accepted password for root from 198.51.100.8 port 40023 ssh2"
    )

    assert record is not None
    assert record.event_type is EventType.SSH_ROOT_LOGIN
    assert record.severity is Severity.MEDIUM


def test_sshd_session_program_is_accepted() -> None:
    """OpenSSH 9.8+ (Debian 13) logs authentication under the sshd-session identifier."""
    record = parse_auth_message(
        "sshd-session", "Accepted password for alice from 198.51.100.7 port 40022 ssh2"
    )

    assert record is not None
    assert record.event_type is EventType.SSH_LOGIN_SUCCESS


def test_ipv6_source_is_normalized() -> None:
    record = parse_auth_message(
        "sshd", "Failed publickey for bob from 2001:db8::25 port 22000 ssh2"
    )

    assert record is not None
    assert str(record.source_ip) == "2001:db8::25"


def test_malformed_ip_becomes_none_instead_of_failing() -> None:
    record = parse_auth_message("sshd", "Failed password for root from not-an-ip port 22 ssh2")

    assert record is not None
    assert record.source_ip is None


def test_sudo_keeps_executable_but_not_arguments() -> None:
    record = parse_auth_message(
        "sudo",
        "alice : TTY=pts/0 ; PWD=/home/alice ; USER=root ; "
        "COMMAND=/usr/bin/apt update --token=s3cret",
    )

    assert record is not None
    assert record.event_type is EventType.SUDO_COMMAND
    assert record.username == "alice"
    assert record.metadata == {
        "target_user": "root",
        "tty": "pts/0",
        "executable": "apt",
    }
    assert "s3cret" not in str(record.metadata)


def test_unrelated_programs_and_messages_are_ignored() -> None:
    assert parse_auth_message("systemd", "Started session-3.scope.") is None
    assert parse_auth_message("cron", "session opened for user root") is None
    assert parse_auth_message("sshd", "Connection closed by 203.0.113.50 port 51514") is None


def test_overlong_username_is_clipped_to_schema_limit() -> None:
    long_name = "a" * 400
    record = parse_auth_message(
        "sshd", f"Failed password for {long_name} from 203.0.113.5 port 1 ssh2"
    )

    assert record is not None
    assert record.username is not None
    assert len(record.username) == MAX_FIELD_LENGTH


def test_syslog_line_is_split_into_parts() -> None:
    parsed = parse_syslog_line("Oct  4 09:00:01 server-01 sshd[1201]: Failed password for root")

    assert parsed is not None
    assert parsed.timestamp_text == "Oct  4 09:00:01"
    assert parsed.program == "sshd"
    assert parsed.message == "Failed password for root"


def test_syslog_line_without_header_is_skipped() -> None:
    assert parse_syslog_line("this is not a syslog line") is None


def test_fixture_file_yields_expected_event_types() -> None:
    records = []
    for raw in FIXTURE.read_text(encoding="utf-8").splitlines():
        parsed = parse_syslog_line(raw)
        if parsed is None:
            continue
        record = parse_auth_message(parsed.program, parsed.message)
        if record is not None:
            records.append(record.event_type)

    assert records == [
        EventType.SSH_LOGIN_FAILED,
        EventType.SSH_LOGIN_FAILED,
        EventType.SSH_LOGIN_SUCCESS,
        EventType.SSH_ROOT_LOGIN,
        EventType.SUDO_COMMAND,
        EventType.SSH_LOGIN_FAILED,
    ]


@pytest.mark.parametrize(
    ("now", "text", "local_expected"),
    [
        # Same year as "now".
        (datetime(2026, 10, 4, 12, tzinfo=UTC), "Oct  4 09:00:01", datetime(2026, 10, 4, 9, 0, 1)),
        # A December entry read in January belongs to the previous year.
        (
            datetime(2026, 1, 2, 0, tzinfo=UTC),
            "Dec 31 23:59:59",
            datetime(2025, 12, 31, 23, 59, 59),
        ),
    ],
)
def test_syslog_timestamp_year_is_inferred(
    now: datetime, text: str, local_expected: datetime
) -> None:
    # Syslog times are host-local, so the expected value is the local wall clock in UTC.
    local_tz = now.astimezone().tzinfo
    expected_utc = local_expected.replace(tzinfo=local_tz).astimezone(UTC)

    assert resolve_syslog_timestamp(text, now) == expected_utc
