"""Log sources: file tailing with rotation, truncation and partial lines; journal cursors."""

from __future__ import annotations

import json
import os
import subprocess
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

import pytest

from sentinelbot_agent.auth.sources import FileSource, JournalSource, SourceError

NOW = datetime(2026, 10, 4, 12, 0, tzinfo=UTC)
FAILED = (
    "Oct  4 09:00:01 server-01 sshd[1]: Failed password for root from 203.0.113.50 port 1 ssh2\n"
)
ACCEPTED = (
    "Oct  4 09:00:02 server-01 sshd[2]: Accepted password for alice from 198.51.100.7 port 2 ssh2\n"
)


def _file_source(path: Path, max_bytes: int = 1_048_576) -> FileSource:
    return FileSource(path, now=lambda: NOW, max_bytes=max_bytes)


def test_first_read_returns_all_lines_and_second_returns_only_new_ones(tmp_path: Path) -> None:
    log = tmp_path / "auth.log"
    log.write_text(FAILED, encoding="utf-8")
    source = _file_source(log)

    lines, state = source.read_new({})
    assert [line.message for line in lines] == [
        "Failed password for root from 203.0.113.50 port 1 ssh2"
    ]

    with log.open("a", encoding="utf-8") as handle:
        handle.write(ACCEPTED)
    lines, _ = source.read_new(state)

    assert [line.message for line in lines] == [
        "Accepted password for alice from 198.51.100.7 port 2 ssh2"
    ]


def test_partial_line_is_left_until_its_newline_arrives(tmp_path: Path) -> None:
    log = tmp_path / "auth.log"
    log.write_text(FAILED + "Oct  4 09:00:03 server-01 sshd[3]: Acce", encoding="utf-8")
    source = _file_source(log)

    lines, state = source.read_new({})
    assert len(lines) == 1

    with log.open("a", encoding="utf-8") as handle:
        handle.write("pted password for alice from 198.51.100.7 port 3 ssh2\n")
    lines, _ = source.read_new(state)

    assert len(lines) == 1
    assert lines[0].message.startswith("Accepted password for alice")


def test_rotation_restarts_from_the_beginning_of_the_new_file(tmp_path: Path) -> None:
    log = tmp_path / "auth.log"
    log.write_text(FAILED, encoding="utf-8")
    source = _file_source(log)
    _, state = source.read_new({})

    rotated = tmp_path / "auth.log.1"
    os.replace(log, rotated)
    log.write_text(ACCEPTED, encoding="utf-8")

    lines, _ = source.read_new(state)

    assert [line.message for line in lines] == [
        "Accepted password for alice from 198.51.100.7 port 2 ssh2"
    ]


def test_truncation_restarts_from_the_beginning(tmp_path: Path) -> None:
    log = tmp_path / "auth.log"
    log.write_text(FAILED + ACCEPTED, encoding="utf-8")
    source = _file_source(log)
    _, state = source.read_new({})

    log.write_text(ACCEPTED, encoding="utf-8")  # same inode, smaller size
    lines, _ = source.read_new(state)

    assert len(lines) == 1


def test_missing_file_raises_source_error(tmp_path: Path) -> None:
    with pytest.raises(SourceError, match="does not exist"):
        _file_source(tmp_path / "absent.log").read_new({})


def test_permission_error_raises_source_error(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    log = tmp_path / "auth.log"
    log.write_text(FAILED, encoding="utf-8")

    def deny(self: Path, *args: Any, **kwargs: Any) -> None:
        raise PermissionError(13, "denied", str(self))

    monkeypatch.setattr(Path, "open", deny)

    with pytest.raises(SourceError, match="permission denied"):
        _file_source(log).read_new({})


def test_oversized_line_without_newline_is_skipped_not_stuck(tmp_path: Path) -> None:
    log = tmp_path / "auth.log"
    log.write_text("x" * 64, encoding="utf-8")
    source = _file_source(log, max_bytes=16)

    _, state = source.read_new({})

    # A full buffer with no newline is skipped, so the next read does not wait forever.
    assert state["offset"] == 16


# --- journal ---------------------------------------------------------------


def _journal_entry(
    cursor: str, message: str, program: str = "sshd", micros: int = 1_790_000_000_000_000
) -> str:
    return json.dumps(
        {
            "__CURSOR": cursor,
            "__REALTIME_TIMESTAMP": str(micros),
            "SYSLOG_IDENTIFIER": program,
            "MESSAGE": message,
        }
    )


class FakeRunner:
    def __init__(self, stdout: str = "", returncode: int = 0, stderr: str = "") -> None:
        self.calls: list[list[str]] = []
        self._stdout = stdout
        self._returncode = returncode
        self._stderr = stderr

    def __call__(self, args: list[str]) -> subprocess.CompletedProcess[str]:
        self.calls.append(args)
        return subprocess.CompletedProcess(args, self._returncode, self._stdout, self._stderr)


def test_journal_first_run_uses_bootstrap_limit_and_saves_cursor() -> None:
    runner = FakeRunner(
        stdout="\n".join(
            [
                _journal_entry("c1", "Failed password for root from 203.0.113.50 port 1 ssh2"),
                _journal_entry("c2", "Accepted password for alice from 198.51.100.7 port 2 ssh2"),
            ]
        )
    )
    source = JournalSource(bootstrap_lines=25, runner=runner)

    lines, state = source.read_new({})

    assert [line.message.split()[0] for line in lines] == ["Failed", "Accepted"]
    assert state == {"cursor": "c2"}
    args = runner.calls[0]
    assert "--lines=25" in args
    assert "SYSLOG_IDENTIFIER=sshd-session" in args
    assert "SYSLOG_IDENTIFIER=sudo" in args


def test_journal_later_run_resumes_after_saved_cursor() -> None:
    runner = FakeRunner(
        stdout=_journal_entry("c3", "Accepted password for alice from 198.51.100.7 port 2 ssh2")
    )
    source = JournalSource(runner=runner)

    _, state = source.read_new({"cursor": "c2"})

    assert "--after-cursor=c2" in runner.calls[0]
    assert state == {"cursor": "c3"}


def test_journal_with_no_new_entries_keeps_previous_cursor() -> None:
    source = JournalSource(runner=FakeRunner(stdout=""))

    lines, state = source.read_new({"cursor": "c9"})

    assert lines == []
    assert state == {"cursor": "c9"}


def test_journal_command_failure_raises_source_error() -> None:
    runner = FakeRunner(returncode=1, stderr="Permission denied")
    source = JournalSource(runner=runner)

    with pytest.raises(SourceError, match="Permission denied"):
        source.read_new({})


def test_journal_skips_malformed_and_binary_entries() -> None:
    stdout = "\n".join(
        [
            "not json",
            json.dumps({"__CURSOR": "c1", "MESSAGE": [1, 2, 3], "SYSLOG_IDENTIFIER": "sshd"}),
            _journal_entry("c2", "Accepted password for alice from 198.51.100.7 port 2 ssh2"),
        ]
    )
    source = JournalSource(runner=FakeRunner(stdout=stdout))

    lines, state = source.read_new({})

    assert len(lines) == 1
    assert state == {"cursor": "c2"}
