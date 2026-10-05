"""Log sources: systemd journal (preferred) and classic log files.

Each source reads only what is new since the state it was given, and returns the updated
state. The collector stores that state, which is what lets the agent resume after a
restart without duplicating events.
"""

from __future__ import annotations

import json
import logging
import shutil
import subprocess
from collections.abc import Callable
from dataclasses import dataclass
from datetime import UTC, datetime
from pathlib import Path
from typing import Any, Protocol

from sentinelbot_agent.auth.parsers import parse_syslog_line, resolve_syslog_timestamp

logger = logging.getLogger(__name__)

JOURNAL_IDENTIFIERS = ("sshd", "sshd-session", "sudo")
MAX_FILE_READ_BYTES = 1_048_576
JOURNAL_TIMEOUT_SECONDS = 30

SourceState = dict[str, Any]
JournalRunner = Callable[[list[str]], subprocess.CompletedProcess[str]]


class SourceError(Exception):
    """A log source cannot be read right now (missing, permission denied, command failed)."""


@dataclass(frozen=True, slots=True)
class RawLogLine:
    """A log message with its program name and UTC timestamp, before parsing."""

    timestamp: datetime
    program: str
    message: str


class LogSource(Protocol):
    """A readable log with resumable state."""

    @property
    def key(self) -> str:
        """Stable identifier used as the state key for this source."""

    def read_new(self, state: SourceState) -> tuple[list[RawLogLine], SourceState]:
        """Return lines not yet seen and the state to store for the next read."""


def _run_journalctl(args: list[str]) -> subprocess.CompletedProcess[str]:
    # Fixed argument list, no shell. journalctl only reads; no host state is changed.
    return subprocess.run(  # noqa: S603 - arguments are built from constants, not input
        args,
        capture_output=True,
        text=True,
        timeout=JOURNAL_TIMEOUT_SECONDS,
        check=False,
    )


class JournalSource:
    """Reads sshd and sudo entries from the systemd journal via ``journalctl``.

    The journal cursor is the resume point. On the first run only the last
    ``bootstrap_lines`` matching entries are read, so an old host does not flood the output.
    """

    key = "journal"

    def __init__(
        self,
        *,
        bootstrap_lines: int = 500,
        runner: JournalRunner = _run_journalctl,
        identifiers: tuple[str, ...] = JOURNAL_IDENTIFIERS,
    ) -> None:
        self._bootstrap_lines = bootstrap_lines
        self._runner = runner
        self._identifiers = identifiers

    def read_new(self, state: SourceState) -> tuple[list[RawLogLine], SourceState]:
        cursor = state.get("cursor")
        args = ["journalctl", "--no-pager", "--output=json"]
        if cursor:
            args.append(f"--after-cursor={cursor}")
        else:
            args.append(f"--lines={self._bootstrap_lines}")
        args.extend(f"SYSLOG_IDENTIFIER={name}" for name in self._identifiers)

        result = self._runner(args)
        if result.returncode != 0:
            detail = result.stderr.strip() or f"exit code {result.returncode}"
            raise SourceError(f"journalctl failed: {detail}")

        lines: list[RawLogLine] = []
        last_cursor: str | None = None
        for raw in result.stdout.splitlines():
            entry = _parse_journal_entry(raw)
            if entry is None:
                continue
            last_cursor = entry.get("__CURSOR", last_cursor)
            line = _to_raw_line(entry)
            if line is not None:
                lines.append(line)
        new_state = {"cursor": last_cursor} if last_cursor else dict(state)
        return lines, new_state


def _parse_journal_entry(raw: str) -> dict[str, Any] | None:
    try:
        entry = json.loads(raw)
    except json.JSONDecodeError:
        return None
    return entry if isinstance(entry, dict) else None


def _to_raw_line(entry: dict[str, Any]) -> RawLogLine | None:
    message = entry.get("MESSAGE")
    program = entry.get("SYSLOG_IDENTIFIER")
    realtime = entry.get("__REALTIME_TIMESTAMP")
    # journald sends MESSAGE as a list of bytes when it is not valid UTF-8; skip those.
    if not isinstance(message, str) or not isinstance(program, str) or not realtime:
        return None
    try:
        timestamp = datetime.fromtimestamp(int(realtime) / 1_000_000, UTC)
    except (TypeError, ValueError, OverflowError, OSError):
        return None
    return RawLogLine(timestamp, program, message)


class FileSource:
    """Tails a classic syslog file such as ``/var/log/auth.log``.

    State records the inode and byte offset. A changed inode means the file was rotated,
    and a smaller size means it was truncated; both restart reading from the beginning.
    Lines still being written (no trailing newline) are left for the next cycle.
    """

    def __init__(
        self,
        path: Path,
        *,
        now: Callable[[], datetime] = lambda: datetime.now(UTC),
        max_bytes: int = MAX_FILE_READ_BYTES,
    ) -> None:
        self._path = path
        self._now = now
        self._max_bytes = max_bytes

    @property
    def key(self) -> str:
        return f"file:{self._path}"

    def read_new(self, state: SourceState) -> tuple[list[RawLogLine], SourceState]:
        try:
            stat = self._path.stat()
        except FileNotFoundError as exc:
            raise SourceError(f"{self._path} does not exist") from exc
        except PermissionError as exc:
            raise SourceError(f"permission denied reading {self._path}") from exc

        offset = int(state.get("offset", 0))
        if state.get("inode") != stat.st_ino or stat.st_size < offset:
            offset = 0

        try:
            with self._path.open("rb") as handle:
                handle.seek(offset)
                data = handle.read(self._max_bytes)
        except PermissionError as exc:
            raise SourceError(f"permission denied reading {self._path}") from exc

        end = data.rfind(b"\n")
        if end == -1:
            # Either a partial line still being written, or one longer than the read limit.
            # The second case would block forever, so skip it once the buffer is full.
            skip = len(data) if len(data) >= self._max_bytes else 0
            return [], {"inode": stat.st_ino, "offset": offset + skip}

        complete = data[: end + 1].decode("utf-8", errors="replace")
        lines = self._parse_lines(complete)
        return lines, {"inode": stat.st_ino, "offset": offset + end + 1}

    def _parse_lines(self, text: str) -> list[RawLogLine]:
        now = self._now()
        lines: list[RawLogLine] = []
        for raw in text.splitlines():
            parsed = parse_syslog_line(raw)
            if parsed is None:
                continue
            try:
                timestamp = resolve_syslog_timestamp(parsed.timestamp_text, now)
            except ValueError:
                continue
            lines.append(RawLogLine(timestamp, parsed.program, parsed.message))
        return lines


def journalctl_available() -> bool:
    return shutil.which("journalctl") is not None
