"""Pure parsers for sshd and sudo log messages.

Only the fields needed for authentication telemetry are extracted. Passwords never
appear in these logs, and sudo commands are reduced to the executable name, so no
command arguments are stored.
"""

from __future__ import annotations

import ipaddress
import re
from dataclasses import dataclass, field
from datetime import datetime
from ipaddress import IPv4Address, IPv6Address
from pathlib import PurePosixPath
from typing import Any

from sentinelbot_agent.models import EventType, Severity

MAX_FIELD_LENGTH = 255

# sshd logs auth results from "sshd" on older OpenSSH and "sshd-session" on 9.8+ (Debian 13).
SSHD_PROGRAMS = frozenset({"sshd", "sshd-session"})
SUDO_PROGRAMS = frozenset({"sudo"})

_ACCEPTED = re.compile(
    r"Accepted (?P<method>\S+) for (?P<user>\S+) from (?P<ip>\S+) port (?P<port>\d+)"
)
_FAILED = re.compile(
    r"Failed (?P<method>\S+) for (?:invalid user )?(?P<user>\S+) "
    r"from (?P<ip>\S+) port (?P<port>\d+)"
)
_SUDO = re.compile(
    r"(?P<user>\S+) : TTY=(?P<tty>[^;]+?) ; .*?USER=(?P<target>\S+) ; COMMAND=(?P<command>.+)$"
)


@dataclass(frozen=True, slots=True)
class AuthRecord:
    """An authentication-relevant log message, ready to become an ``Event``."""

    event_type: EventType
    severity: Severity
    message: str
    username: str | None
    source_ip: IPv4Address | IPv6Address | None
    metadata: dict[str, Any] = field(default_factory=dict)


def parse_auth_message(program: str, message: str) -> AuthRecord | None:
    """Return an ``AuthRecord`` for a relevant sshd/sudo message, otherwise ``None``."""
    if program in SSHD_PROGRAMS:
        return _parse_sshd(message)
    if program in SUDO_PROGRAMS:
        return _parse_sudo(message)
    return None


def _parse_sshd(message: str) -> AuthRecord | None:
    # "Invalid user X from IP" is deliberately ignored: sshd logs it together with a
    # "Failed ... for invalid user X" line for the same attempt, and counting both would
    # double every brute-force attempt.
    if match := _ACCEPTED.match(message):
        user = _clip(match["user"])
        ip = _valid_ip(match["ip"])
        metadata = {
            "auth_method": _clip(match["method"]),
            "port": int(match["port"]),
            "targets_root": user == "root",
        }
        if user == "root":
            return AuthRecord(
                EventType.SSH_ROOT_LOGIN,
                Severity.MEDIUM,
                "Direct root SSH login succeeded",
                user,
                ip,
                metadata,
            )
        return AuthRecord(
            EventType.SSH_LOGIN_SUCCESS,
            Severity.INFO,
            f"Successful SSH login for {user}",
            user,
            ip,
            metadata,
        )

    if match := _FAILED.match(message):
        user = _clip(match["user"])
        ip = _valid_ip(match["ip"])
        metadata = {
            "auth_method": _clip(match["method"]),
            "port": int(match["port"]),
            "targets_root": user == "root",
            "invalid_user": "invalid user" in message,
        }
        return AuthRecord(
            EventType.SSH_LOGIN_FAILED,
            Severity.LOW,
            f"Failed SSH authentication for {user}",
            user,
            ip,
            metadata,
        )
    return None


def _parse_sudo(message: str) -> AuthRecord | None:
    if not (match := _SUDO.match(message)):
        return None
    user = _clip(match["user"])
    target = _clip(match["target"])
    command = match["command"].split()
    executable = _clip(PurePosixPath(command[0]).name) if command else None
    metadata = {
        "target_user": target,
        "tty": _clip(match["tty"].strip()),
        "executable": executable,
    }
    return AuthRecord(
        EventType.SUDO_COMMAND,
        Severity.INFO,
        f"{user} ran sudo as {target}",
        user,
        None,
        metadata,
    )


def _valid_ip(raw: str) -> IPv4Address | IPv6Address | None:
    """Return the address when it parses as IPv4/IPv6, otherwise ``None``."""
    try:
        return ipaddress.ip_address(raw)
    except ValueError:
        return None


def _clip(value: str) -> str:
    """Bound attacker-influenced strings so they always fit the Event schema."""
    return value[:MAX_FIELD_LENGTH]


_SYSLOG_LINE = re.compile(
    r"^(?P<ts>[A-Z][a-z]{2} +\d{1,2} \d{2}:\d{2}:\d{2}) (?P<host>\S+) "
    r"(?P<prog>[^\[:\s]+)(?:\[\d+\])?: +(?P<msg>.*)$"
)


@dataclass(frozen=True, slots=True)
class SyslogLine:
    """One line of a classic syslog file (``/var/log/auth.log``)."""

    timestamp_text: str
    program: str
    message: str


def parse_syslog_line(line: str) -> SyslogLine | None:
    """Split a classic syslog line into timestamp, program and message."""
    if not (match := _SYSLOG_LINE.match(line.rstrip("\n"))):
        return None
    return SyslogLine(match["ts"], match["prog"], match["msg"])


def resolve_syslog_timestamp(text: str, now: datetime) -> datetime:
    """Turn ``Oct  4 09:06:27`` into an aware UTC datetime.

    Syslog omits the year and uses local time. We assume the current year, and fall back
    to the previous year when that would place the entry more than a day in the future
    (for example a December entry read in January).
    """
    local_now = now.astimezone()
    normalized = " ".join(text.split())
    parsed = datetime.strptime(f"{local_now.year} {normalized}", "%Y %b %d %H:%M:%S")
    candidate = parsed.replace(tzinfo=local_now.tzinfo)
    if candidate.timestamp() > now.timestamp() + 86_400:
        candidate = candidate.replace(year=candidate.year - 1)
    return candidate.astimezone(now.tzinfo)
