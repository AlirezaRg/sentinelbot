"""Transparent detection rules. Each rule is a small class with explicit thresholds.

Rules use event timestamps, not wall-clock time, so a recorded event file replays the
same way every time. Detections are emitted as ordinary ``Event`` objects with
``source="detection"`` and ``metadata.rule_id``, so the same pipeline stores and ships them.
Windows and cooldowns come from a ``StateStore``: in memory by default, or Redis.
"""

from __future__ import annotations

from abc import ABC, abstractmethod
from ipaddress import IPv4Address, IPv6Address
from typing import Any

from sentinelbot_agent.models import Event, EventType, Severity

from sentinelbot_detection.baseline import Baseline
from sentinelbot_detection.settings import DetectionSettings
from sentinelbot_detection.state import CooldownLike, MemoryState, StateStore, WindowLike

MAX_LISTED_USERS = 50


class Rule(ABC):
    """A rule consumes the event types in ``event_types`` and returns detections."""

    rule_id: str
    event_types: frozenset[EventType]

    def __init__(self, settings: DetectionSettings, state: StateStore | None = None) -> None:
        self._settings = settings
        self._state: StateStore = state if state is not None else MemoryState()

    @abstractmethod
    def evaluate(self, event: Event) -> list[Event]:
        """Return detections for one event. Must not raise for ordinary input."""

    def _detection(
        self,
        event: Event,
        event_type: EventType,
        severity: Severity,
        message: str,
        metadata: dict[str, object],
        *,
        username: str | None = None,
        source_ip: IPv4Address | IPv6Address | None = None,
    ) -> Event:
        return Event(
            host_id=event.host_id,
            timestamp=event.timestamp,
            event_type=event_type,
            severity=severity,
            source="detection",
            message=message,
            username=username,
            source_ip=source_ip,
            metadata={"rule_id": self.rule_id, **metadata},
        )


class SshBruteForceRule(Rule):
    """Many failed SSH logins from one source within a time window."""

    rule_id = "ssh_bruteforce"
    event_types = frozenset({EventType.SSH_LOGIN_FAILED})

    def __init__(self, settings: DetectionSettings, state: StateStore | None = None) -> None:
        super().__init__(settings, state)
        self._attempts: WindowLike = self._state.window(
            "ssh_bruteforce.attempts", settings.bruteforce_window_seconds, settings.max_tracked_keys
        )
        self._cooldown: CooldownLike = self._state.cooldown(
            "ssh_bruteforce.cooldown", settings.cooldown_seconds, settings.max_tracked_keys
        )

    def evaluate(self, event: Event) -> list[Event]:
        if event.source_ip is None:
            return []
        source = str(event.source_ip)
        attempts = self._attempts.add(
            source,
            event.timestamp,
            (event.username, bool(event.metadata.get("targets_root"))),
        )
        if len(attempts) < self._settings.bruteforce_threshold:
            return []
        if not self._cooldown.allow(source, event.timestamp):
            return []
        users = sorted({user for user, _ in attempts if user})[:MAX_LISTED_USERS]
        return [
            self._detection(
                event,
                EventType.SSH_BRUTEFORCE_DETECTED,
                Severity.HIGH,
                f"Possible SSH brute-force from {source}: {len(attempts)} failed attempts "
                f"within {self._settings.bruteforce_window_seconds}s",
                {
                    "failed_attempts": len(attempts),
                    "threshold": self._settings.bruteforce_threshold,
                    "window_seconds": self._settings.bruteforce_window_seconds,
                    "targeted_users": users,
                    "targets_root": any(root for _, root in attempts),
                },
                source_ip=event.source_ip,
            )
        ]


class SuspiciousRootLoginRule(Rule):
    """A successful direct root login over SSH."""

    rule_id = "root_login"
    event_types = frozenset({EventType.SSH_ROOT_LOGIN})

    def __init__(self, settings: DetectionSettings, state: StateStore | None = None) -> None:
        super().__init__(settings, state)
        self._cooldown: CooldownLike = self._state.cooldown(
            "root_login.cooldown", settings.cooldown_seconds, settings.max_tracked_keys
        )

    def evaluate(self, event: Event) -> list[Event]:
        key = (str(event.source_ip), event.username)
        if not self._cooldown.allow(key, event.timestamp):
            return []
        return [
            self._detection(
                event,
                EventType.SUSPICIOUS_ROOT_LOGIN_DETECTED,
                Severity.HIGH,
                f"Direct root SSH login from {event.source_ip}",
                {"auth_method": event.metadata.get("auth_method")},
                username="root",
                source_ip=event.source_ip,
            )
        ]


class AuthBurstRule(Rule):
    """Unusually many authentication attempts on one host within a time window."""

    rule_id = "auth_burst"
    event_types = frozenset(
        {EventType.SSH_LOGIN_FAILED, EventType.SSH_LOGIN_SUCCESS, EventType.SSH_ROOT_LOGIN}
    )

    def __init__(self, settings: DetectionSettings, state: StateStore | None = None) -> None:
        super().__init__(settings, state)
        self._events: WindowLike = self._state.window(
            "auth_burst.events", settings.auth_burst_window_seconds, settings.max_tracked_keys
        )
        self._cooldown: CooldownLike = self._state.cooldown(
            "auth_burst.cooldown", settings.cooldown_seconds, settings.max_tracked_keys
        )

    def evaluate(self, event: Event) -> list[Event]:
        window = self._events.add(
            event.host_id, event.timestamp, event.event_type is EventType.SSH_LOGIN_FAILED
        )
        if len(window) < self._settings.auth_burst_threshold:
            return []
        if not self._cooldown.allow(event.host_id, event.timestamp):
            return []
        failed = sum(window)
        return [
            self._detection(
                event,
                EventType.AUTH_BURST_DETECTED,
                Severity.MEDIUM,
                f"Authentication burst: {len(window)} attempts within "
                f"{self._settings.auth_burst_window_seconds}s ({failed} failed)",
                {
                    "attempts": len(window),
                    "failed_attempts": failed,
                    "threshold": self._settings.auth_burst_threshold,
                    "window_seconds": self._settings.auth_burst_window_seconds,
                },
            )
        ]


class PrivilegedProcessRule(Rule):
    """A root-owned process whose (name, executable) was not in the learned baseline.

    The first snapshot ever seen is recorded as the baseline and does not alert. The
    snapshot is capped to the top processes by CPU, so the baseline may miss quiet root
    processes. Those can alert later, which is noise but not blindness.
    """

    rule_id = "privileged_process"
    event_types = frozenset({EventType.PROCESS_SNAPSHOT})

    def __init__(
        self,
        settings: DetectionSettings,
        baseline: Baseline,
        state: StateStore | None = None,
    ) -> None:
        super().__init__(settings, state)
        self._baseline = baseline

    def evaluate(self, event: Event) -> list[Event]:
        roots = [
            proc
            for proc in event.metadata.get("processes", [])
            if proc.get("username") == "root" and proc.get("name") and not _is_kernel_thread(proc)
        ]
        if not self._baseline.processes_learned:
            self._baseline.processes.update((proc["name"], proc.get("exe")) for proc in roots)
            self._baseline.processes_learned = True
            return []

        detections: list[Event] = []
        for proc in roots:
            key = (proc["name"], proc.get("exe"))
            if key in self._baseline.processes:
                continue
            self._baseline.processes.add(key)
            detections.append(
                self._detection(
                    event,
                    EventType.PRIVILEGED_PROCESS_DETECTED,
                    Severity.MEDIUM,
                    f"New root-owned process observed: {proc['name']}",
                    {
                        "pid": proc.get("pid"),
                        "ppid": proc.get("ppid"),
                        "name": proc["name"],
                        "exe": proc.get("exe"),
                    },
                    username="root",
                )
            )
            if len(detections) >= self._settings.privileged_process_max_per_event:
                break
        return detections


class UnexpectedListeningPortRule(Rule):
    """A listening port outside the configured allowlist, or new since the baseline.

    With ``allowed_listening_ports`` set, only the allowlist is checked. Otherwise the first
    snapshot is the baseline and later new ports alert.
    """

    rule_id = "unexpected_port"
    event_types = frozenset({EventType.NETWORK_SNAPSHOT})

    def __init__(
        self,
        settings: DetectionSettings,
        baseline: Baseline,
        state: StateStore | None = None,
    ) -> None:
        super().__init__(settings, state)
        self._baseline = baseline
        self._cooldown: CooldownLike = self._state.cooldown(
            "unexpected_port.cooldown", settings.cooldown_seconds, settings.max_tracked_keys
        )

    def evaluate(self, event: Event) -> list[Event]:
        listening = event.metadata.get("listening_ports", [])
        owners: dict[tuple[str, int], dict[str, object]] = {}
        for record in listening:
            port = record.get("local_port")
            if isinstance(port, int):
                owners.setdefault((record["protocol"], port), record)
        observed = set(owners)

        allowed = self._settings.allowed_listening_ports
        if allowed:
            candidates = {key for key in observed if key[1] not in allowed}
        else:
            if not self._baseline.ports_learned:
                self._baseline.listening_ports.update(observed)
                self._baseline.ports_learned = True
                return []
            candidates = observed - self._baseline.listening_ports

        detections: list[Event] = []
        for protocol, port in sorted(candidates):
            if not self._cooldown.allow((protocol, port), event.timestamp):
                continue
            owner = owners[(protocol, port)]
            detections.append(
                self._detection(
                    event,
                    EventType.UNEXPECTED_LISTENING_PORT_DETECTED,
                    Severity.MEDIUM,
                    f"Unexpected {protocol} listening port {port}",
                    {
                        "protocol": protocol,
                        "port": port,
                        "process": owner.get("process"),
                        "pid": owner.get("pid"),
                        "mode": "allowlist" if allowed else "baseline",
                    },
                )
            )
            self._baseline.listening_ports.add((protocol, port))
        return detections


KTHREADD_PID = 2


def _is_kernel_thread(proc: dict[str, Any]) -> bool:
    """Linux kernel threads (kworker, ksoftirqd, ...) are children of kthreadd (pid 2).

    They have no executable and their names change constantly, so alerting on them is noise.
    """
    return proc.get("ppid") == KTHREADD_PID or proc.get("pid") == KTHREADD_PID


def build_rules(
    settings: DetectionSettings,
    baseline: Baseline,
    state: StateStore | None = None,
) -> list[Rule]:
    """Instantiate the enabled rules in a fixed order, sharing one state store."""
    rules: list[Rule] = []
    if "ssh_bruteforce" in settings.enabled_rules:
        rules.append(SshBruteForceRule(settings, state))
    if "root_login" in settings.enabled_rules:
        rules.append(SuspiciousRootLoginRule(settings, state))
    if "auth_burst" in settings.enabled_rules:
        rules.append(AuthBurstRule(settings, state))
    if "privileged_process" in settings.enabled_rules:
        rules.append(PrivilegedProcessRule(settings, baseline, state))
    if "unexpected_port" in settings.enabled_rules:
        rules.append(UnexpectedListeningPortRule(settings, baseline, state))
    return rules
