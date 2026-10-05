"""Each detection rule: thresholds, windows, cooldowns and learning behaviour."""

from __future__ import annotations

from dataclasses import replace

from sentinelbot_agent.models import Event, EventType, Severity

from sentinelbot_detection.baseline import Baseline
from sentinelbot_detection.rules import (
    AuthBurstRule,
    PrivilegedProcessRule,
    SshBruteForceRule,
    SuspiciousRootLoginRule,
    UnexpectedListeningPortRule,
)
from sentinelbot_detection.settings import DetectionSettings
from tests.conftest import failed_login, make_event, network_snapshot, proc, process_snapshot

SETTINGS = DetectionSettings()


def _types(detections: list[Event]) -> list[EventType]:
    return [d.event_type for d in detections]


# --- SSH brute force -------------------------------------------------------


def test_fifth_failure_in_window_triggers_bruteforce_detection() -> None:
    rule = SshBruteForceRule(SETTINGS)
    results = []
    for second in range(5):
        results.extend(rule.evaluate(failed_login(second * 10)))

    assert _types(results) == [EventType.SSH_BRUTEFORCE_DETECTED]
    (detection,) = results
    assert detection.severity is Severity.HIGH
    assert detection.source == "detection"
    assert str(detection.source_ip) == "203.0.113.50"
    assert detection.metadata["failed_attempts"] == 5
    assert detection.metadata["targets_root"] is True
    assert detection.metadata["rule_id"] == "ssh_bruteforce"


def test_four_failures_do_not_trigger() -> None:
    rule = SshBruteForceRule(SETTINGS)
    results = [rule.evaluate(failed_login(s)) for s in range(4)]

    assert all(r == [] for r in results)


def test_failures_outside_window_do_not_accumulate() -> None:
    rule = SshBruteForceRule(SETTINGS)
    results = []
    for second in range(0, 5 * 400, 400):  # one failure every 400s, window is 300s
        results.extend(rule.evaluate(failed_login(second)))

    assert results == []


def test_different_sources_are_counted_separately() -> None:
    rule = SshBruteForceRule(SETTINGS)
    results = []
    for second in range(5):
        results.extend(rule.evaluate(failed_login(second, ip=f"203.0.113.{second + 1}")))

    assert results == []


def test_repeat_detection_is_suppressed_by_cooldown_then_allowed_again() -> None:
    rule = SshBruteForceRule(SETTINGS)
    for second in range(5):
        rule.evaluate(failed_login(second))
    # Sixth failure is still inside the cooldown.
    assert rule.evaluate(failed_login(6)) == []
    # After the cooldown, a fresh burst fires again.
    later = [rule.evaluate(failed_login(1000 + s)) for s in range(5)]
    assert _types(sum(later, [])) == [EventType.SSH_BRUTEFORCE_DETECTED]


def test_successful_login_without_source_ip_is_ignored() -> None:
    rule = SshBruteForceRule(SETTINGS)
    assert rule.evaluate(make_event(EventType.SSH_LOGIN_FAILED, seconds=1)) == []


def test_threshold_is_configurable() -> None:
    rule = SshBruteForceRule(replace(SETTINGS, bruteforce_threshold=2))
    results = [rule.evaluate(failed_login(s)) for s in range(2)]

    assert _types(results[-1]) == [EventType.SSH_BRUTEFORCE_DETECTED]


# --- root login ------------------------------------------------------------


def test_root_login_is_flagged_high() -> None:
    rule = SuspiciousRootLoginRule(SETTINGS)
    event = make_event(
        EventType.SSH_ROOT_LOGIN,
        seconds=1,
        source_ip="198.51.100.8",
        username="root",
        severity=Severity.MEDIUM,
        auth_method="password",
    )

    (detection,) = rule.evaluate(event)

    assert detection.event_type is EventType.SUSPICIOUS_ROOT_LOGIN_DETECTED
    assert detection.severity is Severity.HIGH
    assert detection.username == "root"


def test_repeated_root_login_from_same_source_is_deduplicated() -> None:
    rule = SuspiciousRootLoginRule(SETTINGS)
    event = make_event(
        EventType.SSH_ROOT_LOGIN, seconds=1, source_ip="198.51.100.8", username="root"
    )

    assert len(rule.evaluate(event)) == 1
    assert rule.evaluate(event) == []


# --- auth burst ------------------------------------------------------------


def test_auth_burst_counts_all_attempts_on_a_host() -> None:
    rule = AuthBurstRule(replace(SETTINGS, auth_burst_threshold=3))
    results = []
    for second, ip in enumerate(["203.0.113.1", "203.0.113.2", "203.0.113.3"]):
        results.extend(rule.evaluate(failed_login(second, ip=ip)))

    assert _types(results) == [EventType.AUTH_BURST_DETECTED]
    assert results[0].metadata["attempts"] == 3
    assert results[0].severity is Severity.MEDIUM


def test_non_auth_events_are_not_routed_to_burst_rule() -> None:
    assert EventType.SUDO_COMMAND not in AuthBurstRule.event_types


# --- privileged process ----------------------------------------------------


def test_first_snapshot_is_learned_not_alerted() -> None:
    baseline = Baseline()
    rule = PrivilegedProcessRule(SETTINGS, baseline)

    assert rule.evaluate(process_snapshot(0, proc("sshd", exe="/usr/sbin/sshd"))) == []
    assert baseline.processes_learned is True
    assert ("sshd", "/usr/sbin/sshd") in baseline.processes


def test_new_root_process_after_learning_is_flagged_once() -> None:
    baseline = Baseline()
    rule = PrivilegedProcessRule(SETTINGS, baseline)
    rule.evaluate(process_snapshot(0, proc("sshd", exe="/usr/sbin/sshd")))

    detections = rule.evaluate(
        process_snapshot(60, proc("sshd", exe="/usr/sbin/sshd"), proc("nc", exe="/tmp/nc", pid=42))
    )

    assert _types(detections) == [EventType.PRIVILEGED_PROCESS_DETECTED]
    assert detections[0].metadata["name"] == "nc"
    assert detections[0].metadata["pid"] == 42
    assert detections[0].metadata["exe"] == "/tmp/nc"
    assert rule.evaluate(process_snapshot(120, proc("nc", exe="/tmp/nc", pid=42))) == []


def test_kernel_threads_are_ignored_because_their_names_change() -> None:
    baseline = Baseline(processes_learned=True)
    rule = PrivilegedProcessRule(SETTINGS, baseline)
    kworker = {"pid": 71, "ppid": 2, "name": "kworker/3:1-events", "username": "root", "exe": None}

    assert rule.evaluate(process_snapshot(0, kworker)) == []
    assert baseline.processes == set()


def test_non_root_processes_are_ignored() -> None:
    baseline = Baseline(processes_learned=True)
    rule = PrivilegedProcessRule(SETTINGS, baseline)

    assert rule.evaluate(process_snapshot(0, proc("firefox", user="alice"))) == []


def test_privileged_detections_are_capped_per_snapshot() -> None:
    baseline = Baseline(processes_learned=True)
    rule = PrivilegedProcessRule(replace(SETTINGS, privileged_process_max_per_event=2), baseline)
    many = [proc(f"svc{i}", exe=f"/opt/svc{i}") for i in range(10)]

    assert len(rule.evaluate(process_snapshot(0, *many))) == 2


# --- unexpected listening port ---------------------------------------------


def test_port_outside_allowlist_is_flagged() -> None:
    settings = replace(SETTINGS, allowed_listening_ports=frozenset({22, 443}))
    rule = UnexpectedListeningPortRule(settings, Baseline())

    detections = rule.evaluate(network_snapshot(0, ("tcp", 22, "sshd"), ("tcp", 4444, "nc")))

    assert _types(detections) == [EventType.UNEXPECTED_LISTENING_PORT_DETECTED]
    assert detections[0].metadata["port"] == 4444
    assert detections[0].metadata["process"] == "nc"
    assert detections[0].metadata["mode"] == "allowlist"


def test_baseline_mode_learns_first_snapshot_then_flags_new_ports() -> None:
    baseline = Baseline()
    rule = UnexpectedListeningPortRule(SETTINGS, baseline)

    assert rule.evaluate(network_snapshot(0, ("tcp", 22, "sshd"))) == []
    detections = rule.evaluate(network_snapshot(60, ("tcp", 22, "sshd"), ("tcp", 8080, "python3")))

    assert [d.metadata["port"] for d in detections] == [8080]
    assert detections[0].metadata["mode"] == "baseline"


def test_same_port_is_not_reported_twice_in_cooldown() -> None:
    settings = replace(SETTINGS, allowed_listening_ports=frozenset({22}))
    rule = UnexpectedListeningPortRule(settings, Baseline())

    assert len(rule.evaluate(network_snapshot(0, ("tcp", 9999, "x")))) == 1
    assert rule.evaluate(network_snapshot(30, ("tcp", 9999, "x"))) == []
