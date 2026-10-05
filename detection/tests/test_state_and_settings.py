"""Sliding windows, cooldowns, baseline persistence and settings validation."""

from __future__ import annotations

from pathlib import Path

import pytest

from sentinelbot_detection.baseline import Baseline, load_baseline, save_baseline
from sentinelbot_detection.settings import DetectionConfigError, DetectionSettings, load_settings
from sentinelbot_detection.windows import Cooldown, SlidingWindow
from tests.conftest import at


def test_sliding_window_expires_old_entries() -> None:
    window: SlidingWindow[int] = SlidingWindow(window_seconds=10, max_keys=100)

    window.add("k", at(0), 1)
    assert window.add("k", at(5), 2) == [1, 2]
    assert window.add("k", at(12), 3) == [2, 3]  # the entry at t=0 is now older than 10s


def test_sliding_window_evicts_least_recent_key_at_cap() -> None:
    window: SlidingWindow[int] = SlidingWindow(window_seconds=100, max_keys=2)
    window.add("a", at(0), 1)
    window.add("b", at(1), 1)
    window.add("c", at(2), 1)  # "a" is the least recently active key

    assert window.add("a", at(3), 1) == [1]  # "a" was evicted, so it starts fresh


def test_cooldown_blocks_until_period_has_passed() -> None:
    cooldown = Cooldown(period_seconds=60, max_keys=100)

    assert cooldown.allow("k", at(0)) is True
    assert cooldown.allow("k", at(59)) is False
    assert cooldown.allow("k", at(60)) is True


def test_cooldown_is_per_key() -> None:
    cooldown = Cooldown(period_seconds=60, max_keys=100)
    cooldown.allow("a", at(0))

    assert cooldown.allow("b", at(1)) is True


def test_baseline_round_trips_through_json(tmp_path: Path) -> None:
    path = tmp_path / "baseline.json"
    baseline = Baseline(
        processes={("sshd", "/usr/sbin/sshd"), ("cron", None)},
        listening_ports={("tcp", 22), ("udp", 5353)},
        processes_learned=True,
        ports_learned=True,
    )

    save_baseline(path, baseline)

    assert load_baseline(path) == baseline


def test_missing_baseline_starts_empty(tmp_path: Path) -> None:
    assert load_baseline(tmp_path / "none.json") == Baseline()


def test_corrupt_baseline_is_an_error_not_a_silent_reset(tmp_path: Path) -> None:
    path = tmp_path / "baseline.json"
    path.write_text("{broken", encoding="utf-8")

    with pytest.raises(DetectionConfigError, match="corrupt"):
        load_baseline(path)


def test_settings_load_from_toml(tmp_path: Path) -> None:
    path = tmp_path / "detection.toml"
    path.write_text(
        "[detection]\n"
        "bruteforce_threshold = 10\n"
        "allowed_listening_ports = [22, 443]\n"
        'enabled_rules = ["ssh_bruteforce", "root_login"]\n',
        encoding="utf-8",
    )

    settings = load_settings(path)

    assert settings.bruteforce_threshold == 10
    assert settings.allowed_listening_ports == frozenset({22, 443})
    assert settings.enabled_rules == frozenset({"ssh_bruteforce", "root_login"})


def test_unknown_setting_is_rejected(tmp_path: Path) -> None:
    path = tmp_path / "detection.toml"
    path.write_text("[detection]\nbruteforce_treshold = 10\n", encoding="utf-8")

    with pytest.raises(DetectionConfigError, match="bruteforce_treshold"):
        load_settings(path)


@pytest.mark.parametrize(
    "kwargs",
    [
        {"bruteforce_threshold": 0},
        {"cooldown_seconds": -1},
        {"enabled_rules": frozenset({"telepathy"})},
        {"allowed_listening_ports": frozenset({70000})},
    ],
)
def test_invalid_values_are_rejected(kwargs: dict[str, object]) -> None:
    with pytest.raises(DetectionConfigError):
        DetectionSettings(**kwargs)  # type: ignore[arg-type]


def test_defaults_match_spec_examples() -> None:
    settings = DetectionSettings()

    assert settings.bruteforce_threshold == 5
    assert settings.bruteforce_window_seconds == 300
