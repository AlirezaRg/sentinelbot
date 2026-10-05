"""Engine routing and the CLI pipeline on synthetic event files."""

from __future__ import annotations

import json
import logging
from pathlib import Path

import pytest
from sentinelbot_agent.models import Event, EventType

from sentinelbot_detection.baseline import Baseline
from sentinelbot_detection.cli import EXIT_CONFIG_ERROR, EXIT_OK, main
from sentinelbot_detection.engine import DetectionEngine
from sentinelbot_detection.rules import Rule, SshBruteForceRule, build_rules
from sentinelbot_detection.settings import DetectionSettings
from tests.conftest import failed_login, network_snapshot, proc, process_snapshot


class ExplodingRule(Rule):
    rule_id = "exploding"
    event_types = frozenset({EventType.SSH_LOGIN_FAILED})

    def evaluate(self, event: Event) -> list[Event]:
        raise RuntimeError("bug in rule")


def test_failing_rule_is_isolated_and_others_still_run(caplog: pytest.LogCaptureFixture) -> None:
    engine = DetectionEngine(
        [
            ExplodingRule(DetectionSettings()),
            SshBruteForceRule(DetectionSettings(bruteforce_threshold=1)),
        ]
    )

    with caplog.at_level(logging.ERROR):
        detections = engine.process(failed_login(0))

    assert [d.event_type for d in detections] == [EventType.SSH_BRUTEFORCE_DETECTED]
    assert "rule failed" in caplog.text


def test_detections_are_not_fed_back_into_rules() -> None:
    rules = build_rules(DetectionSettings(bruteforce_threshold=1), Baseline())
    engine = DetectionEngine(rules)
    detection_events = engine.process(failed_login(0))

    for detection in detection_events:
        assert engine.process(detection) == []


def _write_events(path: Path, events: list[Event]) -> None:
    path.write_text("\n".join(e.model_dump_json() for e in events) + "\n", encoding="utf-8")


def _read_types(path: Path) -> list[str]:
    return [
        json.loads(line)["event_type"] for line in path.read_text(encoding="utf-8").splitlines()
    ]


def test_cli_turns_brute_force_stream_into_detection(tmp_path: Path) -> None:
    events_file = tmp_path / "events.jsonl"
    output = tmp_path / "detections.jsonl"
    _write_events(events_file, [failed_login(s) for s in range(5)])

    exit_code = main(["--input", str(events_file), "--output", str(output), "--log-level", "ERROR"])

    assert exit_code == EXIT_OK
    assert _read_types(output) == ["ssh_bruteforce_detected"]


def test_cli_skips_invalid_lines_without_failing(tmp_path: Path) -> None:
    events_file = tmp_path / "events.jsonl"
    output = tmp_path / "detections.jsonl"
    events_file.write_text(
        "garbage\n\n" + failed_login(0).model_dump_json() + "\n", encoding="utf-8"
    )

    assert (
        main(["--input", str(events_file), "--output", str(output), "--log-level", "ERROR"])
        == EXIT_OK
    )
    assert output.read_text(encoding="utf-8") == ""


def test_baseline_persists_across_runs(tmp_path: Path) -> None:
    baseline_file = tmp_path / "baseline.json"
    first_run = tmp_path / "run1.jsonl"
    second_run = tmp_path / "run2.jsonl"
    output = tmp_path / "out.jsonl"

    # Run 1 learns the normal root processes and ports; nothing alerts.
    _write_events(
        first_run,
        [
            process_snapshot(0, proc("sshd", exe="/usr/sbin/sshd")),
            network_snapshot(0, ("tcp", 22, "sshd")),
        ],
    )
    main(
        [
            "--input",
            str(first_run),
            "--output",
            str(output),
            "--baseline",
            str(baseline_file),
            "--log-level",
            "ERROR",
        ]
    )
    assert not output.exists() or output.read_text(encoding="utf-8") == ""

    # Run 2 sees a new root process and a new port, and both alert.
    _write_events(
        second_run,
        [
            process_snapshot(
                3600, proc("sshd", exe="/usr/sbin/sshd"), proc("implant", exe="/tmp/x", pid=9)
            ),
            network_snapshot(3600, ("tcp", 22, "sshd"), ("tcp", 4444, "nc")),
        ],
    )
    main(
        [
            "--input",
            str(second_run),
            "--output",
            str(output),
            "--baseline",
            str(baseline_file),
            "--log-level",
            "ERROR",
        ]
    )

    assert sorted(_read_types(output)) == sorted(
        ["privileged_process_detected", "unexpected_listening_port_detected"]
    )


def test_invalid_config_exits_with_error(tmp_path: Path) -> None:
    config = tmp_path / "detection.toml"
    config.write_text("[detection]\nnot_a_setting = 1\n", encoding="utf-8")

    assert main(["--config", str(config), "--log-level", "ERROR"]) == EXIT_CONFIG_ERROR


def test_corrupt_baseline_exits_with_error(tmp_path: Path) -> None:
    baseline = tmp_path / "baseline.json"
    baseline.write_text("{", encoding="utf-8")

    assert main(["--baseline", str(baseline), "--log-level", "ERROR"]) == EXIT_CONFIG_ERROR
