"""Risk scoring: factor arithmetic, clamping, severity bands, windows and configuration."""

from __future__ import annotations

from dataclasses import replace
from pathlib import Path
from typing import Any

import pytest
from sentinelbot_agent.models import Event, EventType, Severity

from sentinelbot_detection.cli import main
from sentinelbot_detection.scoring import RiskScorer, RiskSettings, load_risk_settings
from sentinelbot_detection.settings import DetectionConfigError
from tests.conftest import make_event

IP = "203.0.113.50"


def _detection(
    rule_id: str,
    seconds: float = 0,
    *,
    ip: str | None = IP,
    username: str | None = None,
    targets_root: bool = False,
) -> Event:
    return make_event(
        EventType.SSH_BRUTEFORCE_DETECTED,
        seconds=seconds,
        source_ip=ip,
        username=username,
        rule_id=rule_id,
        targets_root=targets_root,
    )


def _factor_names(scored: Event) -> list[str]:
    return [f["factor"] for f in scored.metadata["risk_factors"]]


def test_single_bruteforce_scores_its_base_points() -> None:
    scored = RiskScorer(RiskSettings()).score(_detection("ssh_bruteforce"))

    assert scored.metadata["risk_score"] == 40
    assert scored.severity is Severity.MEDIUM
    assert scored.metadata["base_severity"] == "info"


def test_rule_severity_is_a_floor_for_the_final_severity() -> None:
    high_rule = make_event(
        EventType.SSH_BRUTEFORCE_DETECTED,
        source_ip=IP,
        severity=Severity.HIGH,
        rule_id="ssh_bruteforce",
    )

    scored = RiskScorer(RiskSettings()).score(high_rule)  # score 40 would band as MEDIUM

    assert scored.metadata["risk_score"] == 40
    assert scored.severity is Severity.HIGH
    assert scored.metadata["base_severity"] == "high"


def test_root_targeting_adds_privilege_points() -> None:
    scored = RiskScorer(RiskSettings()).score(
        _detection("ssh_bruteforce", username="root", targets_root=True)
    )

    assert scored.metadata["risk_score"] == 55
    assert "privilege" in _factor_names(scored)


def test_repeated_detections_from_same_source_add_repetition() -> None:
    scorer = RiskScorer(RiskSettings())
    scorer.score(_detection("ssh_bruteforce", 0))
    second = scorer.score(_detection("ssh_bruteforce", 100))

    assert second.metadata["risk_score"] == 50
    assert "repetition" in _factor_names(second)


def test_repetition_is_capped() -> None:
    scorer = RiskScorer(RiskSettings())
    last = None
    for second in range(10):
        last = scorer.score(_detection("ssh_bruteforce", second))

    assert last is not None
    repetition = next(f for f in last.metadata["risk_factors"] if f["factor"] == "repetition")
    assert repetition["points"] == 30


def test_different_rules_from_same_source_add_combination() -> None:
    scorer = RiskScorer(RiskSettings())
    scorer.score(_detection("ssh_bruteforce", 0))
    combined = scorer.score(_detection("root_login", 60, username="root"))

    # root_login base 35 + combination 10 + privilege 15
    assert combined.metadata["risk_score"] == 60
    assert combined.severity is Severity.HIGH
    assert "combination" in _factor_names(combined)


def test_trusted_source_lowers_the_score() -> None:
    settings = RiskSettings(trusted_ips=frozenset({IP}))

    scored = RiskScorer(settings).score(_detection("ssh_bruteforce"))

    assert scored.metadata["risk_score"] == 10
    assert scored.severity is Severity.INFO


def test_known_bad_source_raises_the_score() -> None:
    settings = RiskSettings(known_bad_ips=frozenset({IP}))

    scored = RiskScorer(settings).score(_detection("ssh_bruteforce"))

    assert scored.metadata["risk_score"] == 65
    assert scored.severity is Severity.HIGH


def test_score_is_clamped_to_one_hundred() -> None:
    settings = RiskSettings(known_bad_ips=frozenset({IP}))
    scorer = RiskScorer(settings)
    for second in range(5):
        scorer.score(_detection("ssh_bruteforce", second, username="root", targets_root=True))
    # base 40 + repetition 30 (capped) + privilege 15 + known bad 25 = 110, clamped to 100
    scored = scorer.score(_detection("ssh_bruteforce", 6, username="root", targets_root=True))

    assert scored.metadata["risk_score"] == 100
    assert scored.severity is Severity.CRITICAL


def test_score_is_clamped_to_zero() -> None:
    settings = RiskSettings(trusted_ips=frozenset({IP}), base_points={"ssh_bruteforce": 10})

    scored = RiskScorer(settings).score(_detection("ssh_bruteforce"))

    assert scored.metadata["risk_score"] == 0


def test_history_expires_after_the_window() -> None:
    scorer = RiskScorer(replace(RiskSettings(), window_seconds=100))
    scorer.score(_detection("ssh_bruteforce", 0))
    later = scorer.score(_detection("ssh_bruteforce", 500))

    assert "repetition" not in _factor_names(later)


def test_sources_are_scored_independently() -> None:
    scorer = RiskScorer(RiskSettings())
    scorer.score(_detection("ssh_bruteforce", 0, ip="203.0.113.1"))
    other = scorer.score(_detection("ssh_bruteforce", 1, ip="203.0.113.2"))

    assert other.metadata["risk_score"] == 40


@pytest.mark.parametrize(
    ("score", "expected"),
    [
        (19, Severity.INFO),
        (20, Severity.LOW),
        (39, Severity.LOW),
        (40, Severity.MEDIUM),
        (59, Severity.MEDIUM),
        (60, Severity.HIGH),
        (79, Severity.HIGH),
        (80, Severity.CRITICAL),
    ],
)
def test_severity_bands_follow_configured_edges(score: int, expected: Severity) -> None:
    from sentinelbot_detection.scoring import _band

    assert _band(score, (20, 40, 60, 80)) is expected


def test_factors_explain_the_total() -> None:
    scored = RiskScorer(RiskSettings()).score(
        _detection("ssh_bruteforce", username="root", targets_root=True)
    )

    assert (
        sum(f["points"] for f in scored.metadata["risk_factors"]) == scored.metadata["risk_score"]
    )


def test_risk_settings_load_from_toml(tmp_path: Path) -> None:
    path = tmp_path / "config.toml"
    path.write_text(
        "[risk]\n"
        "repeat_points = 5\n"
        'trusted_ips = ["198.51.100.7"]\n'
        "band_edges = [10, 30, 50, 70]\n"
        "[risk.base_points]\n"
        "ssh_bruteforce = 50\n",
        encoding="utf-8",
    )

    settings = load_risk_settings(path)

    assert settings.repeat_points == 5
    assert settings.trusted_ips == frozenset({"198.51.100.7"})
    assert settings.band_edges == (10, 30, 50, 70)
    assert settings.base_points["ssh_bruteforce"] == 50


@pytest.mark.parametrize(
    "body",
    [
        "[risk]\nrepeat_pionts = 5\n",
        "[risk]\nband_edges = [60, 40, 20, 80]\n",
        '[risk]\ntrusted_ips = ["not-an-ip"]\n',
        "[risk.base_points]\nno_such_rule = 5\n",
    ],
)
def test_invalid_risk_config_is_rejected(tmp_path: Path, body: str) -> None:
    path = tmp_path / "config.toml"
    path.write_text(body, encoding="utf-8")

    with pytest.raises(DetectionConfigError):
        load_risk_settings(path)


def test_cli_outputs_risk_score_on_every_detection(tmp_path: Path) -> None:
    import json

    events_file = tmp_path / "events.jsonl"
    output = tmp_path / "out.jsonl"
    lines = [
        make_event(
            EventType.SSH_LOGIN_FAILED, seconds=s, source_ip=IP, username="root", targets_root=True
        ).model_dump_json()
        for s in range(5)
    ]
    events_file.write_text("\n".join(lines) + "\n", encoding="utf-8")

    assert main(["--input", str(events_file), "--output", str(output), "--log-level", "ERROR"]) == 0

    records: list[dict[str, Any]] = [
        json.loads(x) for x in output.read_text(encoding="utf-8").splitlines()
    ]
    assert len(records) == 1
    assert records[0]["metadata"]["risk_score"] == 55
    # The rule's own severity (high) is the floor, even though the score (55) bands as medium.
    assert records[0]["severity"] == "high"
