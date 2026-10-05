"""``sentinelbot-detect``: read telemetry events (JSON Lines), write detections (JSON Lines).

Typical pipeline::

    sentinelbot-agent --once --collectors auth,processes,network | sentinelbot-detect --input -

With ``--redis-url`` (or ``SENTINEL_REDIS_URL``) the sliding windows and cooldowns are kept in
Redis, so brute-force attempts spread across several runs are still counted together.
"""

from __future__ import annotations

import argparse
import contextlib
import logging
import os
import sys
from collections.abc import Sequence
from pathlib import Path
from typing import TextIO

import redis
from pydantic import ValidationError
from sentinelbot_agent.logging_setup import configure_logging
from sentinelbot_agent.models import Event
from sentinelbot_agent.output import JsonLinesSink

from sentinelbot_detection.baseline import load_baseline, save_baseline
from sentinelbot_detection.engine import DetectionEngine
from sentinelbot_detection.rules import build_rules
from sentinelbot_detection.scoring import RiskScorer, load_risk_settings
from sentinelbot_detection.settings import DetectionConfigError, load_settings
from sentinelbot_detection.state import MemoryState, RedisState, StateStore

EXIT_OK = 0
EXIT_CONFIG_ERROR = 2

logger = logging.getLogger("sentinelbot_detection")


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="sentinelbot-detect",
        description="Run detection rules over telemetry events (JSON Lines).",
    )
    parser.add_argument("--input", default="-", help="event file, or '-' for stdin (default)")
    parser.add_argument(
        "--output", type=Path, help="write detections to this file (default stdout)"
    )
    parser.add_argument("--config", type=Path, help="TOML file with [detection] thresholds")
    parser.add_argument(
        "--baseline", type=Path, help="JSON file that stores the learned process/port baseline"
    )
    parser.add_argument(
        "--redis-url",
        default=os.environ.get("SENTINEL_REDIS_URL"),
        help="keep windows and cooldowns in Redis (default: SENTINEL_REDIS_URL, else memory)",
    )
    parser.add_argument(
        "--log-level", default="INFO", choices=["DEBUG", "INFO", "WARNING", "ERROR"]
    )
    return parser


def _state(redis_url: str | None) -> StateStore:
    if not redis_url:
        return MemoryState()
    state = RedisState.from_url(redis_url)
    state.ping()  # fail fast with a clear error instead of mid-stream
    return state


def main(argv: Sequence[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    configure_logging(args.log_level)

    try:
        settings = load_settings(args.config)
        risk_settings = load_risk_settings(args.config)
        baseline = load_baseline(args.baseline)
    except DetectionConfigError as exc:
        logger.error("invalid configuration: %s", exc)
        return EXIT_CONFIG_ERROR

    try:
        state = _state(args.redis_url)
    except redis.RedisError as exc:
        logger.error("cannot reach Redis: %s", exc)
        return EXIT_CONFIG_ERROR

    engine = DetectionEngine(build_rules(settings, baseline, state))
    scorer = RiskScorer(risk_settings, state)
    counts = {"events": 0, "invalid_lines": 0, "detections": 0}

    with contextlib.ExitStack() as stack:
        source: TextIO = (
            sys.stdin
            if args.input == "-"
            else stack.enter_context(open(args.input, encoding="utf-8"))
        )
        destination: TextIO = (
            stack.enter_context(args.output.open("a", encoding="utf-8"))
            if args.output is not None
            else sys.stdout
        )
        sink = JsonLinesSink(destination)

        for raw in source:
            line = raw.strip()
            if not line:
                continue
            try:
                event = Event.model_validate_json(line)
            except ValidationError:
                counts["invalid_lines"] += 1
                continue
            counts["events"] += 1
            for detection in engine.process(event):
                sink.emit(scorer.score(detection))
                counts["detections"] += 1

    if args.baseline is not None:
        save_baseline(args.baseline, baseline)
    logger.info("detection run complete", extra=counts)
    return EXIT_OK
