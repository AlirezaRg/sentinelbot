"""Command-line entry point: ``sentinelbot-agent`` / ``python -m sentinelbot_agent``.

Events go to the API when ``SENTINEL_API_URL`` is set, otherwise to stdout (or ``--output``).
"""

from __future__ import annotations

import argparse
import contextlib
import logging
import sys
from collections.abc import Sequence
from dataclasses import replace
from pathlib import Path
from typing import Any, TextIO

from sentinelbot_agent.agent import Agent
from sentinelbot_agent.collectors import build_collectors
from sentinelbot_agent.config import AgentConfig, ConfigError, parse_collectors
from sentinelbot_agent.logging_setup import configure_logging
from sentinelbot_agent.output import EventSink, HttpBatchSink, JsonLinesSink

EXIT_OK = 0
EXIT_CONFIG_ERROR = 2

logger = logging.getLogger("sentinelbot_agent")


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="sentinelbot-agent",
        description="SentinelBot host telemetry agent. Sends events to the API or writes JSON.",
    )
    parser.add_argument("--once", action="store_true", help="run one collection cycle and exit")
    parser.add_argument(
        "--output",
        type=Path,
        help="append events to this file instead of stdout (overrides SENTINEL_OUTPUT_PATH)",
    )
    parser.add_argument(
        "--interval",
        type=float,
        help="seconds between cycles (overrides SENTINEL_INTERVAL_SECONDS)",
    )
    parser.add_argument(
        "--collectors",
        help="comma-separated collectors, e.g. system,processes (overrides SENTINEL_COLLECTORS)",
    )
    parser.add_argument(
        "--log-level",
        default="INFO",
        choices=["DEBUG", "INFO", "WARNING", "ERROR"],
        help="log level for stderr",
    )
    return parser


def resolve_config(args: argparse.Namespace) -> AgentConfig:
    """Environment config with any explicit CLI flags applied on top."""
    config = AgentConfig.from_env()
    overrides: dict[str, Any] = {}
    if args.output is not None:
        overrides["output_path"] = args.output
    if args.interval is not None:
        overrides["interval_seconds"] = args.interval
    if args.collectors is not None:
        overrides["collectors"] = parse_collectors(args.collectors)
    return replace(config, **overrides) if overrides else config


def main(argv: Sequence[str] | None = None) -> int:
    """Run the agent. Returns a process exit code."""
    args = build_parser().parse_args(argv)
    configure_logging(args.log_level)

    try:
        config = resolve_config(args)
        collectors = build_collectors(config)
    except ConfigError as exc:
        logger.error("invalid configuration: %s", exc)
        return EXIT_CONFIG_ERROR

    _ensure_utf8_stdout()
    with contextlib.ExitStack() as stack:
        try:
            sink = _make_sink(config, stack)
        except ConfigError as exc:
            logger.error("invalid configuration: %s", exc)
            return EXIT_CONFIG_ERROR

        agent = Agent(config, collectors, sink)
        if args.once:
            agent.collect_once()
            return EXIT_OK
        try:
            agent.run_forever()
        except KeyboardInterrupt:
            logger.info("agent stopped by user")
    return EXIT_OK


def _make_sink(config: AgentConfig, stack: contextlib.ExitStack) -> EventSink:
    if config.api_url:
        if not config.api_url.startswith(("http://", "https://")):
            raise ConfigError("SENTINEL_API_URL must start with http:// or https://")
        if not config.api_key:
            raise ConfigError("SENTINEL_API_KEY is required when SENTINEL_API_URL is set")
        return HttpBatchSink(config.api_url, config.api_key)
    stream: TextIO = (
        stack.enter_context(config.output_path.open("a", encoding="utf-8"))
        if config.output_path is not None
        else sys.stdout
    )
    return JsonLinesSink(stream)


def _ensure_utf8_stdout() -> None:
    """Process names may contain non-ASCII; Windows consoles default to a legacy code page."""
    reconfigure = getattr(sys.stdout, "reconfigure", None)
    if reconfigure is not None:
        reconfigure(encoding="utf-8", errors="backslashreplace")
