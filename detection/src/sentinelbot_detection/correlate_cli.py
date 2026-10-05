"""``sentinelbot-correlate``: group scored detections into incidents and manage their status.

Ingest (default) reads detection events (JSON Lines) and prints every incident they touched::

    sentinelbot-detect --input events.jsonl | sentinelbot-correlate --store incidents.json

Status change::

    sentinelbot-correlate --store incidents.json --set-status INC-abc123 RESOLVED
"""

from __future__ import annotations

import argparse
import logging
import sys
from collections.abc import Sequence
from pathlib import Path

from pydantic import ValidationError
from sentinelbot_agent.logging_setup import configure_logging
from sentinelbot_agent.models import Event

from sentinelbot_detection.correlation import (
    CorrelationSettings,
    Correlator,
    IncidentStatus,
    IncidentStore,
    IncidentStoreError,
)

EXIT_OK = 0
EXIT_ERROR = 2

logger = logging.getLogger("sentinelbot_correlate")


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="sentinelbot-correlate",
        description="Correlate detections into incidents (JSON Lines in, incidents out).",
    )
    parser.add_argument("--store", type=Path, required=True, help="incident store JSON file")
    parser.add_argument("--input", default="-", help="detection file, or '-' for stdin (default)")
    parser.add_argument(
        "--gap-seconds",
        type=int,
        default=1800,
        help="max quiet time before a new detection starts a new incident (default 1800)",
    )
    parser.add_argument(
        "--set-status",
        nargs=2,
        metavar=("INCIDENT_ID", "STATUS"),
        help="change an incident's status (OPEN, INVESTIGATING, RESOLVED, FALSE_POSITIVE)",
    )
    parser.add_argument(
        "--log-level", default="INFO", choices=["DEBUG", "INFO", "WARNING", "ERROR"]
    )
    return parser


def main(argv: Sequence[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    configure_logging(args.log_level)

    store = IncidentStore(args.store)
    try:
        store.load()
        settings = CorrelationSettings(gap_seconds=args.gap_seconds)
    except (IncidentStoreError, ValueError) as exc:
        logger.error("cannot use incident store: %s", exc)
        return EXIT_ERROR

    if args.set_status is not None:
        return _set_status(store, *args.set_status)

    correlator = Correlator(store, settings)
    touched: dict[str, None] = {}
    source = sys.stdin if args.input == "-" else open(args.input, encoding="utf-8")  # noqa: SIM115
    try:
        for raw in source:
            line = raw.strip()
            if not line:
                continue
            try:
                event = Event.model_validate_json(line)
            except ValidationError:
                logger.warning("skipping invalid line")
                continue
            if event.source != "detection":
                continue
            touched[correlator.ingest(event).incident_id] = None
    finally:
        if source is not sys.stdin:
            source.close()

    store.save()
    for incident_id in touched:
        sys.stdout.write(store.incidents[incident_id].model_dump_json() + "\n")
    sys.stdout.flush()
    logger.info("correlation run complete", extra={"incidents_touched": len(touched)})
    return EXIT_OK


def _set_status(store: IncidentStore, incident_id: str, raw_status: str) -> int:
    try:
        status = IncidentStatus(raw_status.upper())
    except ValueError:
        logger.error("unknown status %r", raw_status)
        return EXIT_ERROR
    try:
        incident = store.set_status(incident_id, status)
    except KeyError:
        logger.error("no incident with id %s", incident_id)
        return EXIT_ERROR
    store.save()
    sys.stdout.write(incident.model_dump_json() + "\n")
    return EXIT_OK
