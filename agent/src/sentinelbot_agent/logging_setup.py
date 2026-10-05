"""Structured (JSON) logging to stderr. Stdout is reserved for event output."""

from __future__ import annotations

import json
import logging
import sys
from datetime import UTC, datetime

_STANDARD_RECORD_FIELDS = frozenset(vars(logging.makeLogRecord({}))) | {"message", "asctime"}


class JsonFormatter(logging.Formatter):
    """Formats each log record as a single JSON object, including ``extra`` fields."""

    def format(self, record: logging.LogRecord) -> str:
        payload: dict[str, object] = {
            "timestamp": datetime.fromtimestamp(record.created, UTC).isoformat(),
            "level": record.levelname,
            "logger": record.name,
            "message": record.getMessage(),
        }
        for key, value in vars(record).items():
            if key not in _STANDARD_RECORD_FIELDS and not key.startswith("_"):
                payload[key] = value
        if record.exc_info:
            payload["exception"] = self.formatException(record.exc_info)
        return json.dumps(payload, ensure_ascii=False, default=str)


def configure_logging(level: str) -> None:
    """Route the root logger to stderr as JSON at the given level."""
    handler = logging.StreamHandler(sys.stderr)
    handler.setFormatter(JsonFormatter())
    root = logging.getLogger()
    root.handlers.clear()
    root.addHandler(handler)
    root.setLevel(level.upper())
