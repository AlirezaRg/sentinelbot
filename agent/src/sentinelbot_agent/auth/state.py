"""Persistent collector state (resume points) stored as a small JSON file."""

from __future__ import annotations

import json
import logging
import os
from pathlib import Path
from typing import Any

logger = logging.getLogger(__name__)

StateMap = dict[str, dict[str, Any]]


class StateStore:
    """Loads and atomically saves per-source resume state.

    A missing or corrupt file means "start from the beginning". That can re-emit some
    events, which is preferable to silently skipping them.
    """

    def __init__(self, path: Path) -> None:
        self._path = path

    @property
    def path(self) -> Path:
        return self._path

    def load(self) -> StateMap:
        try:
            raw = self._path.read_text(encoding="utf-8")
        except FileNotFoundError:
            return {}
        except OSError as exc:
            logger.warning("state file unreadable, starting fresh", extra={"error": str(exc)})
            return {}
        try:
            data = json.loads(raw)
        except json.JSONDecodeError:
            logger.warning("state file is corrupt, starting fresh", extra={"path": str(self._path)})
            return {}
        if not isinstance(data, dict):
            logger.warning("state file has an unexpected shape, starting fresh")
            return {}
        return {str(k): v for k, v in data.items() if isinstance(v, dict)}

    def save(self, state: StateMap) -> None:
        self._path.parent.mkdir(parents=True, exist_ok=True)
        temporary = self._path.with_name(self._path.name + ".tmp")
        temporary.write_text(json.dumps(state, indent=2, sort_keys=True), encoding="utf-8")
        # os.replace is atomic on the same filesystem, so a crash never leaves half a file.
        os.replace(temporary, self._path)
