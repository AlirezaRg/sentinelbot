"""Bounded in-memory state for rules: sliding windows and cooldowns.

Both structures are keyed by an arbitrary hashable value (usually a source IP or host).
Memory is capped by ``max_keys``; when the cap is reached the least recently active key is
evicted. This is in-process state only. Phase 8 moves it to Redis.
"""

from __future__ import annotations

from collections import deque
from collections.abc import Hashable
from datetime import datetime, timedelta


class SlidingWindow[T]:
    """Keeps the payloads seen for each key during the last ``window_seconds``."""

    def __init__(self, window_seconds: float, max_keys: int) -> None:
        self._window = timedelta(seconds=window_seconds)
        self._max_keys = max_keys
        self._entries: dict[Hashable, deque[tuple[datetime, T]]] = {}

    def add(self, key: Hashable, when: datetime, payload: T) -> list[T]:
        """Record one occurrence and return every payload still inside the window."""
        entries = self._entries.setdefault(key, deque())
        entries.append((when, payload))
        cutoff = when - self._window
        while entries and entries[0][0] < cutoff:
            entries.popleft()
        if len(self._entries) > self._max_keys:
            self._evict_least_recent()
        return [payload for _, payload in entries]

    def _evict_least_recent(self) -> None:
        oldest = min(self._entries, key=lambda k: self._entries[k][-1][0])
        del self._entries[oldest]


class Cooldown:
    """Allows a key to fire at most once per ``period_seconds``."""

    def __init__(self, period_seconds: float, max_keys: int) -> None:
        self._period = timedelta(seconds=period_seconds)
        self._max_keys = max_keys
        self._last: dict[Hashable, datetime] = {}

    def allow(self, key: Hashable, when: datetime) -> bool:
        last = self._last.get(key)
        if last is not None and when - last < self._period:
            return False
        self._last[key] = when
        if len(self._last) > self._max_keys:
            oldest = min(self._last, key=self._last.__getitem__)
            del self._last[oldest]
        return True
