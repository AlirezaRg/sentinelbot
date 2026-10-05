"""Fixed-window rate limiting per client. Redis when configured, otherwise in process memory.

The limit is checked before the API key, so a client guessing keys is slowed down too.
"""

from __future__ import annotations

import threading
import time
from collections.abc import Callable
from typing import Protocol

import redis

DEFAULT_PREFIX = "sentinel:ratelimit"


class RateLimiter(Protocol):
    def allow(self, key: str, limit: int, window_seconds: int) -> bool:
        """Record one request for ``key``. Returns False once ``limit`` is exceeded."""


class MemoryRateLimiter:
    """Per-process counters. Correct for one API process; use Redis for several."""

    def __init__(self, clock: Callable[[], float] = time.time) -> None:
        self._clock = clock
        self._counts: dict[tuple[str, int], int] = {}
        self._lock = threading.Lock()

    def allow(self, key: str, limit: int, window_seconds: int) -> bool:
        bucket = int(self._clock() // window_seconds)
        with self._lock:
            # Forget buckets from earlier windows so memory does not grow without bound.
            self._counts = {k: v for k, v in self._counts.items() if k[1] >= bucket - 1}
            count = self._counts.get((key, bucket), 0) + 1
            self._counts[(key, bucket)] = count
        return count <= limit


class RedisRateLimiter:
    """Shared counters: every API process using the same Redis enforces one limit."""

    def __init__(self, client: redis.Redis, prefix: str = DEFAULT_PREFIX) -> None:
        self._client = client
        self._prefix = prefix

    def allow(self, key: str, limit: int, window_seconds: int) -> bool:
        bucket = int(time.time() // window_seconds)
        redis_key = f"{self._prefix}:{key}:{bucket}"
        pipe = self._client.pipeline()
        pipe.incr(redis_key)
        pipe.expire(redis_key, window_seconds * 2)
        count, _ = pipe.execute()
        return int(count) <= limit
