"""Where rule and scoring state lives: process memory, or Redis so it survives across runs.

Both implementations expose the same two primitives:

* a sliding window: ``add(key, when, payload)`` returns the payloads seen for ``key`` within
  the window ending at ``when``;
* a cooldown: ``allow(key, when)`` is True at most once per period for ``key``.

Redis keeps the state shared by every process that uses the same prefix, which is what lets
a brute-force attempt spread over several ``sentinelbot-detect`` runs still be counted.
"""

from __future__ import annotations

import json
from collections.abc import Hashable
from datetime import datetime, timedelta
from typing import Any, Protocol
from uuid import uuid4

import redis

from sentinelbot_detection.windows import Cooldown, SlidingWindow

DEFAULT_PREFIX = "sentinel:detect"
_MEMBER_SEPARATOR = "|"
_EXPIRY_SLACK_SECONDS = 60


class WindowLike(Protocol):
    def add(self, key: Hashable, when: datetime, payload: Any) -> list[Any]: ...


class CooldownLike(Protocol):
    def allow(self, key: Hashable, when: datetime) -> bool: ...


class StateStore(Protocol):
    def window(self, name: str, window_seconds: float, max_keys: int) -> WindowLike: ...

    def cooldown(self, name: str, period_seconds: float, max_keys: int) -> CooldownLike: ...


class MemoryState:
    """Default: state lives for one process run. ``max_keys`` caps memory."""

    def window(self, name: str, window_seconds: float, max_keys: int) -> WindowLike:
        return SlidingWindow(window_seconds, max_keys)

    def cooldown(self, name: str, period_seconds: float, max_keys: int) -> CooldownLike:
        return Cooldown(period_seconds, max_keys)


class RedisWindow:
    """One sorted set per key. Scores are event times, so replays behave the same as memory."""

    def __init__(self, client: redis.Redis, prefix: str, window_seconds: float) -> None:
        self._client = client
        self._prefix = prefix
        self._window = window_seconds
        self._ttl = int(window_seconds) + _EXPIRY_SLACK_SECONDS

    def add(self, key: Hashable, when: datetime, payload: Any) -> list[Any]:
        redis_key = f"{self._prefix}:{key}"
        score = when.timestamp()
        # A random prefix keeps identical payloads distinct members of the sorted set.
        member = f"{uuid4().hex}{_MEMBER_SEPARATOR}{json.dumps(payload)}"
        pipe = self._client.pipeline()
        pipe.zadd(redis_key, {member: score})
        pipe.zremrangebyscore(redis_key, "-inf", score - self._window)
        pipe.zrange(redis_key, 0, -1)
        pipe.expire(redis_key, self._ttl)
        _, _, members, _ = pipe.execute()
        return [json.loads(item.split(_MEMBER_SEPARATOR, 1)[1]) for item in members]


class RedisCooldown:
    """Stores the last firing time per key. The check-then-set is not atomic: two processes
    that fire for the same key at the same instant can both alert. That is acceptable for
    alert suppression, and it avoids a Lua script."""

    def __init__(self, client: redis.Redis, prefix: str, period_seconds: float) -> None:
        self._client = client
        self._prefix = prefix
        self._period = timedelta(seconds=period_seconds)
        self._ttl = int(period_seconds) * 2 + _EXPIRY_SLACK_SECONDS

    def allow(self, key: Hashable, when: datetime) -> bool:
        redis_key = f"{self._prefix}:{key}"
        raw = self._client.get(redis_key)
        if raw is not None and when - datetime.fromisoformat(str(raw)) < self._period:
            return False
        self._client.set(redis_key, when.isoformat(), ex=self._ttl)
        return True


class RedisState:
    """Shared state in Redis. ``max_keys`` is not needed: Redis expires old keys itself."""

    def __init__(self, client: redis.Redis, prefix: str = DEFAULT_PREFIX) -> None:
        self._client = client
        self._prefix = prefix

    @classmethod
    def from_url(cls, url: str) -> RedisState:
        return cls(redis.Redis.from_url(url, decode_responses=True))

    def ping(self) -> None:
        self._client.ping()

    def window(self, name: str, window_seconds: float, max_keys: int) -> WindowLike:
        return RedisWindow(self._client, f"{self._prefix}:w:{name}", window_seconds)

    def cooldown(self, name: str, period_seconds: float, max_keys: int) -> CooldownLike:
        return RedisCooldown(self._client, f"{self._prefix}:c:{name}", period_seconds)
