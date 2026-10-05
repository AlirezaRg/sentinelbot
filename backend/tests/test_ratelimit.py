"""Rate limiting: counters per client, Redis sharing, and the 429 response from the API."""

from __future__ import annotations

import fakeredis
from fastapi.testclient import TestClient

from sentinelbot_backend.app import create_app
from sentinelbot_backend.config import ApiSettings
from sentinelbot_backend.ratelimit import MemoryRateLimiter, RedisRateLimiter

KEY = "k" * 32
AUTH = {"X-API-Key": KEY}


def test_memory_limiter_allows_up_to_the_limit_then_refuses() -> None:
    limiter = MemoryRateLimiter(clock=lambda: 1000.0)

    results = [limiter.allow("client", limit=3, window_seconds=60) for _ in range(4)]

    assert results == [True, True, True, False]


def test_memory_limiter_resets_in_the_next_window() -> None:
    now = [1000.0]
    limiter = MemoryRateLimiter(clock=lambda: now[0])
    for _ in range(3):
        limiter.allow("client", limit=3, window_seconds=60)

    now[0] = 1120.0  # two windows later

    assert limiter.allow("client", limit=3, window_seconds=60) is True


def test_memory_limiter_counts_clients_separately() -> None:
    limiter = MemoryRateLimiter(clock=lambda: 1000.0)
    for _ in range(3):
        limiter.allow("a", limit=3, window_seconds=60)

    assert limiter.allow("b", limit=3, window_seconds=60) is True


def test_redis_limiter_is_shared_between_instances() -> None:
    server = fakeredis.FakeServer()
    first = RedisRateLimiter(fakeredis.FakeRedis(server=server))
    second = RedisRateLimiter(fakeredis.FakeRedis(server=server))

    assert [first.allow("c", 2, 60), second.allow("c", 2, 60)] == [True, True]
    assert second.allow("c", 2, 60) is False  # the third hit, from the other process


def test_api_returns_429_after_the_limit() -> None:
    client = TestClient(create_app(ApiSettings(api_key=KEY, rate_limit_per_minute=3)))

    statuses = [client.get("/api/v1/system/status", headers=AUTH).status_code for _ in range(4)]

    assert statuses == [200, 200, 200, 429]


def test_429_response_includes_retry_after() -> None:
    client = TestClient(create_app(ApiSettings(api_key=KEY, rate_limit_per_minute=1)))
    client.get("/api/v1/system/status", headers=AUTH)

    response = client.get("/api/v1/system/status", headers=AUTH)

    assert response.status_code == 429
    assert response.headers["Retry-After"] == "60"


def test_rate_limit_applies_before_key_check() -> None:
    """A client guessing keys is limited, even though every guess is wrong."""
    client = TestClient(create_app(ApiSettings(api_key=KEY, rate_limit_per_minute=2)))

    statuses = [
        client.get("/api/v1/system/status", headers={"X-API-Key": "wrong"}).status_code
        for _ in range(3)
    ]

    assert statuses == [401, 401, 429]


def test_health_is_not_rate_limited() -> None:
    client = TestClient(create_app(ApiSettings(api_key=KEY, rate_limit_per_minute=1)))

    statuses = [client.get("/health").status_code for _ in range(5)]

    assert statuses == [200] * 5


def test_zero_disables_rate_limiting() -> None:
    client = TestClient(create_app(ApiSettings(api_key=KEY, rate_limit_per_minute=0)))

    statuses = {client.get("/api/v1/system/status", headers=AUTH).status_code for _ in range(5)}

    assert statuses == {200}
