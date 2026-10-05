"""Authentication for ``/api/v1``: user bearer tokens, or the service API key.

* A user signs in with username and password and presents ``Authorization: Bearer <token>``.
  The role in the token (viewer, analyst, admin) decides what the route allows.
* The service key ``X-API-Key`` is used by agents and the pipeline. It counts as ``admin``.
* Both paths are rate limited per client before any credential is checked.
* If neither secret is configured, protected routes refuse everything (fail closed).
"""

from __future__ import annotations

import hmac
import time
from collections.abc import Callable

from fastapi import Depends, HTTPException, Request, status

from sentinelbot_backend.auth import Principal, has_role, read_token
from sentinelbot_backend.container import Container

API_KEY_HEADER = "X-API-Key"
RATE_WINDOW_SECONDS = 60
SERVICE_PRINCIPAL = Principal(username="api-key", role="admin")


def get_container(request: Request) -> Container:
    container: Container = request.app.state.container
    return container


def _enforce_rate_limit(request: Request, container: Container) -> None:
    if container.rate_limiter is None:
        return
    client = request.client.host if request.client else "unknown"
    allowed = container.rate_limiter.allow(
        f"api:{client}", container.settings.rate_limit_per_minute, RATE_WINDOW_SECONDS
    )
    if not allowed:
        raise HTTPException(
            status_code=status.HTTP_429_TOO_MANY_REQUESTS,
            detail="rate limit exceeded",
            headers={"Retry-After": str(RATE_WINDOW_SECONDS)},
        )


def authenticate(request: Request, container: Container, required_role: str) -> Principal:
    """Return the caller if they may use a route that needs ``required_role``."""
    _enforce_rate_limit(request, container)

    authorization = request.headers.get("Authorization", "")
    if authorization.startswith("Bearer "):
        secret = container.settings.auth_secret
        principal = (
            read_token(authorization[len("Bearer ") :], secret, int(time.time()))
            if secret
            else None
        )
        if principal is None:
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="invalid or expired token",
                headers={"WWW-Authenticate": "Bearer"},
            )
        if not has_role(principal, required_role):
            raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="insufficient role")
        return principal

    expected = container.settings.api_key
    if expected is None:
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail="no API key or user sign-in is configured on the server",
        )
    supplied = request.headers.get(API_KEY_HEADER, "")
    if not hmac.compare_digest(supplied.encode(), expected.encode()):
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="invalid or missing credentials",
            headers={"WWW-Authenticate": "Bearer, ApiKey"},
        )
    return SERVICE_PRINCIPAL


def _requires(required_role: str) -> Callable[..., Principal]:
    def dependency(request: Request, container: Container = Depends(get_container)) -> Principal:
        return authenticate(request, container, required_role)

    return dependency


require_viewer = _requires("viewer")
require_analyst = _requires("analyst")
require_admin = _requires("admin")
