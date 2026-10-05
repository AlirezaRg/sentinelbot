"""Sign-in and the current user. Sign-in is open (it is how a user gets a token), so it has its own
stricter per-client limit and answers the same way for unknown users and wrong passwords."""

from __future__ import annotations

import logging
import time
from typing import Literal

from fastapi import APIRouter, Depends, HTTPException, Request, status
from pydantic import BaseModel, ConfigDict, Field

from sentinelbot_backend.auth import DUMMY_HASH, Principal, issue_token, verify_password
from sentinelbot_backend.container import Container
from sentinelbot_backend.security import get_container, require_viewer

logger = logging.getLogger("sentinelbot_backend.auth")

LOGIN_ATTEMPTS_PER_MINUTE = 10
LOGIN_WINDOW_SECONDS = 60

router = APIRouter(prefix="/api/v1/auth", tags=["auth"])


class LoginRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")

    username: str = Field(min_length=1, max_length=64)
    password: str = Field(min_length=1, max_length=256)


class TokenOut(BaseModel):
    access_token: str
    token_type: Literal["bearer"] = "bearer"
    role: str
    expires_in: int


class MeOut(BaseModel):
    username: str
    role: str


@router.post("/login", response_model=TokenOut)
def login(
    body: LoginRequest, request: Request, container: Container = Depends(get_container)
) -> TokenOut:
    secret = container.settings.auth_secret
    if container.users is None or secret is None:
        raise HTTPException(
            status.HTTP_503_SERVICE_UNAVAILABLE,
            "sign-in needs SENTINEL_DATABASE_URL and SENTINEL_AUTH_SECRET",
        )

    client = request.client.host if request.client else "unknown"
    if container.rate_limiter is not None and not container.rate_limiter.allow(
        f"login:{client}", LOGIN_ATTEMPTS_PER_MINUTE, LOGIN_WINDOW_SECONDS
    ):
        raise HTTPException(
            status.HTTP_429_TOO_MANY_REQUESTS,
            "too many sign-in attempts",
            headers={"Retry-After": str(LOGIN_WINDOW_SECONDS)},
        )

    with container.lock:
        user = container.users.get(body.username)
    # Always run one scrypt check, so an unknown name is not faster than a wrong password.
    password_ok = verify_password(body.password, user.password_hash if user else DUMMY_HASH)
    if user is None or user.disabled or not password_ok:
        logger.warning("sign-in failed", extra={"client": client})
        raise HTTPException(status.HTTP_401_UNAUTHORIZED, "invalid username or password")

    ttl = container.settings.token_ttl_seconds
    token = issue_token(user.username, user.role, secret, ttl, int(time.time()))
    logger.info("signed in", extra={"username": user.username, "role": user.role})
    return TokenOut(access_token=token, role=user.role, expires_in=ttl)


@router.get("/me", response_model=MeOut)
def me(principal: Principal = Depends(require_viewer)) -> MeOut:
    return MeOut(username=principal.username, role=principal.role)
