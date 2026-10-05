"""Passwords and tokens, standard library only.

* Passwords: scrypt with a random salt per user. Verification is constant-time.
* Tokens: ``payload.signature`` where the payload is JSON (subject, role, expiry) and the
  signature is HMAC-SHA256 with ``SENTINEL_AUTH_SECRET``. A token is valid until it expires;
  revoking a user is done by disabling the account, which the login check reads on each sign-in.
"""

from __future__ import annotations

import base64
import hashlib
import hmac
import json
import os
from dataclasses import dataclass

ROLES: tuple[str, ...] = ("viewer", "analyst", "admin")
ROLE_RANK = {role: rank for rank, role in enumerate(ROLES)}

_SCRYPT_N = 2**14
_SCRYPT_R = 8
_SCRYPT_P = 1
_KEY_LENGTH = 32
MIN_PASSWORD_LENGTH = 12


@dataclass(frozen=True, slots=True)
class Principal:
    """Who is calling. ``username`` is "api-key" for the shared service key."""

    username: str
    role: str


def _b64(raw: bytes) -> str:
    return base64.urlsafe_b64encode(raw).rstrip(b"=").decode("ascii")


def _unb64(text: str) -> bytes:
    return base64.urlsafe_b64decode(text + "=" * (-len(text) % 4))


def hash_password(password: str) -> str:
    if len(password) < MIN_PASSWORD_LENGTH:
        raise ValueError(f"password must be at least {MIN_PASSWORD_LENGTH} characters")
    salt = os.urandom(16)
    digest = hashlib.scrypt(
        password.encode("utf-8"),
        salt=salt,
        n=_SCRYPT_N,
        r=_SCRYPT_R,
        p=_SCRYPT_P,
        dklen=_KEY_LENGTH,
    )
    return f"scrypt${_SCRYPT_N}${_SCRYPT_R}${_SCRYPT_P}${_b64(salt)}${_b64(digest)}"


def verify_password(password: str, stored: str) -> bool:
    try:
        scheme, n, r, p, salt_text, digest_text = stored.split("$")
        if scheme != "scrypt":
            return False
        digest = hashlib.scrypt(
            password.encode("utf-8"),
            salt=_unb64(salt_text),
            n=int(n),
            r=int(r),
            p=int(p),
            dklen=len(_unb64(digest_text)),
        )
    except (ValueError, TypeError):
        return False
    return hmac.compare_digest(digest, _unb64(digest_text))


# A fixed hash checked when the user does not exist, so an unknown name takes as long as a
# wrong password and the response does not reveal which usernames exist.
DUMMY_HASH = hash_password("dummy-password-for-timing-only")


def _sign(payload: bytes, secret: str) -> bytes:
    return hmac.new(secret.encode("utf-8"), payload, hashlib.sha256).digest()


def issue_token(username: str, role: str, secret: str, ttl_seconds: int, now: int) -> str:
    payload = json.dumps(
        {"sub": username, "role": role, "exp": now + ttl_seconds}, separators=(",", ":")
    ).encode("utf-8")
    return f"{_b64(payload)}.{_b64(_sign(payload, secret))}"


def read_token(token: str, secret: str, now: int) -> Principal | None:
    """Return the principal if the token is genuine and not expired, otherwise ``None``."""
    try:
        payload_text, signature_text = token.split(".", 1)
        payload = _unb64(payload_text)
        if not hmac.compare_digest(_unb64(signature_text), _sign(payload, secret)):
            return None
        claims = json.loads(payload)
        if int(claims["exp"]) < now or claims["role"] not in ROLE_RANK:
            return None
        return Principal(username=str(claims["sub"]), role=str(claims["role"]))
    except (ValueError, KeyError, TypeError, json.JSONDecodeError):
        return None


SERVICE_ROLE = "service"
# "ingest" is a permission, not a user role: agents, analysts and admins may send telemetry.
INGEST_ROLES = frozenset({SERVICE_ROLE, "analyst", "admin"})


def has_role(principal: Principal, required: str) -> bool:
    """Least privilege: the service key may read and ingest, and nothing else.

    A stolen agent key must not be able to change incident status or reach future admin
    routes, so it is deliberately not ranked as an admin.
    """
    if required == "ingest":
        return principal.role in INGEST_ROLES
    if principal.role == SERVICE_ROLE:
        return required == "viewer"
    return ROLE_RANK[principal.role] >= ROLE_RANK[required]
