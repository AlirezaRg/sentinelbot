"""Password hashing, tokens and roles, tested without the HTTP layer."""

from __future__ import annotations

import pytest

from sentinelbot_backend.auth import (
    ROLES,
    Principal,
    has_role,
    hash_password,
    issue_token,
    read_token,
    verify_password,
)

SECRET = "s" * 40
NOW = 1_800_000_000


def test_password_hash_verifies_and_is_salted() -> None:
    first = hash_password("correct horse battery")
    second = hash_password("correct horse battery")

    assert verify_password("correct horse battery", first)
    assert first != second  # different salt each time
    assert "correct horse battery" not in first


def test_wrong_password_does_not_verify() -> None:
    stored = hash_password("correct horse battery")

    assert verify_password("wrong horse battery!", stored) is False


def test_malformed_stored_hash_does_not_verify() -> None:
    assert verify_password("anything", "not-a-hash") is False


def test_short_password_is_refused() -> None:
    with pytest.raises(ValueError):
        hash_password("short")


def test_token_round_trip_gives_the_same_principal() -> None:
    token = issue_token("alice", "analyst", SECRET, ttl_seconds=3600, now=NOW)

    assert read_token(token, SECRET, now=NOW + 10) == Principal("alice", "analyst")


def test_expired_token_is_rejected() -> None:
    token = issue_token("alice", "admin", SECRET, ttl_seconds=60, now=NOW)

    assert read_token(token, SECRET, now=NOW + 61) is None


def test_token_signed_with_another_secret_is_rejected() -> None:
    token = issue_token("alice", "admin", SECRET, ttl_seconds=3600, now=NOW)

    assert read_token(token, "x" * 40, now=NOW) is None


def test_tampered_role_is_rejected() -> None:
    token = issue_token("alice", "viewer", SECRET, ttl_seconds=3600, now=NOW)
    payload, signature = token.split(".")
    forged_payload = payload[:-1] + ("A" if payload[-1] != "A" else "B")

    assert read_token(f"{forged_payload}.{signature}", SECRET, now=NOW) is None


@pytest.mark.parametrize("junk", ["", "no-dot", "a.b.c", "....", "%%%.%%%"])
def test_garbage_tokens_are_rejected_without_raising(junk: str) -> None:
    assert read_token(junk, SECRET, now=NOW) is None


def test_roles_are_ordered_viewer_analyst_admin() -> None:
    assert ROLES == ("viewer", "analyst", "admin")
    assert has_role(Principal("v", "viewer"), "viewer")
    assert not has_role(Principal("v", "viewer"), "analyst")
    assert has_role(Principal("a", "admin"), "analyst")
