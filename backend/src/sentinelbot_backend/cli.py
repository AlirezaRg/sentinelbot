"""``sentinelbot-api``: serve the API, or manage dashboard users.

    sentinelbot-api                       serve on 127.0.0.1:8000 (default)
    sentinelbot-api create-user --username alice --role analyst   (asks for the password)

Binds to localhost unless told otherwise.
"""

from __future__ import annotations

import argparse
import getpass
import logging
from collections.abc import Sequence

import uvicorn
from sentinelbot_agent.logging_setup import configure_logging
from sentinelbot_database.session import make_engine, make_session_factory

from sentinelbot_backend.app import create_app
from sentinelbot_backend.auth import ROLES, hash_password
from sentinelbot_backend.config import ApiSettings, SettingsError
from sentinelbot_backend.storage_sql import SqlUserStore

EXIT_OK = 0
EXIT_CONFIG_ERROR = 2

logger = logging.getLogger("sentinelbot_backend")


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="sentinelbot-api", description="Serve the SentinelBot API."
    )
    parser.add_argument("--host", default="127.0.0.1", help="bind address (default 127.0.0.1)")
    parser.add_argument("--port", type=int, default=8000)
    parser.add_argument(
        "--log-level", default="INFO", choices=["DEBUG", "INFO", "WARNING", "ERROR"]
    )
    commands = parser.add_subparsers(dest="command")
    create = commands.add_parser("create-user", help="create a dashboard user")
    create.add_argument("--username", required=True)
    create.add_argument("--role", choices=ROLES, default="viewer")
    return parser


def main(argv: Sequence[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    configure_logging(args.log_level)

    try:
        settings = ApiSettings.from_env()
    except SettingsError as exc:
        logger.error("invalid configuration: %s", exc)
        return EXIT_CONFIG_ERROR

    if args.command == "create-user":
        return _create_user(settings, args.username, args.role)

    if settings.api_key is None:
        logger.warning("SENTINEL_API_KEY is not set; the service key is disabled")
    if settings.auth_secret is None:
        logger.warning("SENTINEL_AUTH_SECRET is not set; user sign-in is disabled")
    if args.host not in ("127.0.0.1", "localhost", "::1"):
        logger.warning("listening on a non-loopback address; put TLS and a proxy in front")

    app = create_app(settings)
    uvicorn.run(app, host=args.host, port=args.port, log_config=None, access_log=False)
    return EXIT_OK


def _create_user(settings: ApiSettings, username: str, role: str) -> int:
    if not settings.database_url:
        logger.error("user accounts need SENTINEL_DATABASE_URL")
        return EXIT_CONFIG_ERROR
    if not 1 <= len(username) <= 64:
        logger.error("username must be 1 to 64 characters")
        return EXIT_CONFIG_ERROR

    store = SqlUserStore(make_session_factory(make_engine(settings.database_url)))
    if store.get(username) is not None:
        logger.error("user %s already exists", username)
        return EXIT_CONFIG_ERROR

    password = getpass.getpass("Password (at least 12 characters): ")
    if password != getpass.getpass("Repeat password: "):
        logger.error("passwords do not match")
        return EXIT_CONFIG_ERROR
    try:
        hashed = hash_password(password)
    except ValueError as exc:
        logger.error("%s", exc)
        return EXIT_CONFIG_ERROR

    store.create(username, hashed, role)
    print(f"created user {username} with role {role}")
    return EXIT_OK
