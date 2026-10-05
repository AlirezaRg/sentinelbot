"""Delivery channels. Email is the only real one for now; the rest of the design can add more.

Credentials come from the environment in the API, never from code or from the database.
"""

from __future__ import annotations

import smtplib
import ssl
from collections.abc import Sequence
from email.message import EmailMessage
from typing import Protocol


class AlertChannel(Protocol):
    name: str

    def send(self, subject: str, body: str) -> None:
        """Deliver one message. Raises on failure."""


class EmailChannel:
    """Sends plain-text mail through an SMTP server, with STARTTLS by default."""

    name = "email"

    def __init__(
        self,
        *,
        host: str,
        port: int,
        sender: str,
        recipients: Sequence[str],
        username: str | None = None,
        password: str | None = None,
        starttls: bool = True,
        timeout_seconds: float = 10,
    ) -> None:
        if not recipients:
            raise ValueError("at least one recipient is required")
        self._host = host
        self._port = port
        self._sender = sender
        self._recipients = list(recipients)
        self._username = username
        self._password = password
        self._starttls = starttls
        self._timeout = timeout_seconds

    def send(self, subject: str, body: str) -> None:
        message = EmailMessage()
        message["Subject"] = subject
        message["From"] = self._sender
        message["To"] = ", ".join(self._recipients)
        message.set_content(body)
        with smtplib.SMTP(self._host, self._port, timeout=self._timeout) as smtp:
            if self._starttls:
                smtp.starttls(context=ssl.create_default_context())
            if self._username:
                smtp.login(self._username, self._password or "")
            smtp.send_message(message)


class RecordingChannel:
    """Keeps messages in memory. For tests and dry runs."""

    name = "recording"

    def __init__(self) -> None:
        self.sent: list[tuple[str, str]] = []

    def send(self, subject: str, body: str) -> None:
        self.sent.append((subject, body))
