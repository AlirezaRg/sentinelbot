"""Model providers. Each one only turns a (system, user) text pair into text.

Sending anything to an external model discloses the incident's source address and usernames to
that provider. This is why the default is the offline analysis and a model is opt-in.
"""

from __future__ import annotations

from typing import Protocol

import httpx

ANTHROPIC_URL = "https://api.anthropic.com/v1/messages"
ANTHROPIC_VERSION = "2023-06-01"


class LLMProvider(Protocol):
    name: str

    def complete(self, system: str, user: str) -> str:
        """Return the model's text reply. Raises on transport or API failure."""


class AnthropicProvider:
    name = "anthropic"

    def __init__(
        self,
        api_key: str,
        model: str,
        *,
        client: httpx.Client | None = None,
        timeout_seconds: float = 30,
        max_tokens: int = 1200,
    ) -> None:
        self._api_key = api_key
        self._model = model
        self._client = client or httpx.Client(timeout=timeout_seconds)
        self._max_tokens = max_tokens

    def complete(self, system: str, user: str) -> str:
        response = self._client.post(
            ANTHROPIC_URL,
            headers={
                "x-api-key": self._api_key,
                "anthropic-version": ANTHROPIC_VERSION,
                "content-type": "application/json",
            },
            json={
                "model": self._model,
                "max_tokens": self._max_tokens,
                "system": system,
                "messages": [{"role": "user", "content": user}],
            },
        )
        response.raise_for_status()
        blocks = response.json().get("content", [])
        return "".join(
            str(block.get("text", "")) for block in blocks if block.get("type") == "text"
        )
