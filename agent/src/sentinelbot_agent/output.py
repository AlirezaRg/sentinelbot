"""Event output: JSON Lines to a text stream, or batched HTTP delivery to the API."""

from __future__ import annotations

import logging
import urllib.error
import urllib.request
from collections import deque
from typing import Protocol, TextIO

from sentinelbot_agent.models import Event

logger = logging.getLogger(__name__)

DEFAULT_BATCH_SIZE = 200
DEFAULT_QUEUE_LIMIT = 10_000
HTTP_TIMEOUT_SECONDS = 15
HTTP_CONFLICT = 409


class EventSink(Protocol):
    def emit(self, event: Event) -> None:
        """Accept one event. May buffer it."""

    def flush(self) -> None:
        """Deliver anything buffered. Must not raise for a transient delivery failure."""


class JsonLinesSink:
    """Writes each event as one compact JSON object per line and flushes immediately."""

    def __init__(self, stream: TextIO) -> None:
        self._stream = stream

    def emit(self, event: Event) -> None:
        self._stream.write(event.model_dump_json() + "\n")
        self._stream.flush()

    def flush(self) -> None:
        self._stream.flush()


class HttpBatchSink:
    """Sends events to ``POST {url}/api/v1/events`` in batches.

    A batch that fails for a transient reason (network, server error) stays queued and is sent
    again on the next flush. A batch the server already has (HTTP 409) is dropped, so a retry
    never creates duplicates. The queue is bounded: under a long outage the oldest events go first.
    """

    def __init__(
        self,
        base_url: str,
        api_key: str,
        *,
        batch_size: int = DEFAULT_BATCH_SIZE,
        queue_limit: int = DEFAULT_QUEUE_LIMIT,
    ) -> None:
        self._endpoint = base_url.rstrip("/") + "/api/v1/events"
        self._api_key = api_key
        self._batch_size = batch_size
        self._queue: deque[Event] = deque(maxlen=queue_limit)

    @property
    def pending(self) -> int:
        return len(self._queue)

    def emit(self, event: Event) -> None:
        self._queue.append(event)

    def flush(self) -> None:
        while self._queue:
            batch = [self._queue.popleft() for _ in range(min(self._batch_size, len(self._queue)))]
            status = self._post(batch)
            if status is None:
                # Transient failure: keep the batch at the front of the queue, in order.
                self._queue.extendleft(reversed(batch))
                logger.warning("event delivery failed; will retry", extra={"pending": self.pending})
                return
            if status == HTTP_CONFLICT:
                logger.info("server already has this batch; dropped", extra={"events": len(batch)})

    def _post(self, batch: list[Event]) -> int | None:
        """Return the HTTP status, or ``None`` when the batch should be retried."""
        body = ("[" + ",".join(event.model_dump_json() for event in batch) + "]").encode("utf-8")
        request = urllib.request.Request(
            self._endpoint,
            data=body,
            method="POST",
            headers={"Content-Type": "application/json", "X-API-Key": self._api_key},
        )
        try:
            with urllib.request.urlopen(request, timeout=HTTP_TIMEOUT_SECONDS) as response:
                return int(response.status)
        except urllib.error.HTTPError as exc:
            if exc.code == HTTP_CONFLICT:
                return HTTP_CONFLICT
            logger.warning("API rejected batch", extra={"status": exc.code})
            return None
        except (urllib.error.URLError, OSError, ValueError) as exc:
            logger.warning("API unreachable", extra={"error": type(exc).__name__})
            return None
