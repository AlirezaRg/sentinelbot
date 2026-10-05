"""Application factory. Tests and tools build an app with explicit settings; the CLI uses env."""

from __future__ import annotations

import logging
import time
from collections.abc import Awaitable, Callable, Sequence

from fastapi import Depends, FastAPI, Request, Response
from fastapi.responses import JSONResponse
from prometheus_client import CONTENT_TYPE_LATEST, generate_latest
from sentinelbot_alerts.channels import AlertChannel

from sentinelbot_backend import __version__
from sentinelbot_backend.auth_routes import router as auth_router
from sentinelbot_backend.config import ApiSettings
from sentinelbot_backend.container import Container, build_container
from sentinelbot_backend.repository import DuplicateEventError
from sentinelbot_backend.routes import router
from sentinelbot_backend.security import get_container, require_viewer

logger = logging.getLogger("sentinelbot_backend.access")


def create_app(
    settings: ApiSettings | None = None,
    *,
    alert_channels: Sequence[AlertChannel] | None = None,
) -> FastAPI:
    resolved = settings if settings is not None else ApiSettings.from_env()
    app = FastAPI(
        title="SentinelBot API",
        version=__version__,
        description="Host security telemetry, detections and incidents.",
    )
    app.state.container = build_container(resolved, alert_channels)
    app.include_router(router)
    app.include_router(auth_router)

    @app.get("/health", tags=["health"])
    def health() -> dict[str, str]:
        """Liveness check. Does not require the API key and reveals nothing sensitive."""
        return {"status": "ok"}

    @app.get("/metrics", tags=["metrics"], dependencies=[Depends(require_viewer)])
    def prometheus_metrics(container: Container = Depends(get_container)) -> Response:
        """Prometheus exposition format. Requires the API key (send it as X-API-Key)."""
        return Response(
            content=generate_latest(container.metrics.registry),
            media_type=CONTENT_TYPE_LATEST,
        )

    @app.exception_handler(DuplicateEventError)
    async def _duplicate(_: Request, exc: DuplicateEventError) -> JSONResponse:
        return JSONResponse(
            status_code=409,
            content={"detail": {"message": "duplicate event_id", "event_ids": exc.event_ids}},
        )

    @app.middleware("http")
    async def access_log(
        request: Request, call_next: Callable[[Request], Awaitable[Response]]
    ) -> Response:
        started = time.perf_counter()
        response = await call_next(request)
        logger.info(
            "request",
            extra={
                "method": request.method,
                "path": request.url.path,
                "status": response.status_code,
                "duration_ms": round((time.perf_counter() - started) * 1000, 2),
            },
        )
        return response

    return app
