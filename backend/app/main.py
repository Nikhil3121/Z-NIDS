"""Z-NIDS API application factory."""

from __future__ import annotations

import logging
from collections.abc import AsyncIterator
from contextlib import asynccontextmanager

from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware

from app.api.v1 import health
from app.api.v1.router import api_router
from app.core.config import Environment, get_settings
from app.core.exceptions import register_exception_handlers
from app.core.logging import configure_logging
from app.core.middleware import (
    BodySizeLimitMiddleware,
    RequestContextMiddleware,
    SecurityHeadersMiddleware,
    TimeoutMiddleware,
)
from app.websocket.manager import manager

logger = logging.getLogger("znids")


@asynccontextmanager
async def lifespan(app: FastAPI) -> AsyncIterator[None]:
    settings = get_settings()
    logger.info(
        "starting Z-NIDS API",
        extra={
            "environment": settings.environment.value,
            "demo_mode": settings.demo_mode,
            "response_mode": settings.response_mode.value,
            "pipeline_mode": settings.pipeline_mode.value,
        },
    )
    if not settings.is_testing:
        await manager.start()
    try:
        yield
    finally:
        await manager.stop()
        logger.info("Z-NIDS API stopped")


def create_app() -> FastAPI:
    settings = get_settings()
    configure_logging(settings.log_level, settings.log_json)

    docs = settings.expose_docs and settings.environment != Environment.PRODUCTION
    app = FastAPI(
        title="Z-NIDS API",
        description="Zero-Day Network Intrusion Detection & Response Platform",
        version="1.0.0",
        lifespan=lifespan,
        docs_url="/docs" if docs else None,
        redoc_url="/redoc" if docs else None,
        openapi_url=f"{settings.api_prefix}/openapi.json" if docs else None,
    )
    register_exception_handlers(app)

    # Starlette runs middleware outermost-last: RequestContext wraps everything.
    app.add_middleware(TimeoutMiddleware, seconds=settings.request_timeout_seconds)
    app.add_middleware(BodySizeLimitMiddleware, max_bytes=settings.max_request_bytes)
    app.add_middleware(
        CORSMiddleware,
        allow_origins=settings.cors_origins,
        allow_credentials=True,
        allow_methods=["GET", "POST", "PATCH", "PUT", "DELETE", "OPTIONS"],
        allow_headers=["Authorization", "Content-Type", "X-Request-ID", "X-ZNIDS-CSRF", "X-Sensor-Key"],
        expose_headers=["X-Request-ID", "Retry-After"],
        max_age=600,
    )
    app.add_middleware(SecurityHeadersMiddleware, hsts=settings.is_production_like)
    app.add_middleware(RequestContextMiddleware)

    app.include_router(health.router)
    app.include_router(api_router, prefix=settings.api_prefix)
    return app


app = create_app()
