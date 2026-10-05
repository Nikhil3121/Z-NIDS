"""Liveness, readiness and metrics endpoints.

These deliberately reveal nothing beyond up/down per dependency — no versions,
hostnames, connection strings or error text.
"""

from __future__ import annotations

import logging

from fastapi import APIRouter, Response
from fastapi.responses import JSONResponse
from prometheus_client import CONTENT_TYPE_LATEST, generate_latest
from sqlalchemy import text

from app.core.redis import get_redis
from app.db.session import get_engine

router = APIRouter(tags=["health"])
logger = logging.getLogger(__name__)


@router.get("/health")
def health() -> dict[str, str]:
    """Liveness: the process is up and serving."""
    return {"status": "ok"}


def _check_db() -> bool:
    try:
        with get_engine().connect() as conn:
            conn.execute(text("SELECT 1"))
        return True
    except Exception as exc:
        logger.error("readiness: database check failed", extra={"error_type": type(exc).__name__})
        return False


def _check_redis() -> bool:
    try:
        return bool(get_redis().ping())
    except Exception as exc:
        logger.error("readiness: redis check failed", extra={"error_type": type(exc).__name__})
        return False


@router.get("/ready")
def ready() -> JSONResponse:
    """Readiness: dependencies required to serve traffic are reachable."""
    checks = {"database": _check_db(), "redis": _check_redis()}
    ok = all(checks.values())
    return JSONResponse(
        {"status": "ready" if ok else "not_ready", "checks": {k: "ok" if v else "fail" for k, v in checks.items()}},
        status_code=200 if ok else 503,
    )


@router.get("/metrics", include_in_schema=False)
def metrics() -> Response:
    """Prometheus scrape endpoint. nginx restricts this path to the internal network."""
    return Response(generate_latest(), media_type=CONTENT_TYPE_LATEST)
