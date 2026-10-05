"""Shared Redis client."""

from __future__ import annotations

from functools import lru_cache

import redis

from app.core.config import get_settings

_override: redis.Redis | None = None


@lru_cache
def _client() -> redis.Redis:
    settings = get_settings()
    return redis.Redis.from_url(
        settings.redis_url,
        decode_responses=True,
        socket_timeout=2.0,
        socket_connect_timeout=2.0,
        health_check_interval=30,
    )


def get_redis() -> redis.Redis:
    return _override if _override is not None else _client()


def set_redis_client(client: redis.Redis | None) -> None:
    """Replace the Redis client process-wide (test suites use an in-process fake)."""
    global _override
    _override = client
