"""Fixed-window rate limiting backed by Redis.

Keys are `rl:<scope>:<identity>:<window>`. When Redis is unreachable the
limiter logs an error; `fail_closed` scopes (login) then reject the request,
other scopes allow it so a cache outage does not take the whole SOC offline.
"""

from __future__ import annotations

import logging
import time
from collections.abc import Callable

import redis
from fastapi import Request

from app.core.config import get_settings
from app.core.exceptions import RateLimitedError, ServiceUnavailableError
from app.core.metrics import RATE_LIMITED
from app.core.redis import get_redis

logger = logging.getLogger(__name__)


class RateLimiter:
    def __init__(self, client_factory: Callable[[], redis.Redis] = get_redis) -> None:
        self._client_factory = client_factory

    def hit(
        self, scope: str, identity: str, limit: int, window_seconds: int = 60, *, fail_closed: bool = False
    ) -> None:
        if not get_settings().rate_limit_enabled or limit <= 0:
            return
        window = int(time.time() // window_seconds)
        key = f"rl:{scope}:{identity}:{window}"
        try:
            client = self._client_factory()
            pipe = client.pipeline()
            pipe.incr(key)
            pipe.expire(key, window_seconds + 1)
            count, _ = pipe.execute()
        except redis.RedisError as exc:
            logger.error("rate limiter unavailable", extra={"scope": scope, "error": str(exc)})
            if fail_closed:
                raise ServiceUnavailableError("Rate limiter unavailable; try again shortly") from exc
            return
        if int(count) > limit:
            RATE_LIMITED.labels(scope=scope).inc()
            retry_after = window_seconds - int(time.time() % window_seconds)
            raise RateLimitedError(retry_after=max(retry_after, 1))


rate_limiter = RateLimiter()


def client_ip(request: Request) -> str:
    # The reverse proxy (nginx) is configured to overwrite X-Real-IP; uvicorn runs
    # with --proxy-headers restricted to the proxy so request.client is trustworthy.
    return request.client.host if request.client else "unknown"


def limit(scope: str, limit_attr: str, *, fail_closed: bool = False) -> Callable[[Request], None]:
    """FastAPI dependency factory: rate-limit by client IP using a settings attribute."""

    def _dependency(request: Request) -> None:
        settings = get_settings()
        rate_limiter.hit(scope, client_ip(request), getattr(settings, limit_attr), fail_closed=fail_closed)

    return _dependency
