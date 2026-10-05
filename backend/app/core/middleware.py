"""ASGI middleware: request IDs, security headers, body-size limit, timeouts, metrics.

Written as plain ASGI (not BaseHTTPMiddleware) so they compose cheaply and do
not buffer streaming responses.
"""

from __future__ import annotations

import asyncio
import json
import logging
import re
import time
import uuid
from typing import Any

from starlette.types import ASGIApp, Message, Receive, Scope, Send

from app.core.exceptions import error_body
from app.core.logging import correlation_id_var, request_id_var
from app.core.metrics import HTTP_LATENCY, HTTP_REQUESTS

logger = logging.getLogger("znids.http")

_SAFE_ID = re.compile(r"^[A-Za-z0-9\-_.]{8,64}$")

SECURITY_HEADERS = [
    (b"x-content-type-options", b"nosniff"),
    (b"x-frame-options", b"DENY"),
    (b"referrer-policy", b"no-referrer"),
    (b"cross-origin-opener-policy", b"same-origin"),
    (b"cross-origin-resource-policy", b"same-site"),
    (b"permissions-policy", b"camera=(), microphone=(), geolocation=(), payment=()"),
    # The API only ever returns JSON; forbid it from being rendered as a document.
    (b"content-security-policy", b"default-src 'none'; frame-ancestors 'none'"),
    (b"cache-control", b"no-store"),
]
# Swagger UI needs to load its own assets.
_DOCS_CSP = (
    b"default-src 'self'; script-src 'self' https://cdn.jsdelivr.net 'unsafe-inline'; "
    b"style-src 'self' https://cdn.jsdelivr.net 'unsafe-inline'; img-src 'self' data: https://fastapi.tiangolo.com; "
    b"frame-ancestors 'none'"
)


async def _send_json(
    send: Send, status: int, body: dict[str, Any], headers: list[tuple[bytes, bytes]] | None = None
) -> None:
    payload = json.dumps(body).encode()
    await send(
        {
            "type": "http.response.start",
            "status": status,
            "headers": [(b"content-type", b"application/json"), (b"content-length", str(len(payload)).encode())]
            + (headers or []),
        }
    )
    await send({"type": "http.response.body", "body": payload})


class RequestContextMiddleware:
    """Assigns request/correlation IDs, logs access lines and records metrics."""

    def __init__(self, app: ASGIApp) -> None:
        self.app = app

    async def __call__(self, scope: Scope, receive: Receive, send: Send) -> None:
        if scope["type"] not in ("http", "websocket"):
            await self.app(scope, receive, send)
            return
        headers = dict(scope.get("headers") or [])
        incoming = headers.get(b"x-request-id", b"").decode("latin-1")
        request_id = incoming if _SAFE_ID.match(incoming) else uuid.uuid4().hex
        corr = headers.get(b"x-correlation-id", b"").decode("latin-1")
        correlation_id = corr if _SAFE_ID.match(corr) else request_id
        rid_token = request_id_var.set(request_id)
        cid_token = correlation_id_var.set(correlation_id)
        start = time.perf_counter()
        status_holder = {"status": 500}

        async def _send(message: Message) -> None:
            if message["type"] == "http.response.start":
                status_holder["status"] = message["status"]
                message.setdefault("headers", [])
                message["headers"] = [
                    *list(message["headers"]),
                    (b"x-request-id", request_id.encode()),
                    (b"x-correlation-id", correlation_id.encode()),
                ]
            await send(message)

        try:
            await self.app(scope, receive, _send)
        finally:
            if scope["type"] == "http":
                elapsed = time.perf_counter() - start
                route = scope.get("route")
                route_path = getattr(route, "path", "unmatched")
                HTTP_REQUESTS.labels(scope["method"], route_path, str(status_holder["status"])).inc()
                HTTP_LATENCY.labels(scope["method"], route_path).observe(elapsed)
                logger.info(
                    "request",
                    extra={
                        "method": scope["method"],
                        "path": scope["path"],
                        "status": status_holder["status"],
                        "duration_ms": round(elapsed * 1000, 2),
                    },
                )
            request_id_var.reset(rid_token)
            correlation_id_var.reset(cid_token)


class SecurityHeadersMiddleware:
    def __init__(self, app: ASGIApp, *, hsts: bool) -> None:
        self.app = app
        self.hsts = hsts

    async def __call__(self, scope: Scope, receive: Receive, send: Send) -> None:
        if scope["type"] != "http":
            await self.app(scope, receive, send)
            return
        is_docs = scope["path"].startswith(("/docs", "/redoc"))

        async def _send(message: Message) -> None:
            if message["type"] == "http.response.start":
                existing = {k.lower() for k, _ in message.get("headers", [])}
                extra = [(k, v) for k, v in SECURITY_HEADERS if k not in existing]
                if is_docs:
                    extra = [(k, _DOCS_CSP if k == b"content-security-policy" else v) for k, v in extra]
                if self.hsts:
                    extra.append((b"strict-transport-security", b"max-age=63072000; includeSubDomains"))
                message["headers"] = list(message.get("headers", [])) + extra
            await send(message)

        await self.app(scope, receive, _send)


class BodySizeLimitMiddleware:
    """Rejects bodies over `max_bytes`, by Content-Length and while streaming."""

    def __init__(self, app: ASGIApp, *, max_bytes: int) -> None:
        self.app = app
        self.max_bytes = max_bytes

    async def __call__(self, scope: Scope, receive: Receive, send: Send) -> None:
        if scope["type"] != "http":
            await self.app(scope, receive, send)
            return
        headers = dict(scope.get("headers") or [])
        declared = headers.get(b"content-length")
        if declared is not None:
            try:
                too_big = int(declared) > self.max_bytes
            except ValueError:
                await _send_json(send, 400, error_body("BAD_REQUEST", "Invalid Content-Length"))
                return
            if too_big:
                await _send_json(send, 413, error_body("PAYLOAD_TOO_LARGE", "Request body too large"))
                return

        received = 0
        exceeded = False

        async def _receive() -> Message:
            nonlocal received, exceeded
            message = await receive()
            if message["type"] == "http.request":
                received += len(message.get("body", b""))
                if received > self.max_bytes:
                    exceeded = True
                    raise _BodyTooLarge
            return message

        try:
            await self.app(scope, _receive, send)
        except _BodyTooLarge:
            if exceeded:
                await _send_json(send, 413, error_body("PAYLOAD_TOO_LARGE", "Request body too large"))


class _BodyTooLarge(Exception):
    pass


class TimeoutMiddleware:
    """Bounds total handling time of HTTP requests (WebSockets are exempt)."""

    def __init__(self, app: ASGIApp, *, seconds: float) -> None:
        self.app = app
        self.seconds = seconds

    async def __call__(self, scope: Scope, receive: Receive, send: Send) -> None:
        if scope["type"] != "http":
            await self.app(scope, receive, send)
            return
        started = {"value": False}

        async def _send(message: Message) -> None:
            if message["type"] == "http.response.start":
                started["value"] = True
            await send(message)

        try:
            await asyncio.wait_for(self.app(scope, receive, _send), timeout=self.seconds)
        except TimeoutError:
            logger.error("request timed out", extra={"path": scope["path"], "timeout_s": self.seconds})
            if not started["value"]:
                await _send_json(send, 504, error_body("TIMEOUT", "Request timed out"))
