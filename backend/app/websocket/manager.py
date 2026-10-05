"""WebSocket connection manager and Redis pub/sub fan-out.

Authentication happens in the first message (`{"type": "auth", "token": ...}`)
rather than the URL, so access tokens never land in proxy/access logs. Each
connection only receives event types its user's permissions allow, and
user-targeted events (e.g. notifications) only reach that user.
"""

from __future__ import annotations

import asyncio
import contextlib
import json
import logging
from dataclasses import dataclass, field

import redis.asyncio as aioredis
from fastapi import WebSocket

from app.core.config import get_settings
from app.core.metrics import WS_CONNECTIONS
from app.websocket.events import CHANNEL, EVENT_PERMISSIONS, RealtimeEvent

logger = logging.getLogger(__name__)


@dataclass(eq=False)
class Client:
    ws: WebSocket
    user_id: int
    permissions: set[str]
    queue: asyncio.Queue[str] = field(default_factory=lambda: asyncio.Queue(maxsize=500))


class ConnectionManager:
    def __init__(self) -> None:
        self.clients: set[Client] = set()
        self._task: asyncio.Task[None] | None = None

    def add(self, client: Client) -> None:
        self.clients.add(client)
        WS_CONNECTIONS.set(len(self.clients))

    def remove(self, client: Client) -> None:
        self.clients.discard(client)
        WS_CONNECTIONS.set(len(self.clients))

    def dispatch(self, raw: str) -> None:
        try:
            msg = json.loads(raw)
            event = RealtimeEvent(msg["type"])
        except (ValueError, KeyError):
            logger.warning("dropping malformed realtime message")
            return
        needed = EVENT_PERMISSIONS.get(event)
        target_user = msg.get("user_id")
        outgoing = json.dumps({"type": msg["type"], "ts": msg.get("ts"), "data": msg.get("data")})
        for client in list(self.clients):
            if target_user is not None and client.user_id != target_user:
                continue
            if needed and needed not in client.permissions:
                continue
            try:
                client.queue.put_nowait(outgoing)
            except asyncio.QueueFull:
                # A slow consumer must not stall everyone: drop it; the UI reconnects and refetches.
                logger.warning("websocket client too slow; disconnecting", extra={"user_id": client.user_id})
                asyncio.get_running_loop().create_task(client.ws.close(code=1013))
                self.remove(client)

    async def _listen(self) -> None:
        settings = get_settings()
        backoff = 1.0
        while True:
            conn = aioredis.from_url(settings.redis_url, decode_responses=True)
            pubsub = conn.pubsub()
            try:
                await pubsub.subscribe(CHANNEL)
                logger.info("realtime subscriber connected")
                backoff = 1.0
                async for message in pubsub.listen():
                    if message.get("type") == "message":
                        self.dispatch(message["data"])
            except asyncio.CancelledError:
                raise
            except Exception as exc:
                logger.warning("realtime subscriber disconnected; retrying",
                               extra={"error": str(exc) or type(exc).__name__, "retry_in_s": backoff})
                await asyncio.sleep(backoff)
                backoff = min(backoff * 2, 30.0)
            finally:
                # Close this attempt's connection so retries do not leak sockets.
                with contextlib.suppress(Exception):
                    await pubsub.aclose()
                with contextlib.suppress(Exception):
                    await conn.aclose()

    async def start(self) -> None:
        if self._task is None:
            self._task = asyncio.create_task(self._listen())

    async def stop(self) -> None:
        if self._task is not None:
            self._task.cancel()
            with contextlib.suppress(asyncio.CancelledError):
                await self._task
            self._task = None


manager = ConnectionManager()
