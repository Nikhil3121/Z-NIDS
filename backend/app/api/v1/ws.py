"""WebSocket endpoints: live SOC events for analysts, and event ingestion for sensors."""

from __future__ import annotations

import asyncio
import contextlib
import json
import logging

from fastapi import APIRouter, WebSocket, WebSocketDisconnect
from sqlalchemy import select
from starlette.concurrency import run_in_threadpool

from app.api.deps import authenticate_token
from app.core.config import get_settings
from app.core.exceptions import AppError, RateLimitedError
from app.core.rate_limit import rate_limiter
from app.core.security import hash_token
from app.db.session import get_sessionmaker
from app.models.asset import Sensor
from app.services import ingest_service
from app.websocket.manager import Client, manager

router = APIRouter(tags=["realtime"])
logger = logging.getLogger(__name__)

AUTH_TIMEOUT = 5.0


def _origin_allowed(ws: WebSocket) -> bool:
    origin = ws.headers.get("origin")
    # Non-browser clients (sensors, CLI) send no Origin; browsers always do.
    return origin is None or origin in get_settings().cors_origins


async def _first_message(ws: WebSocket) -> dict:
    raw = await asyncio.wait_for(ws.receive_text(), timeout=AUTH_TIMEOUT)
    if len(raw) > 8192:
        raise ValueError("auth message too large")
    msg = json.loads(raw)
    if not isinstance(msg, dict) or msg.get("type") != "auth":
        raise ValueError("first message must be an auth message")
    return msg


@router.websocket("/ws")
async def live(ws: WebSocket) -> None:
    if not _origin_allowed(ws):
        await ws.close(code=1008)
        return
    await ws.accept()
    try:
        msg = await _first_message(ws)

        def _auth() -> tuple[int, set[str]]:
            db = get_sessionmaker()()
            try:
                user = authenticate_token(db, str(msg.get("token", "")))
                return user.id, set(user.role.permission_codes)
            finally:
                db.close()

        user_id, permissions = await run_in_threadpool(_auth)
    except (TimeoutError, ValueError, AppError):
        await ws.send_text(json.dumps({"type": "error", "data": {"code": "AUTHENTICATION_FAILED"}}))
        await ws.close(code=1008)
        return

    client = Client(ws, user_id, permissions)
    manager.add(client)
    await ws.send_text(json.dumps({"type": "ready", "data": {"user_id": user_id}}))

    async def _sender() -> None:
        while True:
            await ws.send_text(await client.queue.get())

    sender = asyncio.create_task(_sender())
    try:
        while True:
            # Clients only send pings; anything else is ignored. Token expiry is
            # enforced by the client reconnecting with a fresh token.
            data = await ws.receive_text()
            if data == "ping":
                await ws.send_text(json.dumps({"type": "pong"}))
    except WebSocketDisconnect:
        pass
    finally:
        sender.cancel()
        with contextlib.suppress(asyncio.CancelledError):
            await sender
        manager.remove(client)


@router.websocket("/ws/ingest")
async def ingest(ws: WebSocket) -> None:
    """Sensor stream: auth message `{"type":"auth","sensor_key":...}`, then
    `{"type":"events","events":[...]}` batches (max 1000 per message)."""
    await ws.accept()
    try:
        msg = await _first_message(ws)
        key = str(msg.get("sensor_key", ""))

        def _sensor_id() -> int:
            db = get_sessionmaker()()
            try:
                sensor = db.scalar(select(Sensor).where(Sensor.api_key_hash == hash_token(key)))
                if sensor is None or not sensor.is_active:
                    raise ValueError("invalid sensor key")
                return sensor.id
            finally:
                db.close()

        sensor_id = await run_in_threadpool(_sensor_id)
    except (TimeoutError, ValueError):
        await ws.close(code=1008)
        return
    await ws.send_text(json.dumps({"type": "ready"}))

    def _ingest(events: list[dict]) -> dict:
        db = get_sessionmaker()()
        try:
            sensor = db.get(Sensor, sensor_id)
            if sensor is None or not sensor.is_active:
                raise ValueError("sensor disabled")
            try:
                rate_limiter.hit("ingest", f"sensor:{sensor.id}", get_settings().rate_limit_ingest_per_minute)
            except RateLimitedError as exc:
                return {"type": "error", "data": {"code": "RATE_LIMITED", "retry_after": exc.retry_after}}
            result = ingest_service.ingest(db, events, source_type=sensor.sensor_type, sensor=sensor)
            return {
                "type": "ack",
                "accepted": len(result.accepted_ids),
                "duplicates": result.duplicates,
                "rejected": result.rejected[:50],
            }
        finally:
            db.close()

    try:
        while True:
            raw = await ws.receive_text()
            if len(raw) > get_settings().max_request_bytes:
                await ws.send_text(json.dumps({"type": "error", "data": {"code": "PAYLOAD_TOO_LARGE"}}))
                continue
            try:
                msg = json.loads(raw)
                events = msg["events"] if msg.get("type") == "events" else None
                if not isinstance(events, list) or not 1 <= len(events) <= 1000:
                    raise ValueError("expected {type: events, events: [1..1000]}")
            except (ValueError, KeyError, TypeError) as exc:
                await ws.send_text(json.dumps({"type": "error", "data": {"code": "BAD_MESSAGE", "message": str(exc)}}))
                continue
            try:
                await ws.send_text(json.dumps(await run_in_threadpool(_ingest, events), default=str))
            except ValueError:
                await ws.close(code=1008)
                return
    except WebSocketDisconnect:
        return
