"""Typed real-time events, published through Redis pub/sub.

Producers (API processes, Celery workers) publish after their transaction
commits; every API process subscribes once and fans messages out to its
authenticated WebSocket clients (see websocket/manager.py).
"""

from __future__ import annotations

import json
import logging
from datetime import UTC, datetime
from enum import StrEnum
from typing import Any

import redis

from app.core.redis import get_redis

logger = logging.getLogger(__name__)

CHANNEL = "znids:realtime"


class RealtimeEvent(StrEnum):
    ALERT_CREATED = "security.alert.created"
    ALERT_UPDATED = "security.alert.updated"
    INCIDENT_CREATED = "security.incident.created"
    INCIDENT_UPDATED = "security.incident.updated"
    NETWORK_EVENTS_PROCESSED = "network.event.created"
    ASSET_UPDATED = "asset.updated"
    MODEL_DRIFT_DETECTED = "model.drift.detected"
    RESPONSE_UPDATED = "response.action.updated"
    NOTIFICATION_CREATED = "notification.created"


# Which permission a subscriber needs to receive each event type.
EVENT_PERMISSIONS: dict[RealtimeEvent, str] = {
    RealtimeEvent.ALERT_CREATED: "alerts:view",
    RealtimeEvent.ALERT_UPDATED: "alerts:view",
    RealtimeEvent.INCIDENT_CREATED: "incidents:view",
    RealtimeEvent.INCIDENT_UPDATED: "incidents:view",
    RealtimeEvent.NETWORK_EVENTS_PROCESSED: "events:view",
    RealtimeEvent.ASSET_UPDATED: "assets:view",
    RealtimeEvent.MODEL_DRIFT_DETECTED: "models:view",
    RealtimeEvent.RESPONSE_UPDATED: "incidents:view",
    RealtimeEvent.NOTIFICATION_CREATED: "alerts:view",
}


def envelope(event: RealtimeEvent, data: dict[str, Any], user_id: int | None = None) -> dict[str, Any]:
    return {"type": event.value, "ts": datetime.now(UTC).isoformat(), "data": data, "user_id": user_id}


def publish(event: RealtimeEvent, data: dict[str, Any], *, user_id: int | None = None) -> None:
    """Best-effort publish. Real-time delivery must never break the pipeline,
    but failures are logged loudly — the data itself is already committed."""
    try:
        get_redis().publish(CHANNEL, json.dumps(envelope(event, data, user_id), default=str))
    except redis.RedisError as exc:
        logger.error("realtime publish failed", extra={"event": event.value, "error": str(exc)})


def publish_many(items: list[tuple[RealtimeEvent, dict[str, Any]]]) -> None:
    if not items:
        return
    try:
        pipe = get_redis().pipeline(transaction=False)
        for event, data in items:
            pipe.publish(CHANNEL, json.dumps(envelope(event, data), default=str))
        pipe.execute()
    except redis.RedisError as exc:
        logger.error("realtime publish failed", extra={"count": len(items), "error": str(exc)})
