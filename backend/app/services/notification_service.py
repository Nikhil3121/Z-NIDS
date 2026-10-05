"""Notification fan-out: in-app, per-user email preferences, organisation channels."""

from __future__ import annotations

import logging
from dataclasses import dataclass
from typing import Any

from sqlalchemy import select
from sqlalchemy.orm import Session

from app.core.config import get_settings
from app.core.metrics import NOTIFICATIONS
from app.integrations.notifications.email import send_email
from app.integrations.notifications.webhook import post_json, slack_payload
from app.models.enums import ChannelType, DeliveryStatus, NotificationEvent, Permission, Severity
from app.models.notification import Notification, NotificationChannel
from app.models.user import NotificationPreference, User
from app.websocket.events import RealtimeEvent, publish

logger = logging.getLogger(__name__)

# Defaults when a user has not saved a preference for an event type.
DEFAULT_IN_APP = True
DEFAULT_EMAIL = {NotificationEvent.INCIDENT_ASSIGNED, NotificationEvent.RESPONSE_APPROVAL}

# Which permission makes a user an eligible recipient of an event type.
_AUDIENCE = {
    NotificationEvent.CRITICAL_ALERT: Permission.VIEW_ALERTS,
    NotificationEvent.UNKNOWN_ANOMALY: Permission.VIEW_ALERTS,
    NotificationEvent.INCIDENT_ESCALATED: Permission.VIEW_INCIDENTS,
    NotificationEvent.MODEL_DRIFT: Permission.MANAGE_MODELS,
    NotificationEvent.RESPONSE_APPROVAL: Permission.APPROVE_RESPONSE,
}


@dataclass
class Message:
    event: NotificationEvent
    title: str
    body: str
    severity: Severity
    resource_type: str | None = None
    resource_id: str | None = None

    def link(self) -> str | None:
        if not self.resource_type or not self.resource_id:
            return None
        path = {"incident": "incidents", "alert": "alerts", "ml_model": "models/drift"}.get(self.resource_type)
        return f"{get_settings().frontend_base_url}/{path}/{self.resource_id}" if path else None


def _prefs(db: Session, users: list[User], event: NotificationEvent) -> dict[int, NotificationPreference]:
    if not users:
        return {}
    rows = db.scalars(
        select(NotificationPreference).where(
            NotificationPreference.user_id.in_([u.id for u in users]), NotificationPreference.event_type == event
        )
    ).all()
    return {p.user_id: p for p in rows}


def recipients(db: Session, event: NotificationEvent, explicit: list[User] | None) -> list[User]:
    if explicit is not None:
        return [u for u in explicit if u.is_active]
    perm = _AUDIENCE.get(event)
    users = db.scalars(select(User).where(User.is_active.is_(True))).all()
    return [u for u in users if perm is None or u.has_permission(perm.value)]


def notify(db: Session, message: Message, *, users: list[User] | None = None) -> list[Notification]:
    """Create notification records and deliver them. Caller commits."""
    created: list[Notification] = []
    targets = recipients(db, message.event, users)
    prefs = _prefs(db, targets, message.event)
    for user in targets:
        pref = prefs.get(user.id)
        in_app = pref.in_app if pref else DEFAULT_IN_APP
        email = pref.email if pref else message.event in DEFAULT_EMAIL
        if in_app:
            n = Notification(
                user_id=user.id,
                channel_type="in_app",
                event_type=message.event,
                title=message.title,
                body=message.body,
                resource_type=message.resource_type,
                resource_id=message.resource_id,
                delivery_status=DeliveryStatus.SENT,
            )
            db.add(n)
            created.append(n)
        if email:
            n = Notification(
                user_id=user.id,
                channel_type="email",
                event_type=message.event,
                title=message.title,
                body=message.body,
                resource_type=message.resource_type,
                resource_id=message.resource_id,
                delivery_status=DeliveryStatus.PENDING,
            )
            db.add(n)
            created.append(n)

    severity_rank = Severity(message.severity).rank
    channels = db.scalars(select(NotificationChannel).where(NotificationChannel.is_active.is_(True))).all()
    for ch in channels:
        events = {e.strip() for e in ch.events.split(",") if e.strip()}
        if message.event.value not in events or severity_rank < Severity(ch.min_severity).rank:
            continue
        n = Notification(
            channel_id=ch.id,
            channel_type=ch.channel_type.value,
            event_type=message.event,
            title=message.title,
            body=message.body,
            resource_type=message.resource_type,
            resource_id=message.resource_id,
            delivery_status=DeliveryStatus.PENDING,
        )
        db.add(n)
        created.append(n)
    db.flush()
    for n in created:
        if n.delivery_status == DeliveryStatus.PENDING:
            deliver(db, n, message)
        elif n.channel_type == "in_app":
            NOTIFICATIONS.labels(channel="in_app", status="sent").inc()
    return created


def publish_created(notifications: list[Notification]) -> None:
    """Push in-app notifications to their users. Call after the transaction commits."""
    for n in notifications:
        if n.channel_type == "in_app" and n.user_id is not None:
            publish(
                RealtimeEvent.NOTIFICATION_CREATED,
                {
                    "id": n.id,
                    "title": n.title,
                    "event_type": n.event_type.value,
                    "resource_type": n.resource_type,
                    "resource_id": n.resource_id,
                },
                user_id=n.user_id,
            )


def deliver(db: Session, n: Notification, message: Message | None = None) -> None:
    """Attempt one delivery; record the outcome (never raises)."""
    n.attempts += 1
    link = message.link() if message else None
    try:
        if n.channel_type == "email":
            user = db.get(User, n.user_id) if n.user_id else None
            if user is None:
                raise RuntimeError("recipient no longer exists")
            send_email(user.email, f"[Z-NIDS] {n.title}", n.body + (f"\n\n{link}" if link else ""))
        else:
            channel = db.get(NotificationChannel, n.channel_id) if n.channel_id else None
            if channel is None or not channel.is_active:
                n.delivery_status = DeliveryStatus.SKIPPED
                n.error = "channel inactive or removed"
                return
            if channel.channel_type == ChannelType.EMAIL:
                send_email(channel.target, f"[Z-NIDS] {n.title}", n.body + (f"\n\n{link}" if link else ""))
            elif channel.channel_type == ChannelType.SLACK:
                post_json(channel.target, slack_payload(n.title, n.body, link), sign=False)
            else:
                post_json(channel.target, _webhook_body(n, link), sign=True)
        n.delivery_status = DeliveryStatus.SENT
        n.error = None
        NOTIFICATIONS.labels(channel=n.channel_type, status="sent").inc()
    except Exception as exc:
        n.delivery_status = DeliveryStatus.FAILED
        n.error = f"{type(exc).__name__}: {exc}"[:500]
        NOTIFICATIONS.labels(channel=n.channel_type, status="failed").inc()
        logger.warning(
            "notification delivery failed", extra={"notification_id": n.id, "channel": n.channel_type, "error": n.error}
        )


def _webhook_body(n: Notification, link: str | None) -> dict[str, Any]:
    return {
        "event": n.event_type.value,
        "title": n.title,
        "body": n.body,
        "resource_type": n.resource_type,
        "resource_id": n.resource_id,
        "link": link,
        "notification_id": n.id,
    }
