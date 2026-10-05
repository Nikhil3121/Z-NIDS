"""/api/v1/notifications — in-app inbox and organisation notification channels."""

from __future__ import annotations

from datetime import UTC, datetime
from typing import Annotated

from fastapi import APIRouter, Depends, Query
from pydantic import Field, field_validator
from sqlalchemy import func, select, update

from app.api.deps import CurrentUser, DbSession, Meta, require
from app.api.query import page_params, paginate
from app.core.exceptions import ConflictError, NotFoundError, ValidationFailedError
from app.integrations.notifications.webhook import UnsafeTargetError, validate_target
from app.models.enums import ChannelType, DeliveryStatus, NotificationEvent, Permission, Severity
from app.models.notification import Notification, NotificationChannel
from app.models.user import User
from app.schemas.common import Message, Page, PageParams, Schema, StrictInput
from app.services import audit_service, notification_service
from app.services.notification_service import Message as NotifyMessage

router = APIRouter(prefix="/notifications", tags=["notifications"])
Admin = Annotated[User, Depends(require(Permission.MANAGE_SETTINGS))]


class NotificationOut(Schema):
    id: int
    channel_type: str
    event_type: NotificationEvent
    title: str
    body: str
    resource_type: str | None
    resource_id: str | None
    delivery_status: DeliveryStatus
    read_at: datetime | None
    created_at: datetime


class ChannelOut(Schema):
    id: int
    name: str
    channel_type: ChannelType
    target: str
    events: str
    min_severity: str
    is_active: bool
    created_at: datetime


class ChannelIn(StrictInput):
    name: str = Field(min_length=2, max_length=120)
    channel_type: ChannelType
    target: str = Field(min_length=3, max_length=512)
    events: list[NotificationEvent] = Field(min_length=1)
    min_severity: Severity = Severity.HIGH
    is_active: bool = True

    @field_validator("target")
    @classmethod
    def _strip(cls, v: str) -> str:
        return v.strip()


def _mask(target: str, channel_type: ChannelType) -> str:
    """Webhook URLs embed secrets (e.g. Slack paths) — never return them in full."""
    if channel_type == ChannelType.EMAIL:
        return target
    return target[:24] + "…" if len(target) > 24 else target


@router.get("", response_model=Page[NotificationOut])
def inbox(
    db: DbSession, user: CurrentUser, params: Annotated[PageParams, Depends(page_params)], unread_only: bool = False
) -> Page[NotificationOut]:
    stmt = select(Notification).where(Notification.user_id == user.id, Notification.channel_type == "in_app")
    if unread_only:
        stmt = stmt.where(Notification.read_at.is_(None))
    return paginate(db, stmt.order_by(Notification.created_at.desc()), params, NotificationOut.model_validate)


@router.get("/unread-count")
def unread_count(db: DbSession, user: CurrentUser) -> dict[str, int]:
    n = (
        db.scalar(
            select(func.count())
            .select_from(Notification)
            .where(
                Notification.user_id == user.id, Notification.channel_type == "in_app", Notification.read_at.is_(None)
            )
        )
        or 0
    )
    return {"unread": int(n)}


@router.post("/read", response_model=Message)
def mark_read(db: DbSession, user: CurrentUser, ids: list[int] | None = None) -> Message:
    stmt = update(Notification).where(Notification.user_id == user.id, Notification.read_at.is_(None))
    if ids:
        stmt = stmt.where(Notification.id.in_(ids[:500]))
    db.execute(stmt.values(read_at=datetime.now(UTC)))
    db.commit()
    return Message(message="ok")


@router.get("/channels", response_model=list[ChannelOut])
def channels(db: DbSession, _: Admin) -> list[ChannelOut]:
    out = []
    for c in db.scalars(select(NotificationChannel).order_by(NotificationChannel.name)).all():
        item = ChannelOut.model_validate(c)
        item.target = _mask(c.target, c.channel_type)
        out.append(item)
    return out


@router.post("/channels", response_model=ChannelOut, status_code=201)
def create_channel(body: ChannelIn, db: DbSession, user: Admin, meta: Meta) -> ChannelOut:
    if body.channel_type == ChannelType.EMAIL:
        if "@" not in body.target or len(body.target) > 254:
            raise ValidationFailedError("Email channel target must be an email address")
    else:
        try:
            validate_target(body.target)
        except UnsafeTargetError as exc:
            raise ValidationFailedError(str(exc), code="UNSAFE_WEBHOOK_TARGET") from exc
    if db.scalar(select(NotificationChannel).where(NotificationChannel.name == body.name)):
        raise ConflictError("A channel with this name already exists")
    ch = NotificationChannel(
        name=body.name,
        channel_type=body.channel_type,
        target=body.target,
        events=",".join(e.value for e in body.events),
        min_severity=body.min_severity.value,
        is_active=body.is_active,
        created_by_id=user.id,
    )
    db.add(ch)
    db.flush()
    audit_service.record(
        db,
        "CONFIGURATION_CHANGED",
        actor=user,
        resource_type="notification_channel",
        resource_id=ch.id,
        meta=meta,
        details={"name": ch.name, "type": ch.channel_type.value},
    )
    db.commit()
    out = ChannelOut.model_validate(ch)
    out.target = _mask(ch.target, ch.channel_type)
    return out


@router.delete("/channels/{channel_id}", response_model=Message)
def delete_channel(channel_id: int, db: DbSession, user: Admin, meta: Meta) -> Message:
    ch = db.get(NotificationChannel, channel_id)
    if ch is None:
        raise NotFoundError("Channel not found")
    ch.is_active = False
    audit_service.record(
        db,
        "CONFIGURATION_CHANGED",
        actor=user,
        resource_type="notification_channel",
        resource_id=ch.id,
        meta=meta,
        details={"deactivated": ch.name},
    )
    db.commit()
    return Message(message="Channel deactivated")


@router.post("/channels/{channel_id}/test")
def test_channel(channel_id: int, db: DbSession, user: Admin, meta: Meta) -> dict:
    """Send a clearly-labelled test message through one channel and report the real outcome."""
    ch = db.get(NotificationChannel, channel_id)
    if ch is None:
        raise NotFoundError("Channel not found")
    msg = NotifyMessage(
        NotificationEvent.CRITICAL_ALERT,
        "Z-NIDS test notification",
        f"Test message requested by {user.email}. No security event occurred.",
        Severity.INFO,
    )
    n = Notification(
        channel_id=ch.id,
        channel_type=ch.channel_type.value,
        event_type=msg.event,
        title=msg.title,
        body=msg.body,
        delivery_status=DeliveryStatus.PENDING,
    )
    db.add(n)
    db.flush()
    notification_service.deliver(db, n, msg)
    audit_service.record(
        db,
        "NOTIFICATION_CHANNEL_TESTED",
        actor=user,
        resource_type="notification_channel",
        resource_id=ch.id,
        meta=meta,
        details={"status": n.delivery_status.value},
    )
    db.commit()
    return {"status": n.delivery_status.value, "error": n.error}


@router.get("/deliveries", response_model=Page[NotificationOut])
def deliveries(
    db: DbSession,
    _: Admin,
    params: Annotated[PageParams, Depends(page_params)],
    status: DeliveryStatus | None = Query(None),
) -> Page[NotificationOut]:
    stmt = select(Notification).where(Notification.channel_type != "in_app")
    if status:
        stmt = stmt.where(Notification.delivery_status == status)
    return paginate(db, stmt.order_by(Notification.created_at.desc()), params, NotificationOut.model_validate)
