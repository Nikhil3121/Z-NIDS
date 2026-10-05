"""Notification channels and the notification/delivery log."""

from __future__ import annotations

from datetime import datetime

from sqlalchemy import BigInteger, Boolean, DateTime, ForeignKey, Index, Integer, String, Text, func
from sqlalchemy.orm import Mapped, mapped_column

from app.db.base import Base, TimestampMixin
from app.models.enums import ChannelType, DeliveryStatus, NotificationEvent, db_enum


class NotificationChannel(TimestampMixin, Base):
    """An organisation-wide outbound channel (webhook, Slack-compatible webhook, mailbox)."""

    __tablename__ = "notification_channels"

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    name: Mapped[str] = mapped_column(String(120), unique=True, nullable=False)
    channel_type: Mapped[ChannelType] = mapped_column(db_enum(ChannelType, "channel_type"), nullable=False)
    target: Mapped[str] = mapped_column(String(512), nullable=False)
    # Comma-separated NotificationEvent values this channel subscribes to.
    events: Mapped[str] = mapped_column(String(255), nullable=False)
    min_severity: Mapped[str] = mapped_column(String(16), default="high", nullable=False)
    is_active: Mapped[bool] = mapped_column(Boolean, default=True, nullable=False)
    created_by_id: Mapped[int | None] = mapped_column(ForeignKey("users.id", ondelete="SET NULL"))


class Notification(Base):
    """In-app notification for a user, or a delivery record for a channel."""

    __tablename__ = "notifications"
    __table_args__ = (Index("ix_notifications_user_read", "user_id", "read_at"),)

    id: Mapped[int] = mapped_column(BigInteger, primary_key=True)
    user_id: Mapped[int | None] = mapped_column(ForeignKey("users.id", ondelete="CASCADE"))
    channel_id: Mapped[int | None] = mapped_column(ForeignKey("notification_channels.id", ondelete="SET NULL"))
    channel_type: Mapped[str] = mapped_column(String(16), nullable=False)  # in_app | email | webhook | slack
    event_type: Mapped[NotificationEvent] = mapped_column(
        db_enum(NotificationEvent, "notification_event"), nullable=False
    )
    title: Mapped[str] = mapped_column(String(255), nullable=False)
    body: Mapped[str] = mapped_column(Text, default="", nullable=False)
    resource_type: Mapped[str | None] = mapped_column(String(32))
    resource_id: Mapped[str | None] = mapped_column(String(64))
    delivery_status: Mapped[DeliveryStatus] = mapped_column(
        db_enum(DeliveryStatus, "delivery_status"), default=DeliveryStatus.PENDING, nullable=False
    )
    error: Mapped[str | None] = mapped_column(String(500))
    attempts: Mapped[int] = mapped_column(Integer, default=0, nullable=False)
    read_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), server_default=func.now(), nullable=False)
