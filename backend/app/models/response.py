"""Response actions and the lab/sandbox enforcement state."""

from __future__ import annotations

from datetime import datetime
from typing import Any

from sqlalchemy import Boolean, DateTime, ForeignKey, Index, Integer, String, Text, func, text
from sqlalchemy.dialects.postgresql import INET, JSONB
from sqlalchemy.orm import Mapped, mapped_column

from app.db.base import Base, TimestampMixin
from app.models.enums import ResponseActionType, ResponseStatus, db_enum


class ResponseAction(TimestampMixin, Base):
    """A proposed or executed containment action. Every transition is audited."""

    __tablename__ = "response_actions"

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    action_type: Mapped[ResponseActionType] = mapped_column(
        db_enum(ResponseActionType, "response_action_type"), nullable=False
    )
    target: Mapped[str] = mapped_column(String(255), nullable=False)
    reason: Mapped[str] = mapped_column(Text, nullable=False)
    status: Mapped[ResponseStatus] = mapped_column(db_enum(ResponseStatus, "response_status"), nullable=False)
    mode: Mapped[str] = mapped_column(String(32), nullable=False)
    adapter: Mapped[str] = mapped_column(String(32), nullable=False)
    incident_id: Mapped[int | None] = mapped_column(ForeignKey("incidents.id", ondelete="SET NULL"), index=True)
    alert_id: Mapped[int | None] = mapped_column(ForeignKey("alerts.id", ondelete="SET NULL"))
    requested_by_id: Mapped[int | None] = mapped_column(ForeignKey("users.id", ondelete="SET NULL"))
    decided_by_id: Mapped[int | None] = mapped_column(ForeignKey("users.id", ondelete="SET NULL"))
    decided_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    executed_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    result: Mapped[dict[str, Any]] = mapped_column(JSONB, default=dict, nullable=False)


class LabBlocklistEntry(Base):
    """Block state of the built-in *lab* firewall adapter.

    This table is the enforcement point only for the sandbox; a production
    deployment plugs a real firewall adapter in behind the same interface.
    """

    __tablename__ = "lab_blocklist"
    __table_args__ = (Index("uq_lab_blocklist_active_ip", "ip_address", unique=True, postgresql_where=text("active")),)

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    ip_address: Mapped[str] = mapped_column(INET, nullable=False)
    reason: Mapped[str] = mapped_column(Text, nullable=False)
    response_action_id: Mapped[int | None] = mapped_column(ForeignKey("response_actions.id", ondelete="SET NULL"))
    active: Mapped[bool] = mapped_column(Boolean, default=True, nullable=False)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), server_default=func.now(), nullable=False)
    expires_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    removed_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
