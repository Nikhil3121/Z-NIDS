"""Alerts (deduplicated detections) and their detection links."""

from __future__ import annotations

from datetime import datetime

from sqlalchemy import (
    BigInteger,
    Boolean,
    Column,
    DateTime,
    Float,
    ForeignKey,
    Index,
    Integer,
    String,
    Table,
    Text,
    text,
)
from sqlalchemy.dialects.postgresql import INET
from sqlalchemy.orm import Mapped, mapped_column, relationship

from app.db.base import Base, TimestampMixin
from app.models.enums import AlertStatus, AlertType, Classification, Severity, db_enum

alert_detections = Table(
    "alert_detections",
    Base.metadata,
    Column("alert_id", ForeignKey("alerts.id", ondelete="CASCADE"), primary_key=True),
    Column("detection_id", ForeignKey("detections.id", ondelete="CASCADE"), primary_key=True),
)


class Alert(TimestampMixin, Base):
    """An analyst-facing signal.

    Repeated detections with the same `dedup_key` inside the dedup window fold
    into one open alert (occurrence_count++) instead of creating new rows.
    """

    __tablename__ = "alerts"
    __table_args__ = (
        Index("ix_alerts_status_severity", "status", "severity"),
        Index(
            "ix_alerts_open_dedup",
            "dedup_key",
            postgresql_where=text("status IN ('OPEN', 'ACKNOWLEDGED')"),
        ),
        Index("ix_alerts_last_seen", "last_seen"),
    )

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    alert_type: Mapped[AlertType] = mapped_column(db_enum(AlertType, "alert_type"), nullable=False)
    title: Mapped[str] = mapped_column(String(255), nullable=False)
    description: Mapped[str] = mapped_column(Text, default="", nullable=False)
    status: Mapped[AlertStatus] = mapped_column(
        db_enum(AlertStatus, "alert_status"), default=AlertStatus.OPEN, nullable=False
    )
    severity: Mapped[Severity] = mapped_column(db_enum(Severity, "severity"), nullable=False)
    classification: Mapped[Classification | None] = mapped_column(db_enum(Classification, "classification"))
    category: Mapped[str] = mapped_column(String(64), nullable=False)
    dedup_key: Mapped[str] = mapped_column(String(255), nullable=False)
    src_ip: Mapped[str | None] = mapped_column(INET)
    dst_ip: Mapped[str | None] = mapped_column(INET)
    dst_port: Mapped[int | None] = mapped_column(Integer)
    risk_score: Mapped[float] = mapped_column(Float, default=0.0, nullable=False)
    occurrence_count: Mapped[int] = mapped_column(BigInteger, default=1, nullable=False)
    first_seen: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)
    last_seen: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)
    primary_detection_id: Mapped[int | None] = mapped_column(ForeignKey("detections.id", ondelete="SET NULL"))
    incident_id: Mapped[int | None] = mapped_column(ForeignKey("incidents.id", ondelete="SET NULL"), index=True)
    assigned_to_id: Mapped[int | None] = mapped_column(ForeignKey("users.id", ondelete="SET NULL"))
    acknowledged_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    acknowledged_by_id: Mapped[int | None] = mapped_column(ForeignKey("users.id", ondelete="SET NULL"))
    resolved_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    resolved_by_id: Mapped[int | None] = mapped_column(ForeignKey("users.id", ondelete="SET NULL"))
    is_demo: Mapped[bool] = mapped_column(Boolean, default=False, nullable=False)

    detections = relationship("Detection", secondary=alert_detections, lazy="noload")
