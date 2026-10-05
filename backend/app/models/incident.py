"""Incidents, their activity timeline, evidence and affected assets."""

from __future__ import annotations

from datetime import datetime
from typing import Any

from sqlalchemy import (
    BigInteger,
    Boolean,
    CheckConstraint,
    DateTime,
    Float,
    ForeignKey,
    Identity,
    Index,
    Integer,
    String,
    Text,
    UniqueConstraint,
    func,
)
from sqlalchemy.dialects.postgresql import INET, JSONB
from sqlalchemy.orm import Mapped, mapped_column, relationship

from app.db.base import Base, TimestampMixin
from app.models.enums import (
    ActivityType,
    Classification,
    EvidenceType,
    IncidentResolution,
    IncidentStatus,
    Severity,
    db_enum,
)


class Incident(TimestampMixin, Base):
    __tablename__ = "incidents"
    __table_args__ = (
        Index("ix_incidents_status_severity", "status", "severity"),
        Index("ix_incidents_correlation_key", "correlation_key"),
        CheckConstraint("(status = 'RESOLVED') = (resolution IS NOT NULL)", name="resolution_iff_resolved"),
    )

    # Starts at 1001 so the public reference reads INC-1001, INC-1002, ...
    id: Mapped[int] = mapped_column(Integer, Identity(start=1001), primary_key=True)
    title: Mapped[str] = mapped_column(String(255), nullable=False)
    description: Mapped[str] = mapped_column(Text, default="", nullable=False)
    severity: Mapped[Severity] = mapped_column(db_enum(Severity, "severity"), nullable=False)
    status: Mapped[IncidentStatus] = mapped_column(
        db_enum(IncidentStatus, "incident_status"), default=IncidentStatus.NEW, nullable=False
    )
    classification: Mapped[Classification | None] = mapped_column(db_enum(Classification, "classification"))
    risk_score: Mapped[float] = mapped_column(Float, default=0.0, nullable=False)
    correlation_key: Mapped[str | None] = mapped_column(String(255))
    correlation_rule: Mapped[str | None] = mapped_column(String(64))
    # Ordered kill-chain stages observed, e.g. [{"stage": "discovery", "alert_id": 4, "ts": ...}].
    attack_chain: Mapped[list[dict[str, Any]]] = mapped_column(JSONB, default=list, nullable=False)
    primary_src_ip: Mapped[str | None] = mapped_column(INET)
    first_seen: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)
    last_seen: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)
    assigned_to_id: Mapped[int | None] = mapped_column(ForeignKey("users.id", ondelete="SET NULL"))
    created_by_id: Mapped[int | None] = mapped_column(ForeignKey("users.id", ondelete="SET NULL"))
    resolution: Mapped[IncidentResolution | None] = mapped_column(db_enum(IncidentResolution, "incident_resolution"))
    resolution_notes: Mapped[str | None] = mapped_column(Text)
    resolved_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    is_demo: Mapped[bool] = mapped_column(Boolean, default=False, nullable=False)

    @property
    def reference(self) -> str:
        return f"INC-{self.id}"

    assigned_to = relationship("User", foreign_keys=[assigned_to_id], lazy="joined")


class IncidentActivity(Base):
    """Incident-scoped timeline of human and system actions."""

    __tablename__ = "incident_activities"

    id: Mapped[int] = mapped_column(BigInteger, primary_key=True)
    incident_id: Mapped[int] = mapped_column(ForeignKey("incidents.id", ondelete="CASCADE"), nullable=False, index=True)
    actor_id: Mapped[int | None] = mapped_column(ForeignKey("users.id", ondelete="SET NULL"))
    activity_type: Mapped[ActivityType] = mapped_column(db_enum(ActivityType, "activity_type"), nullable=False)
    from_value: Mapped[str | None] = mapped_column(String(255))
    to_value: Mapped[str | None] = mapped_column(String(255))
    message: Mapped[str] = mapped_column(Text, default="", nullable=False)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), server_default=func.now(), nullable=False)

    actor = relationship("User", lazy="joined")


class Evidence(Base):
    __tablename__ = "evidence"
    __table_args__ = (
        CheckConstraint(
            "(evidence_type <> 'NOTE') OR (content IS NOT NULL AND length(content) > 0)", name="note_has_content"
        ),
    )

    id: Mapped[int] = mapped_column(BigInteger, primary_key=True)
    incident_id: Mapped[int] = mapped_column(ForeignKey("incidents.id", ondelete="CASCADE"), nullable=False, index=True)
    evidence_type: Mapped[EvidenceType] = mapped_column(db_enum(EvidenceType, "evidence_type"), nullable=False)
    event_id: Mapped[int | None] = mapped_column(ForeignKey("network_events.id", ondelete="SET NULL"))
    detection_id: Mapped[int | None] = mapped_column(ForeignKey("detections.id", ondelete="SET NULL"))
    threat_intel_id: Mapped[int | None] = mapped_column(ForeignKey("threat_intel_indicators.id", ondelete="SET NULL"))
    content: Mapped[str | None] = mapped_column(Text)
    # For attachments: {filename, size, sha256, content_type, storage_key}
    attachment: Mapped[dict[str, Any] | None] = mapped_column(JSONB)
    created_by_id: Mapped[int | None] = mapped_column(ForeignKey("users.id", ondelete="SET NULL"))
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), server_default=func.now(), nullable=False)

    created_by = relationship("User", lazy="joined")


class IncidentAsset(Base):
    __tablename__ = "incident_assets"
    __table_args__ = (UniqueConstraint("incident_id", "asset_id", name="uq_incident_assets_pair"),)

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    incident_id: Mapped[int] = mapped_column(ForeignKey("incidents.id", ondelete="CASCADE"), nullable=False, index=True)
    asset_id: Mapped[int] = mapped_column(ForeignKey("assets.id", ondelete="CASCADE"), nullable=False)
    role: Mapped[str] = mapped_column(String(16), nullable=False)  # source | target
