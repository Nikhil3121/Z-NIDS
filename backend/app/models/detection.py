"""Detections and MITRE ATT&CK mappings."""

from __future__ import annotations

from datetime import datetime
from typing import Any

from sqlalchemy import BigInteger, Boolean, DateTime, Float, ForeignKey, Index, Integer, String, Text, func
from sqlalchemy.dialects.postgresql import INET, JSONB
from sqlalchemy.orm import Mapped, mapped_column, relationship

from app.db.base import Base
from app.models.enums import Classification, DetectorType, Protocol, Severity, db_enum


class Detection(Base):
    """A non-normal verdict on one event.

    Source/destination are denormalised from the event because detections are
    retained longer than raw events (DETECTION_RETENTION_DAYS vs EVENT_RETENTION_DAYS).
    Every risk component is stored alongside the final score.
    """

    __tablename__ = "detections"
    __table_args__ = (
        Index("ix_detections_ts", "ts"),
        Index("ix_detections_classification_ts", "classification", "ts"),
        Index("ix_detections_src_ts", "src_ip", "ts"),
    )

    id: Mapped[int] = mapped_column(BigInteger, primary_key=True)
    event_id: Mapped[int | None] = mapped_column(ForeignKey("network_events.id", ondelete="SET NULL"), index=True)
    ts: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)
    classification: Mapped[Classification] = mapped_column(db_enum(Classification, "classification"), nullable=False)
    category: Mapped[str] = mapped_column(String(64), nullable=False)
    detector: Mapped[DetectorType] = mapped_column(db_enum(DetectorType, "detector_type"), nullable=False)
    detectors_fired: Mapped[list[str]] = mapped_column(JSONB, default=list, nullable=False)
    src_ip: Mapped[str] = mapped_column(INET, nullable=False)
    src_port: Mapped[int | None] = mapped_column(Integer)
    dst_ip: Mapped[str] = mapped_column(INET, nullable=False)
    dst_port: Mapped[int | None] = mapped_column(Integer)
    protocol: Mapped[Protocol] = mapped_column(db_enum(Protocol, "protocol"), nullable=False)
    anomaly_score: Mapped[float | None] = mapped_column(Float)
    confidence: Mapped[float] = mapped_column(Float, nullable=False)
    severity: Mapped[Severity] = mapped_column(db_enum(Severity, "severity"), nullable=False)
    risk_score: Mapped[float] = mapped_column(Float, nullable=False)
    risk_components: Mapped[dict[str, Any]] = mapped_column(JSONB, default=dict, nullable=False)
    # List of {factor, detail, value, baseline, weight} produced by the detectors.
    explanation: Mapped[list[dict[str, Any]]] = mapped_column(JSONB, default=list, nullable=False)
    summary: Mapped[str] = mapped_column(Text, nullable=False)
    rule_id: Mapped[str | None] = mapped_column(String(64))
    model_version: Mapped[str | None] = mapped_column(String(64))
    # Known-attack family predicted by the supervised model, when confident.
    predicted_family: Mapped[str | None] = mapped_column(String(64))
    is_demo: Mapped[bool] = mapped_column(Boolean, default=False, nullable=False)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), server_default=func.now(), nullable=False)

    mitre_mappings: Mapped[list[MitreMapping]] = relationship(
        back_populates="detection", lazy="selectin", cascade="all, delete-orphan"
    )


class MitreTechnique(Base):
    """Reference catalogue (subset of ATT&CK Enterprise relevant to network telemetry)."""

    __tablename__ = "mitre_techniques"

    technique_id: Mapped[str] = mapped_column(String(16), primary_key=True)
    name: Mapped[str] = mapped_column(String(160), nullable=False)
    tactic: Mapped[str] = mapped_column(String(64), nullable=False)
    description: Mapped[str] = mapped_column(Text, default="", nullable=False)
    url: Mapped[str] = mapped_column(String(255), nullable=False)


class MitreMapping(Base):
    __tablename__ = "mitre_mappings"

    id: Mapped[int] = mapped_column(BigInteger, primary_key=True)
    detection_id: Mapped[int] = mapped_column(
        ForeignKey("detections.id", ondelete="CASCADE"), nullable=False, index=True
    )
    technique_id: Mapped[str] = mapped_column(ForeignKey("mitre_techniques.technique_id"), nullable=False)
    confidence: Mapped[float] = mapped_column(Float, nullable=False)
    evidence: Mapped[str] = mapped_column(Text, nullable=False)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), server_default=func.now(), nullable=False)

    detection: Mapped[Detection] = relationship(back_populates="mitre_mappings")
    technique: Mapped[MitreTechnique] = relationship(lazy="joined")
