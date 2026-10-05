"""ML model registry, evaluations, metrics and drift reports."""

from __future__ import annotations

from datetime import datetime
from typing import Any

from sqlalchemy import (
    Boolean,
    DateTime,
    Float,
    ForeignKey,
    Index,
    Integer,
    String,
    Text,
    UniqueConstraint,
    func,
    text,
)
from sqlalchemy.dialects.postgresql import JSONB
from sqlalchemy.orm import Mapped, mapped_column

from app.db.base import Base
from app.models.enums import ModelStatus, db_enum


class MLModel(Base):
    """A versioned, checksummed model bundle.

    At most one version per model name may be ACTIVE (enforced by a partial
    unique index). Activation is an explicit, audited API call — training never
    replaces the production model.
    """

    __tablename__ = "ml_models"
    __table_args__ = (
        UniqueConstraint("name", "version", name="uq_ml_models_name_version"),
        Index("uq_ml_models_one_active", "name", unique=True, postgresql_where=text("status = 'ACTIVE'")),
    )

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    name: Mapped[str] = mapped_column(String(64), nullable=False)
    version: Mapped[int] = mapped_column(Integer, nullable=False)
    model_type: Mapped[str] = mapped_column(String(64), nullable=False)
    feature_version: Mapped[str] = mapped_column(String(32), nullable=False)
    training_dataset: Mapped[str] = mapped_column(String(255), nullable=False)
    dataset_sha256: Mapped[str] = mapped_column(String(64), nullable=False)
    training_config: Mapped[dict[str, Any]] = mapped_column(JSONB, default=dict, nullable=False)
    trained_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)
    metrics: Mapped[dict[str, Any]] = mapped_column(JSONB, default=dict, nullable=False)
    status: Mapped[ModelStatus] = mapped_column(db_enum(ModelStatus, "model_status"), nullable=False)
    artifact_path: Mapped[str] = mapped_column(String(512), nullable=False)
    checksum_sha256: Mapped[str] = mapped_column(String(64), nullable=False)
    notes: Mapped[str | None] = mapped_column(Text)
    created_by_id: Mapped[int | None] = mapped_column(ForeignKey("users.id", ondelete="SET NULL"))
    activated_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    activated_by_id: Mapped[int | None] = mapped_column(ForeignKey("users.id", ondelete="SET NULL"))
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), server_default=func.now(), nullable=False)

    @property
    def tag(self) -> str:
        return f"{self.name}-v{self.version}"


class ModelEvaluation(Base):
    """One evaluation run (e.g. held-out-family experiment) of one model."""

    __tablename__ = "model_evaluations"

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    model_id: Mapped[int] = mapped_column(ForeignKey("ml_models.id", ondelete="CASCADE"), nullable=False, index=True)
    dataset: Mapped[str] = mapped_column(String(255), nullable=False)
    dataset_sha256: Mapped[str] = mapped_column(String(64), nullable=False)
    heldout_families: Mapped[list[str]] = mapped_column(JSONB, default=list, nullable=False)
    is_synthetic: Mapped[bool] = mapped_column(Boolean, nullable=False)
    config: Mapped[dict[str, Any]] = mapped_column(JSONB, default=dict, nullable=False)
    summary: Mapped[dict[str, Any]] = mapped_column(JSONB, default=dict, nullable=False)
    confusion_matrix: Mapped[dict[str, Any]] = mapped_column(JSONB, default=dict, nullable=False)
    per_family: Mapped[dict[str, Any]] = mapped_column(JSONB, default=dict, nullable=False)
    report_path: Mapped[str | None] = mapped_column(String(512))
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), server_default=func.now(), nullable=False)


class ModelMetric(Base):
    """Flat metric rows for querying/charting (one row per metric per scope)."""

    __tablename__ = "model_metrics"
    __table_args__ = (Index("ix_model_metrics_model_name", "model_id", "metric_name"),)

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    model_id: Mapped[int] = mapped_column(ForeignKey("ml_models.id", ondelete="CASCADE"), nullable=False)
    evaluation_id: Mapped[int | None] = mapped_column(ForeignKey("model_evaluations.id", ondelete="CASCADE"))
    scope: Mapped[str] = mapped_column(String(64), nullable=False)  # overall | known | unknown | family:<x> | drift
    metric_name: Mapped[str] = mapped_column(String(64), nullable=False)
    metric_value: Mapped[float | None] = mapped_column(Float)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), server_default=func.now(), nullable=False)


class DriftReport(Base):
    __tablename__ = "drift_reports"

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    model_id: Mapped[int] = mapped_column(ForeignKey("ml_models.id", ondelete="CASCADE"), nullable=False, index=True)
    window_start: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)
    window_end: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)
    sample_size: Mapped[int] = mapped_column(Integer, nullable=False)
    threshold: Mapped[float] = mapped_column(Float, nullable=False)
    feature_psi: Mapped[dict[str, float]] = mapped_column(JSONB, default=dict, nullable=False)
    max_psi: Mapped[float] = mapped_column(Float, nullable=False)
    drifted: Mapped[bool] = mapped_column(Boolean, nullable=False)
    alert_id: Mapped[int | None] = mapped_column(ForeignKey("alerts.id", ondelete="SET NULL"))
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), server_default=func.now(), nullable=False)
