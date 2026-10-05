"""Threat-intelligence indicators (cached provider results and analyst-managed IOCs)."""

from __future__ import annotations

from datetime import datetime
from typing import Any

from sqlalchemy import CheckConstraint, DateTime, Float, ForeignKey, Index, Integer, String, UniqueConstraint, func
from sqlalchemy.dialects.postgresql import JSONB
from sqlalchemy.orm import Mapped, mapped_column

from app.db.base import Base
from app.models.enums import IocType, Reputation, db_enum


class ThreatIntelIndicator(Base):
    """One provider's opinion about one IOC.

    `provider='local'` rows are IOCs entered or imported by analysts. Provider
    rows are cached lookups that expire at `expires_at`; nothing here is ever
    synthesised by Z-NIDS itself.
    """

    __tablename__ = "threat_intel_indicators"
    __table_args__ = (
        UniqueConstraint("ioc_type", "ioc_value", "provider", name="uq_ti_ioc_provider"),
        Index("ix_ti_value", "ioc_value"),
        CheckConstraint("confidence >= 0 AND confidence <= 100", name="confidence_range"),
    )

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    ioc_type: Mapped[IocType] = mapped_column(db_enum(IocType, "ioc_type"), nullable=False)
    ioc_value: Mapped[str] = mapped_column(String(512), nullable=False)
    provider: Mapped[str] = mapped_column(String(64), nullable=False)
    confidence: Mapped[float] = mapped_column(Float, nullable=False)
    reputation: Mapped[Reputation] = mapped_column(db_enum(Reputation, "reputation"), nullable=False)
    source: Mapped[str | None] = mapped_column(String(255))
    tags: Mapped[list[str]] = mapped_column(JSONB, default=list, nullable=False)
    raw_metadata: Mapped[dict[str, Any]] = mapped_column(JSONB, default=dict, nullable=False)
    first_seen: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    last_seen: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    fetched_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), server_default=func.now(), nullable=False)
    expires_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    created_by_id: Mapped[int | None] = mapped_column(ForeignKey("users.id", ondelete="SET NULL"))
