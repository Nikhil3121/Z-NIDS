"""Asset inventory and sensors."""

from __future__ import annotations

from datetime import datetime

from sqlalchemy import BigInteger, Boolean, DateTime, Float, Integer, String, Text, func
from sqlalchemy.dialects.postgresql import INET, MACADDR
from sqlalchemy.orm import Mapped, mapped_column

from app.db.base import Base, TimestampMixin
from app.models.enums import AssetStatus, AssetType, Criticality, EventSource, db_enum


class Asset(TimestampMixin, Base):
    __tablename__ = "assets"

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    ip_address: Mapped[str] = mapped_column(INET, unique=True, nullable=False)
    hostname: Mapped[str | None] = mapped_column(String(255), index=True)
    mac_address: Mapped[str | None] = mapped_column(MACADDR)
    asset_type: Mapped[AssetType] = mapped_column(
        db_enum(AssetType, "asset_type"), default=AssetType.UNKNOWN, nullable=False
    )
    operating_system: Mapped[str | None] = mapped_column(String(120))
    environment: Mapped[str | None] = mapped_column(String(64))
    criticality: Mapped[Criticality] = mapped_column(
        db_enum(Criticality, "criticality"), default=Criticality.MEDIUM, nullable=False
    )
    owner: Mapped[str | None] = mapped_column(String(120))
    status: Mapped[AssetStatus] = mapped_column(
        db_enum(AssetStatus, "asset_status"), default=AssetStatus.ACTIVE, nullable=False
    )
    notes: Mapped[str | None] = mapped_column(Text)
    # True when the asset was created from observed traffic rather than by an analyst.
    auto_discovered: Mapped[bool] = mapped_column(Boolean, default=True, nullable=False)
    # Lab/sandbox assets are the only ones the response engine may disable.
    is_lab: Mapped[bool] = mapped_column(Boolean, default=False, nullable=False)
    is_demo: Mapped[bool] = mapped_column(Boolean, default=False, nullable=False, index=True)
    risk_score: Mapped[float] = mapped_column(Float, default=0.0, nullable=False)
    first_seen: Mapped[datetime] = mapped_column(DateTime(timezone=True), server_default=func.now(), nullable=False)
    last_seen: Mapped[datetime] = mapped_column(DateTime(timezone=True), server_default=func.now(), nullable=False)


class Sensor(TimestampMixin, Base):
    """A telemetry producer (Zeek/Suricata forwarder, flow exporter, lab generator).

    Sensors authenticate to the ingestion API with an API key that is stored
    only as a SHA-256 hash; `key_prefix` lets operators identify a key.
    """

    __tablename__ = "sensors"

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    name: Mapped[str] = mapped_column(String(120), unique=True, nullable=False)
    sensor_type: Mapped[EventSource] = mapped_column(db_enum(EventSource, "event_source"), nullable=False)
    api_key_hash: Mapped[str] = mapped_column(String(64), unique=True, nullable=False)
    key_prefix: Mapped[str] = mapped_column(String(12), nullable=False)
    location: Mapped[str | None] = mapped_column(String(120))
    is_active: Mapped[bool] = mapped_column(Boolean, default=True, nullable=False)
    is_demo: Mapped[bool] = mapped_column(Boolean, default=False, nullable=False)
    last_seen: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    events_received: Mapped[int] = mapped_column(BigInteger, default=0, nullable=False)
