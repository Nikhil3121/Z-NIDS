"""Normalized network flow events, rollups and behavioral baselines."""

from __future__ import annotations

from datetime import datetime
from typing import Any

from sqlalchemy import (
    BigInteger,
    Boolean,
    DateTime,
    Float,
    ForeignKey,
    Index,
    Integer,
    SmallInteger,
    String,
    UniqueConstraint,
    func,
    text,
)
from sqlalchemy.dialects.postgresql import INET, JSONB
from sqlalchemy.orm import Mapped, mapped_column

from app.db.base import Base
from app.models.enums import (
    Classification,
    EventSource,
    FlowDirection,
    ProcessingStatus,
    Protocol,
    db_enum,
)


class NetworkEvent(Base):
    """One normalized flow record.

    Only flow metadata is stored — never packet payloads. `raw_ref` points back
    at the originating log line / record so an analyst can pivot to the sensor.
    Rows are purged by the retention task after EVENT_RETENTION_DAYS.
    """

    __tablename__ = "network_events"
    __table_args__ = (
        UniqueConstraint("sensor_id", "external_id", name="uq_network_events_sensor_external"),
        Index("ix_network_events_ts", "ts"),
        Index("ix_network_events_src_ts", "src_ip", "ts"),
        Index("ix_network_events_dst_ts", "dst_ip", "ts"),
        Index(
            "ix_network_events_pending",
            "id",
            postgresql_where=text("processing_status = 'PENDING'"),
        ),
        Index("ix_network_events_classification_ts", "classification", "ts"),
    )

    id: Mapped[int] = mapped_column(BigInteger, primary_key=True)
    # Sensor-supplied identifier (Zeek uid, Suricata flow_id, ...) for idempotent re-ingest.
    external_id: Mapped[str | None] = mapped_column(String(128))
    ts: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)
    src_ip: Mapped[str] = mapped_column(INET, nullable=False)
    src_port: Mapped[int | None] = mapped_column(Integer)
    dst_ip: Mapped[str] = mapped_column(INET, nullable=False)
    dst_port: Mapped[int | None] = mapped_column(Integer)
    protocol: Mapped[Protocol] = mapped_column(db_enum(Protocol, "protocol"), nullable=False)
    app_protocol: Mapped[str | None] = mapped_column(String(32))
    duration_ms: Mapped[float] = mapped_column(Float, default=0.0, nullable=False)
    packets_out: Mapped[int] = mapped_column(BigInteger, default=0, nullable=False)
    packets_in: Mapped[int] = mapped_column(BigInteger, default=0, nullable=False)
    bytes_out: Mapped[int] = mapped_column(BigInteger, default=0, nullable=False)
    bytes_in: Mapped[int] = mapped_column(BigInteger, default=0, nullable=False)
    # Bitmask: FIN=1 SYN=2 RST=4 PSH=8 ACK=16 URG=32 (union over the flow).
    tcp_flags: Mapped[int] = mapped_column(SmallInteger, default=0, nullable=False)
    # Zeek-style connection state (S0, SF, REJ, RSTO, ...), when the sensor provides one.
    conn_state: Mapped[str | None] = mapped_column(String(16))
    direction: Mapped[FlowDirection] = mapped_column(db_enum(FlowDirection, "flow_direction"), nullable=False)
    source_type: Mapped[EventSource] = mapped_column(db_enum(EventSource, "event_source"), nullable=False)
    sensor_id: Mapped[int | None] = mapped_column(ForeignKey("sensors.id", ondelete="SET NULL"))
    raw_ref: Mapped[str | None] = mapped_column(String(255))
    is_demo: Mapped[bool] = mapped_column(Boolean, default=False, nullable=False)
    # Alert metadata forwarded by an external IDS (e.g. Suricata signature hit).
    external_alert: Mapped[dict[str, Any] | None] = mapped_column(JSONB)
    # Ground-truth label from a labelled research dataset. Never shown as a detection.
    dataset_label: Mapped[str | None] = mapped_column(String(64))

    processing_status: Mapped[ProcessingStatus] = mapped_column(
        db_enum(ProcessingStatus, "processing_status"), default=ProcessingStatus.PENDING, nullable=False
    )
    classification: Mapped[Classification | None] = mapped_column(db_enum(Classification, "classification"))
    anomaly_score: Mapped[float | None] = mapped_column(Float)
    risk_score: Mapped[float | None] = mapped_column(Float)
    processed_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    ingested_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), server_default=func.now(), nullable=False)

    @property
    def total_bytes(self) -> int:
        return self.bytes_in + self.bytes_out

    @property
    def total_packets(self) -> int:
        return self.packets_in + self.packets_out


class EventRollup(Base):
    """Per-minute aggregate used by the dashboard instead of scanning raw events."""

    __tablename__ = "event_rollups"

    bucket: Mapped[datetime] = mapped_column(DateTime(timezone=True), primary_key=True)
    is_demo: Mapped[bool] = mapped_column(Boolean, primary_key=True)
    events: Mapped[int] = mapped_column(BigInteger, default=0, nullable=False)
    bytes: Mapped[int] = mapped_column(BigInteger, default=0, nullable=False)
    packets: Mapped[int] = mapped_column(BigInteger, default=0, nullable=False)
    normal: Mapped[int] = mapped_column(BigInteger, default=0, nullable=False)
    anomalous: Mapped[int] = mapped_column(BigInteger, default=0, nullable=False)
    known_attack: Mapped[int] = mapped_column(BigInteger, default=0, nullable=False)
    potential_unknown: Mapped[int] = mapped_column(BigInteger, default=0, nullable=False)


class Baseline(Base):
    """Running mean/variance (Welford) of a behavioural metric for one entity.

    entity_type is one of: global, asset, protocol, hour. The detection engine
    only trusts a baseline once `count` reaches BASELINE_MIN_OBSERVATIONS so new
    assets are not judged against an empty history.
    """

    __tablename__ = "baselines"
    __table_args__ = (UniqueConstraint("entity_type", "entity_key", "metric", name="uq_baselines_entity_metric"),)

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    entity_type: Mapped[str] = mapped_column(String(16), nullable=False)
    entity_key: Mapped[str] = mapped_column(String(64), nullable=False)
    metric: Mapped[str] = mapped_column(String(48), nullable=False)
    count: Mapped[int] = mapped_column(BigInteger, default=0, nullable=False)
    mean: Mapped[float] = mapped_column(Float, default=0.0, nullable=False)
    m2: Mapped[float] = mapped_column(Float, default=0.0, nullable=False)
    updated_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), server_default=func.now(), onupdate=func.now(), nullable=False
    )
