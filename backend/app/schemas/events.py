"""Normalised event ingestion schema and event read models."""

from __future__ import annotations

import ipaddress
import re
from datetime import UTC, datetime, timedelta
from typing import Any

from pydantic import BaseModel, ConfigDict, Field, field_validator, model_validator

from app.models.enums import Classification, EventSource, FlowDirection, ProcessingStatus, Protocol
from app.schemas.common import IPStr, Schema

_FLAG_BITS = {
    "F": 1,
    "FIN": 1,
    "S": 2,
    "SYN": 2,
    "R": 4,
    "RST": 4,
    "P": 8,
    "PSH": 8,
    "A": 16,
    "ACK": 16,
    "U": 32,
    "URG": 32,
}
_PROTO_NUMBERS = {"6": "tcp", "17": "udp", "1": "icmp", "58": "icmp"}
_TOKEN = re.compile(r"^[A-Za-z0-9_.\-]{1,32}$")
MAX_BYTES = 10**13  # 10 TB — anything above is a sensor bug, not a flow
MAX_PACKETS = 10**11
MAX_DURATION_MS = 7 * 24 * 3600 * 1000


class ExternalAlert(BaseModel):
    model_config = ConfigDict(extra="ignore", str_strip_whitespace=True)
    signature: str = Field(max_length=255)
    signature_id: int | str | None = None
    category: str | None = Field(default=None, max_length=128)
    severity: int | None = Field(default=None, ge=1, le=4)


class EventIn(BaseModel):
    """One flow record from any sensor, after adapter normalisation."""

    model_config = ConfigDict(extra="forbid", str_strip_whitespace=True)

    ts: datetime
    src_ip: str
    dst_ip: str
    src_port: int | None = Field(default=None, ge=0, le=65535)
    dst_port: int | None = Field(default=None, ge=0, le=65535)
    protocol: Protocol
    app_protocol: str | None = Field(default=None, max_length=32)
    duration_ms: float = Field(default=0.0, ge=0, le=MAX_DURATION_MS)
    packets_out: int = Field(default=0, ge=0, le=MAX_PACKETS)
    packets_in: int = Field(default=0, ge=0, le=MAX_PACKETS)
    bytes_out: int = Field(default=0, ge=0, le=MAX_BYTES)
    bytes_in: int = Field(default=0, ge=0, le=MAX_BYTES)
    tcp_flags: int = Field(default=0, ge=0, le=255)
    conn_state: str | None = Field(default=None, max_length=16)
    external_id: str | None = Field(default=None, max_length=128)
    raw_ref: str | None = Field(default=None, max_length=255)
    external_alert: ExternalAlert | None = None
    #: Ground-truth label — honoured only for lab/demo sensors and dataset imports.
    dataset_label: str | None = Field(default=None, max_length=64)

    @field_validator("src_ip", "dst_ip")
    @classmethod
    def _ip(cls, v: str) -> str:
        try:
            return str(ipaddress.ip_address(v))
        except ValueError as exc:
            raise ValueError("invalid IP address") from exc

    @field_validator("protocol", mode="before")
    @classmethod
    def _protocol(cls, v: Any) -> Any:
        if isinstance(v, int | str):
            s = str(v).strip().lower()
            s = _PROTO_NUMBERS.get(s, s)
            return s if s in {p.value for p in Protocol} else "other"
        return v

    @field_validator("tcp_flags", mode="before")
    @classmethod
    def _flags(cls, v: Any) -> Any:
        if isinstance(v, list):
            mask = 0
            for item in v:
                bit = _FLAG_BITS.get(str(item).upper())
                if bit is None:
                    raise ValueError(f"unknown TCP flag {item!r}")
                mask |= bit
            return mask
        if isinstance(v, str) and not v.isdigit():
            mask = 0
            for ch in v.upper():
                if ch not in _FLAG_BITS:
                    raise ValueError(f"unknown TCP flag {ch!r}")
                mask |= _FLAG_BITS[ch]
            return mask
        return v

    @field_validator("app_protocol")
    @classmethod
    def _app_protocol(cls, v: str | None) -> str | None:
        if v in (None, "", "-"):
            return None
        if not _TOKEN.match(v):
            raise ValueError("must be 1-32 characters of [A-Za-z0-9_.-]")
        return v.lower()

    @field_validator("conn_state")
    @classmethod
    def _conn_state(cls, v: str | None) -> str | None:
        if v in (None, "", "-"):
            return None
        if not _TOKEN.match(v) or len(v) > 16:
            raise ValueError("must be 1-16 characters of [A-Za-z0-9_.-]")
        return v.upper()

    @field_validator("ts")
    @classmethod
    def _ts(cls, v: datetime) -> datetime:
        if v.tzinfo is None:
            v = v.replace(tzinfo=UTC)
        now = datetime.now(UTC)
        if v > now + timedelta(minutes=5):
            raise ValueError("timestamp is in the future")
        if v < now - timedelta(days=3650):
            raise ValueError("timestamp is too old")
        return v.astimezone(UTC)

    @model_validator(mode="after")
    def _consistency(self) -> EventIn:
        if self.protocol != Protocol.TCP and self.tcp_flags:
            self.tcp_flags = 0
        return self


class IngestRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")
    events: list[dict[str, Any]] = Field(min_length=1, max_length=5000)


class RejectedEvent(BaseModel):
    index: int
    errors: list[str]


class IngestResponse(BaseModel):
    accepted: int
    duplicates: int
    rejected: list[RejectedEvent]
    queued: bool
    event_ids: list[int]


class EventOut(Schema):
    id: int
    ts: datetime
    src_ip: IPStr
    src_port: int | None
    dst_ip: IPStr
    dst_port: int | None
    protocol: Protocol
    app_protocol: str | None
    duration_ms: float
    packets_out: int
    packets_in: int
    bytes_out: int
    bytes_in: int
    tcp_flags: int
    conn_state: str | None
    direction: FlowDirection
    source_type: EventSource
    sensor_id: int | None
    raw_ref: str | None
    is_demo: bool
    processing_status: ProcessingStatus
    classification: Classification | None
    anomaly_score: float | None
    risk_score: float | None
    ingested_at: datetime
    external_alert: dict[str, Any] | None = None
