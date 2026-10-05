"""Response/request schemas for detections, alerts, incidents, assets, sensors."""

from __future__ import annotations

from datetime import datetime
from typing import Any

from pydantic import Field, field_validator

from app.models.enums import (
    ActivityType,
    AlertStatus,
    AlertType,
    AssetStatus,
    AssetType,
    Classification,
    Criticality,
    DetectorType,
    EventSource,
    EvidenceType,
    IncidentResolution,
    IncidentStatus,
    Protocol,
    ResponseActionType,
    ResponseStatus,
    Severity,
)
from app.schemas.common import IPStr, Schema, StrictInput


class UserRef(Schema):
    id: int
    name: str
    email: str


class MitreMappingOut(Schema):
    technique_id: str
    name: str
    tactic: str
    url: str
    confidence: float
    evidence: str


class DetectionOut(Schema):
    id: int
    event_id: int | None
    ts: datetime
    classification: Classification
    category: str
    detector: DetectorType
    detectors_fired: list[str]
    src_ip: IPStr
    src_port: int | None
    dst_ip: IPStr
    dst_port: int | None
    protocol: Protocol
    anomaly_score: float | None
    confidence: float
    severity: Severity
    risk_score: float
    risk_components: dict[str, Any]
    explanation: list[dict[str, Any]]
    summary: str
    rule_id: str | None
    model_version: str | None
    predicted_family: str | None
    is_demo: bool
    mitre: list[MitreMappingOut] = Field(default_factory=list)


class AlertOut(Schema):
    id: int
    alert_type: AlertType
    title: str
    description: str
    status: AlertStatus
    severity: Severity
    classification: Classification | None
    category: str
    src_ip: IPStr | None
    dst_ip: IPStr | None
    dst_port: int | None
    risk_score: float
    occurrence_count: int
    first_seen: datetime
    last_seen: datetime
    primary_detection_id: int | None
    incident_id: int | None
    assigned_to_id: int | None
    acknowledged_at: datetime | None
    resolved_at: datetime | None
    is_demo: bool
    created_at: datetime


class AlertUpdate(StrictInput):
    status: AlertStatus | None = None
    assigned_to_id: int | None = Field(default=None, ge=1)
    unassign: bool = False
    note: str | None = Field(default=None, max_length=2000)


class IncidentOut(Schema):
    id: int
    reference: str
    title: str
    severity: Severity
    status: IncidentStatus
    classification: Classification | None
    risk_score: float
    correlation_rule: str | None
    primary_src_ip: IPStr | None
    first_seen: datetime
    last_seen: datetime
    assigned_to: UserRef | None
    resolution: IncidentResolution | None
    is_demo: bool
    created_at: datetime
    updated_at: datetime


class ActivityOut(Schema):
    id: int
    activity_type: ActivityType
    from_value: str | None
    to_value: str | None
    message: str
    actor: UserRef | None
    created_at: datetime


class EvidenceOut(Schema):
    id: int
    evidence_type: EvidenceType
    event_id: int | None
    detection_id: int | None
    threat_intel_id: int | None
    content: str | None
    attachment: dict[str, Any] | None
    created_by: UserRef | None
    created_at: datetime


class IncidentUpdate(StrictInput):
    status: IncidentStatus | None = None
    resolution: IncidentResolution | None = None
    resolution_notes: str | None = Field(default=None, max_length=5000)
    severity: Severity | None = None
    severity_reason: str | None = Field(default=None, max_length=500)
    assigned_to_id: int | None = Field(default=None, ge=1)
    unassign: bool = False


class NoteIn(StrictInput):
    text: str = Field(min_length=1, max_length=10_000)


class EvidenceIn(StrictInput):
    evidence_type: EvidenceType
    event_id: int | None = Field(default=None, ge=1)
    detection_id: int | None = Field(default=None, ge=1)
    threat_intel_id: int | None = Field(default=None, ge=1)
    content: str | None = Field(default=None, max_length=10_000)

    @field_validator("evidence_type")
    @classmethod
    def _no_attachment(cls, v: EvidenceType) -> EvidenceType:
        if v in (EvidenceType.ATTACHMENT, EvidenceType.NOTE):
            raise ValueError("use the notes or attachments endpoint for this evidence type")
        return v


class AssetOut(Schema):
    id: int
    ip_address: IPStr
    hostname: str | None
    mac_address: str | None
    asset_type: AssetType
    operating_system: str | None
    environment: str | None
    criticality: Criticality
    owner: str | None
    status: AssetStatus
    notes: str | None
    auto_discovered: bool
    is_lab: bool
    is_demo: bool
    risk_score: float
    first_seen: datetime
    last_seen: datetime


class AssetIn(StrictInput):
    ip_address: str
    hostname: str | None = Field(default=None, max_length=255, pattern=r"^[A-Za-z0-9.\-_]*$")
    mac_address: str | None = Field(default=None, pattern=r"^([0-9A-Fa-f]{2}[:-]){5}[0-9A-Fa-f]{2}$")
    asset_type: AssetType = AssetType.UNKNOWN
    operating_system: str | None = Field(default=None, max_length=120)
    environment: str | None = Field(default=None, max_length=64)
    criticality: Criticality = Criticality.MEDIUM
    owner: str | None = Field(default=None, max_length=120)
    notes: str | None = Field(default=None, max_length=5000)
    is_lab: bool = False


class AssetPatch(StrictInput):
    hostname: str | None = Field(default=None, max_length=255, pattern=r"^[A-Za-z0-9.\-_]*$")
    mac_address: str | None = Field(default=None, pattern=r"^([0-9A-Fa-f]{2}[:-]){5}[0-9A-Fa-f]{2}$")
    asset_type: AssetType | None = None
    operating_system: str | None = Field(default=None, max_length=120)
    environment: str | None = Field(default=None, max_length=64)
    criticality: Criticality | None = None
    owner: str | None = Field(default=None, max_length=120)
    status: AssetStatus | None = None
    notes: str | None = Field(default=None, max_length=5000)
    is_lab: bool | None = None


class SensorOut(Schema):
    id: int
    name: str
    sensor_type: EventSource
    key_prefix: str
    location: str | None
    is_active: bool
    is_demo: bool
    last_seen: datetime | None
    events_received: int
    created_at: datetime


class SensorCreate(StrictInput):
    name: str = Field(min_length=2, max_length=120, pattern=r"^[A-Za-z0-9 ._\-]+$")
    sensor_type: EventSource
    location: str | None = Field(default=None, max_length=120)
    is_demo: bool = False


class SensorCreated(SensorOut):
    api_key: str = Field(description="Shown exactly once. Store it in the sensor's secret store.")


class ResponseActionOut(Schema):
    id: int
    action_type: ResponseActionType
    target: str
    reason: str
    status: ResponseStatus
    mode: str
    adapter: str
    incident_id: int | None
    alert_id: int | None
    requested_by_id: int | None
    decided_by_id: int | None
    decided_at: datetime | None
    executed_at: datetime | None
    result: dict[str, Any]
    created_at: datetime


class ResponseRequest(StrictInput):
    action_type: ResponseActionType
    target: str = Field(min_length=2, max_length=64)
    reason: str = Field(min_length=5, max_length=2000)
    incident_id: int | None = Field(default=None, ge=1)
    alert_id: int | None = Field(default=None, ge=1)


class ResponseDecision(StrictInput):
    approve: bool
    comment: str | None = Field(default=None, max_length=2000)
