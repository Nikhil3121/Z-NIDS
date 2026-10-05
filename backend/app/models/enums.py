"""Domain enumerations shared by models, schemas and services."""

from __future__ import annotations

from enum import StrEnum

from sqlalchemy import Enum as SAEnum


def db_enum(enum_cls: type[StrEnum], name: str) -> SAEnum:
    """Store enums as VARCHAR + CHECK constraint (portable, migration-friendly)."""
    return SAEnum(
        enum_cls,
        name=name,
        native_enum=False,
        create_constraint=True,
        length=32,
        values_callable=lambda e: [m.value for m in e],
        validate_strings=True,
    )


class RoleName(StrEnum):
    ADMIN = "ADMIN"
    SECURITY_MANAGER = "SECURITY_MANAGER"
    SECURITY_ANALYST = "SECURITY_ANALYST"
    VIEWER = "VIEWER"


class Permission(StrEnum):
    VIEW_EVENTS = "events:view"
    INGEST_EVENTS = "events:ingest"
    VIEW_DETECTIONS = "detections:view"
    VIEW_ALERTS = "alerts:view"
    MANAGE_ALERTS = "alerts:manage"
    VIEW_INCIDENTS = "incidents:view"
    MANAGE_INCIDENTS = "incidents:manage"
    VIEW_ASSETS = "assets:view"
    MANAGE_ASSETS = "assets:manage"
    VIEW_THREAT_INTEL = "threat_intel:view"
    MANAGE_THREAT_INTEL = "threat_intel:manage"
    VIEW_MODELS = "models:view"
    MANAGE_MODELS = "models:manage"
    REQUEST_RESPONSE = "response:request"
    APPROVE_RESPONSE = "response:approve"
    VIEW_REPORTS = "reports:view"
    MANAGE_USERS = "users:manage"
    VIEW_AUDIT = "audit:view"
    MANAGE_SETTINGS = "settings:manage"
    MANAGE_SENSORS = "sensors:manage"
    USE_ASSISTANT = "assistant:use"


_VIEW_ALL = {
    Permission.VIEW_EVENTS,
    Permission.VIEW_DETECTIONS,
    Permission.VIEW_ALERTS,
    Permission.VIEW_INCIDENTS,
    Permission.VIEW_ASSETS,
    Permission.VIEW_THREAT_INTEL,
    Permission.VIEW_MODELS,
    Permission.VIEW_REPORTS,
}

_ANALYST = _VIEW_ALL | {
    Permission.MANAGE_ALERTS,
    Permission.MANAGE_INCIDENTS,
    Permission.MANAGE_THREAT_INTEL,
    Permission.REQUEST_RESPONSE,
    Permission.USE_ASSISTANT,
}

_MANAGER = _ANALYST | {
    Permission.MANAGE_ASSETS,
    Permission.MANAGE_MODELS,
    Permission.APPROVE_RESPONSE,
    Permission.VIEW_AUDIT,
}

# Canonical role -> permission grants. The migration seeds these into the
# roles/permissions tables; the API authorises against the database copy.
ROLE_PERMISSIONS: dict[RoleName, set[Permission]] = {
    RoleName.VIEWER: set(_VIEW_ALL),
    RoleName.SECURITY_ANALYST: _ANALYST,
    RoleName.SECURITY_MANAGER: _MANAGER,
    RoleName.ADMIN: set(Permission),
}


class TokenPurpose(StrEnum):
    ACTIVATION = "ACTIVATION"
    PASSWORD_RESET = "PASSWORD_RESET"  # noqa: S105 - enum label, not a secret


class Protocol(StrEnum):
    TCP = "tcp"
    UDP = "udp"
    ICMP = "icmp"
    OTHER = "other"


class FlowDirection(StrEnum):
    INBOUND = "inbound"
    OUTBOUND = "outbound"
    INTERNAL = "internal"
    EXTERNAL = "external"


class EventSource(StrEnum):
    API = "api"
    ZEEK = "zeek"
    SURICATA = "suricata"
    NETFLOW = "netflow"
    CSV = "csv"
    SYNTHETIC = "synthetic"


class ProcessingStatus(StrEnum):
    PENDING = "PENDING"
    PROCESSED = "PROCESSED"
    FAILED = "FAILED"


class Classification(StrEnum):
    NORMAL = "NORMAL"
    KNOWN_ATTACK = "KNOWN_ATTACK"
    ANOMALOUS = "ANOMALOUS"
    POTENTIAL_UNKNOWN = "POTENTIAL_UNKNOWN"


class Severity(StrEnum):
    INFO = "info"
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"

    @property
    def rank(self) -> int:
        return _SEVERITY_RANK[self]

    @classmethod
    def from_risk(cls, risk: float) -> Severity:
        if risk >= 85:
            return cls.CRITICAL
        if risk >= 65:
            return cls.HIGH
        if risk >= 40:
            return cls.MEDIUM
        if risk >= 20:
            return cls.LOW
        return cls.INFO


_SEVERITY_RANK = {
    Severity.INFO: 0,
    Severity.LOW: 1,
    Severity.MEDIUM: 2,
    Severity.HIGH: 3,
    Severity.CRITICAL: 4,
}


class DetectorType(StrEnum):
    SIGNATURE = "signature"
    ANOMALY = "anomaly"
    BEHAVIORAL = "behavioral"
    THREAT_INTEL = "threat_intel"
    CORRELATION = "correlation"


class AlertStatus(StrEnum):
    OPEN = "OPEN"
    ACKNOWLEDGED = "ACKNOWLEDGED"
    RESOLVED = "RESOLVED"
    SUPPRESSED = "SUPPRESSED"


class AlertType(StrEnum):
    DETECTION = "DETECTION"
    MODEL_DRIFT = "MODEL_DRIFT"
    SYSTEM = "SYSTEM"


class IncidentStatus(StrEnum):
    NEW = "NEW"
    ACKNOWLEDGED = "ACKNOWLEDGED"
    INVESTIGATING = "INVESTIGATING"
    CONFIRMED = "CONFIRMED"
    CONTAINED = "CONTAINED"
    RESOLVED = "RESOLVED"


class IncidentResolution(StrEnum):
    TRUE_POSITIVE = "TRUE_POSITIVE"
    FALSE_POSITIVE = "FALSE_POSITIVE"
    BENIGN = "BENIGN"
    DUPLICATE = "DUPLICATE"


class EvidenceType(StrEnum):
    EVENT = "EVENT"
    DETECTION = "DETECTION"
    NOTE = "NOTE"
    THREAT_INTEL = "THREAT_INTEL"
    ATTACHMENT = "ATTACHMENT"


class ActivityType(StrEnum):
    CREATED = "CREATED"
    STATUS_CHANGED = "STATUS_CHANGED"
    SEVERITY_CHANGED = "SEVERITY_CHANGED"
    ASSIGNED = "ASSIGNED"
    NOTE_ADDED = "NOTE_ADDED"
    EVIDENCE_ADDED = "EVIDENCE_ADDED"
    ALERT_LINKED = "ALERT_LINKED"
    RESPONSE = "RESPONSE"
    ESCALATED = "ESCALATED"


class AssetType(StrEnum):
    SERVER = "server"
    ENDPOINT = "endpoint"
    DATABASE = "database"
    FIREWALL = "firewall"
    SENSOR = "sensor"
    NETWORK_DEVICE = "network_device"
    UNKNOWN = "unknown"


class AssetStatus(StrEnum):
    ACTIVE = "active"
    INACTIVE = "inactive"
    QUARANTINED = "quarantined"
    DISABLED = "disabled"


class Criticality(StrEnum):
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"

    @property
    def score(self) -> float:
        return {"low": 25.0, "medium": 50.0, "high": 75.0, "critical": 95.0}[self.value]


class IocType(StrEnum):
    IP = "ip"
    DOMAIN = "domain"
    URL = "url"
    HASH = "hash"


class Reputation(StrEnum):
    MALICIOUS = "malicious"
    SUSPICIOUS = "suspicious"
    BENIGN = "benign"
    UNKNOWN = "unknown"


class ModelStatus(StrEnum):
    TRAINED = "TRAINED"
    STAGING = "STAGING"
    ACTIVE = "ACTIVE"
    ARCHIVED = "ARCHIVED"
    REJECTED = "REJECTED"


class NotificationEvent(StrEnum):
    CRITICAL_ALERT = "critical_alert"
    UNKNOWN_ANOMALY = "unknown_anomaly"
    INCIDENT_ASSIGNED = "incident_assigned"
    INCIDENT_ESCALATED = "incident_escalated"
    MODEL_DRIFT = "model_drift"
    RESPONSE_APPROVAL = "response_approval"


class ChannelType(StrEnum):
    EMAIL = "email"
    WEBHOOK = "webhook"
    SLACK = "slack"


class DeliveryStatus(StrEnum):
    PENDING = "PENDING"
    SENT = "SENT"
    FAILED = "FAILED"
    SKIPPED = "SKIPPED"


class ResponseActionType(StrEnum):
    BLOCK_IP = "BLOCK_IP"
    QUARANTINE_ASSET = "QUARANTINE_ASSET"
    DISABLE_LAB_ASSET = "DISABLE_LAB_ASSET"
    NOTIFY_ANALYST = "NOTIFY_ANALYST"


class ResponseStatus(StrEnum):
    PROPOSED = "PROPOSED"
    APPROVED = "APPROVED"
    REJECTED = "REJECTED"
    EXECUTED = "EXECUTED"
    FAILED = "FAILED"
    REVERTED = "REVERTED"


class AuditResult(StrEnum):
    SUCCESS = "SUCCESS"
    FAILURE = "FAILURE"
    DENIED = "DENIED"
