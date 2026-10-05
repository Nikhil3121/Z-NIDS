"""Alert creation (with deduplication) and the analyst alert workflow."""

from __future__ import annotations

import logging
from dataclasses import dataclass, field
from datetime import UTC, datetime, timedelta

from sqlalchemy import insert, select
from sqlalchemy.orm import Session

from app.core.config import get_settings
from app.core.exceptions import InvalidStateTransitionError, NotFoundError
from app.core.metrics import ALERTS_CREATED
from app.models.alert import Alert, alert_detections
from app.models.detection import Detection
from app.models.enums import AlertStatus, AlertType, Classification, Severity
from app.models.user import User
from app.services import audit_service
from app.services.audit_service import RequestMeta

logger = logging.getLogger(__name__)

_TITLES = {
    "port_scan": "Port scan from {src}",
    "brute_force": "Brute-force attempts from {src} against {dst}:{port}",
    "ddos": "Denial-of-service flood against {dst}",
    "suspicious_port": "Outbound connection to a commonly abused port from {src}",
    "cleartext_protocol": "Cleartext remote administration session from {src}",
    "threat_intel_match": "Traffic involving a threat-intelligence indicator ({src} → {dst})",
    "unknown_anomaly": "Potential unknown attack behaviour from {src}",
    "behavioral_anomaly": "Behavioural anomaly: {src} deviates from its baseline",
    "external_ids_alert": "External IDS alert: {src} → {dst}",
}


def dedup_key(det: Detection) -> str:
    src, dst, port = str(det.src_ip), str(det.dst_ip), det.dst_port
    if det.category == "ddos":
        return f"ddos|dst:{dst}"
    if det.category in ("port_scan", "unknown_anomaly", "behavioral_anomaly"):
        return f"{det.category}|{src}"
    if det.category == "brute_force":
        return f"brute_force|{src}|{dst}:{port}"
    return f"{det.category}|{src}|{dst}"


def title_for(det: Detection) -> str:
    template = _TITLES.get(det.category, "{family} activity from {src}")
    if det.classification == Classification.KNOWN_ATTACK and det.category not in _TITLES:
        template = "Known attack pattern '{family}' from {src}"
    return template.format(src=det.src_ip, dst=det.dst_ip, port=det.dst_port, family=det.category.replace("_", " "))


@dataclass
class AlertChange:
    alert: Alert
    created: bool
    escalated: bool = False


@dataclass
class AlertBatcher:
    """Folds a batch of detections into alerts with one DB lookup per dedup key."""

    db: Session
    window: timedelta = field(default_factory=lambda: timedelta(minutes=get_settings().alert_dedup_minutes))
    _open: dict[str, Alert | None] = field(default_factory=dict)
    changes: dict[int, AlertChange] = field(default_factory=dict)
    _links: set[tuple[int, int]] = field(default_factory=set)

    def _find_open(self, key: str, ts: datetime) -> Alert | None:
        if key not in self._open:
            self._open[key] = self.db.scalar(
                select(Alert)
                .where(
                    Alert.dedup_key == key,
                    Alert.status.in_([AlertStatus.OPEN, AlertStatus.ACKNOWLEDGED]),
                    Alert.last_seen >= ts - self.window,
                )
                .order_by(Alert.last_seen.desc())
                .limit(1)
                .with_for_update(key_share=True)
            )
        return self._open[key]

    def add(self, det: Detection) -> Alert:
        key = dedup_key(det)
        alert = self._find_open(key, det.ts)
        if alert is None:
            alert = Alert(
                alert_type=AlertType.DETECTION,
                title=title_for(det)[:255],
                description=det.summary,
                status=AlertStatus.OPEN,
                severity=det.severity,
                classification=det.classification,
                category=det.category,
                dedup_key=key,
                src_ip=det.src_ip,
                dst_ip=det.dst_ip,
                dst_port=det.dst_port,
                risk_score=det.risk_score,
                occurrence_count=1,
                first_seen=det.ts,
                last_seen=det.ts,
                primary_detection_id=det.id,
                is_demo=det.is_demo,
            )
            self.db.add(alert)
            self.db.flush()
            self._open[key] = alert
            self.changes[alert.id] = AlertChange(alert, created=True)
            ALERTS_CREATED.labels(severity=det.severity.value).inc()
        else:
            alert.occurrence_count += 1
            if det.ts > alert.last_seen:
                alert.last_seen = det.ts
            escalated = Severity(det.severity).rank > Severity(alert.severity).rank
            if escalated:
                alert.severity = det.severity
            if det.risk_score > alert.risk_score:
                alert.risk_score = det.risk_score
                alert.primary_detection_id = det.id
                alert.description = det.summary
            # A potential-unknown verdict outranks plain anomalous for the same actor.
            if det.classification == Classification.POTENTIAL_UNKNOWN or alert.classification is None:
                alert.classification = det.classification
            change = self.changes.get(alert.id)
            if change is None:
                self.changes[alert.id] = AlertChange(alert, created=False, escalated=escalated)
            elif escalated:
                change.escalated = True
        if (alert.id, det.id) not in self._links:
            self._links.add((alert.id, det.id))
        return alert

    def flush_links(self) -> None:
        if self._links:
            self.db.execute(
                insert(alert_detections),
                [{"alert_id": a, "detection_id": d} for a, d in self._links],
            )
            self._links.clear()


# --- analyst workflow ---------------------------------------------------------

_ALLOWED = {
    AlertStatus.OPEN: {AlertStatus.ACKNOWLEDGED, AlertStatus.RESOLVED, AlertStatus.SUPPRESSED},
    AlertStatus.ACKNOWLEDGED: {AlertStatus.RESOLVED, AlertStatus.SUPPRESSED, AlertStatus.OPEN},
    AlertStatus.RESOLVED: {AlertStatus.OPEN},
    AlertStatus.SUPPRESSED: {AlertStatus.OPEN},
}


def get_alert(db: Session, alert_id: int) -> Alert:
    alert = db.get(Alert, alert_id)
    if alert is None:
        raise NotFoundError("Alert not found")
    return alert


def change_status(
    db: Session, alert: Alert, status: AlertStatus, user: User, meta: RequestMeta, note: str | None = None
) -> Alert:
    if status == alert.status:
        return alert
    if status not in _ALLOWED[alert.status]:
        raise InvalidStateTransitionError(f"Cannot move an alert from {alert.status.value} to {status.value}")
    old = alert.status
    now = datetime.now(UTC)
    alert.status = status
    if status == AlertStatus.ACKNOWLEDGED:
        alert.acknowledged_at, alert.acknowledged_by_id = now, user.id
    elif status in (AlertStatus.RESOLVED, AlertStatus.SUPPRESSED):
        alert.resolved_at, alert.resolved_by_id = now, user.id
    elif status == AlertStatus.OPEN:
        alert.resolved_at = alert.resolved_by_id = None
    action = {
        AlertStatus.ACKNOWLEDGED: "ALERT_ACKNOWLEDGED",
        AlertStatus.RESOLVED: "ALERT_RESOLVED",
        AlertStatus.SUPPRESSED: "ALERT_SUPPRESSED",
        AlertStatus.OPEN: "ALERT_REOPENED",
    }[status]
    audit_service.record(
        db,
        action,
        actor=user,
        resource_type="alert",
        resource_id=alert.id,
        meta=meta,
        details={"from": old.value, "to": status.value, "note": note},
    )
    return alert


def assign(db: Session, alert: Alert, assignee: User | None, user: User, meta: RequestMeta) -> Alert:
    old = alert.assigned_to_id
    alert.assigned_to_id = assignee.id if assignee else None
    audit_service.record(
        db,
        "ALERT_ASSIGNED",
        actor=user,
        resource_type="alert",
        resource_id=alert.id,
        meta=meta,
        details={"from": old, "to": alert.assigned_to_id},
    )
    return alert
