"""Correlation engine (alerts -> incidents) and the incident workflow.

Correlation
-----------
* An alert joins an open incident with the same correlation key (the acting
  source, or the target for floods) seen inside CORRELATION_WINDOW_MINUTES.
* Pivot: if the alert's *source* was a *target* in an open incident, the alert
  joins that incident — a victim that starts attacking others extends the chain.
* Otherwise a new incident opens when a single alert is severe enough, or when
  unincorporated alerts from one actor span >= N distinct kill-chain stages.
Everything is deduplicated: alerts attach to at most one incident.
"""

from __future__ import annotations

import json
import logging
from dataclasses import dataclass, field
from datetime import UTC, datetime, timedelta
from functools import lru_cache
from typing import Any

from sqlalchemy import select
from sqlalchemy.dialects.postgresql import insert as pg_insert
from sqlalchemy.orm import Session

from app.core.config import get_settings
from app.core.exceptions import InvalidStateTransitionError, NotFoundError, ValidationFailedError
from app.core.metrics import INCIDENTS_CREATED
from app.models.alert import Alert
from app.models.asset import Asset
from app.models.enums import (
    ActivityType,
    AlertStatus,
    Classification,
    EvidenceType,
    IncidentResolution,
    IncidentStatus,
    Severity,
)
from app.models.incident import Evidence, Incident, IncidentActivity, IncidentAsset
from app.models.user import User
from app.services import audit_service
from app.services.audit_service import RequestMeta

logger = logging.getLogger(__name__)


@lru_cache
def correlation_config() -> dict[str, Any]:
    return json.loads(get_settings().correlation_rules_path.read_text(encoding="utf-8"))


def stage_of(category: str) -> str:
    return correlation_config()["stages"].get(category, "unknown")


def correlation_key(alert: Alert) -> str:
    if alert.category == "ddos":
        return f"target:{alert.dst_ip}"
    return f"actor:{alert.src_ip}"


_STAGE_LABEL = {
    "discovery": "discovery",
    "initial_access": "initial access",
    "credential_access": "credential access",
    "command_and_control": "command & control",
    "lateral_movement": "lateral movement",
    "exfiltration": "exfiltration",
    "impact": "impact",
    "unknown": "unknown behaviour",
    "policy": "policy violation",
}


def _chain_entry(alert: Alert) -> dict[str, Any]:
    return {
        "stage": stage_of(alert.category),
        "category": alert.category,
        "alert_id": alert.id,
        "ts": alert.first_seen.isoformat(),
        "src_ip": str(alert.src_ip),
        "dst_ip": str(alert.dst_ip),
    }


def _title(alerts: list[Alert], key: str) -> str:
    stages = []
    for a in sorted(alerts, key=lambda a: a.first_seen):
        s = stage_of(a.category)
        if s not in stages:
            stages.append(s)
    actor = key.split(":", 1)[1]
    if len(stages) >= 2:
        return f"Multi-stage activity from {actor}: " + " → ".join(_STAGE_LABEL.get(s, s) for s in stages)
    top = max(alerts, key=lambda a: a.risk_score)
    if top.classification == Classification.POTENTIAL_UNKNOWN:
        return f"Potential unknown attack involving {actor}"
    return top.title


def _max_severity(values: list[Severity]) -> Severity:
    return max(values, key=lambda s: Severity(s).rank)


@dataclass
class IncidentChange:
    incident: Incident
    created: bool
    escalated_from: Severity | None = None
    new_alert_ids: list[int] = field(default_factory=list)


class CorrelationEngine:
    def __init__(self, db: Session) -> None:
        self.db = db
        settings = get_settings()
        self.window = timedelta(minutes=settings.correlation_window_minutes)
        self.rules = correlation_config()["rules"]
        self.changes: dict[int, IncidentChange] = {}

    # -- lookups ----------------------------------------------------------

    def _open_incident_by_key(self, key: str, ts: datetime) -> Incident | None:
        return self.db.scalar(
            select(Incident)
            .where(
                Incident.correlation_key == key,
                Incident.status != IncidentStatus.RESOLVED,
                Incident.last_seen >= ts - self.window,
            )
            .order_by(Incident.last_seen.desc())
            .limit(1)
            .with_for_update(of=Incident, key_share=True)
        )

    def _open_incident_with_target(self, ip: str, ts: datetime) -> Incident | None:
        return self.db.scalar(
            select(Incident)
            .join(IncidentAsset, IncidentAsset.incident_id == Incident.id)
            .join(Asset, Asset.id == IncidentAsset.asset_id)
            .where(
                Asset.ip_address == ip,
                IncidentAsset.role == "target",
                Incident.status != IncidentStatus.RESOLVED,
                Incident.last_seen >= ts - self.window,
            )
            .order_by(Incident.last_seen.desc())
            .limit(1)
            .with_for_update(of=Incident, key_share=True)
        )

    # -- attach / create ----------------------------------------------------

    def _link_assets(self, incident: Incident, alerts: list[Alert]) -> None:
        pairs: set[tuple[str, str]] = set()
        for a in alerts:
            if a.src_ip is not None:
                pairs.add((str(a.src_ip), "source"))
            if a.dst_ip is not None:
                pairs.add((str(a.dst_ip), "target"))
        if not pairs:
            return
        assets = {
            str(x.ip_address): x.id
            for x in self.db.scalars(select(Asset).where(Asset.ip_address.in_([p[0] for p in pairs]))).all()
        }
        rows = [
            {"incident_id": incident.id, "asset_id": assets[ip], "role": role} for ip, role in pairs if ip in assets
        ]
        if rows:
            self.db.execute(
                pg_insert(IncidentAsset).values(rows).on_conflict_do_nothing(constraint="uq_incident_assets_pair")
            )

    def _attach(self, incident: Incident, alerts: list[Alert], via: str) -> None:
        change = self.changes.setdefault(incident.id, IncidentChange(incident, created=False))
        old_sev = Severity(incident.severity)
        chain = list(incident.attack_chain or [])
        for alert in alerts:
            if alert.incident_id == incident.id:
                continue
            alert.incident_id = incident.id
            change.new_alert_ids.append(alert.id)
            chain.append(_chain_entry(alert))
            incident.last_seen = max(incident.last_seen, alert.last_seen)
            incident.risk_score = max(incident.risk_score, alert.risk_score)
            if alert.classification == Classification.POTENTIAL_UNKNOWN:
                incident.classification = Classification.POTENTIAL_UNKNOWN
            self.db.add(
                IncidentActivity(
                    incident_id=incident.id,
                    activity_type=ActivityType.ALERT_LINKED,
                    to_value=f"ALT-{alert.id}",
                    message=f"Alert ALT-{alert.id} ({alert.category}) linked via {via}.",
                )
            )
            if alert.primary_detection_id:
                self.db.add(
                    Evidence(
                        incident_id=incident.id,
                        evidence_type=EvidenceType.DETECTION,
                        detection_id=alert.primary_detection_id,
                        content=f"Primary detection of alert ALT-{alert.id}",
                    )
                )
        incident.attack_chain = sorted(chain, key=lambda c: c["ts"])
        new_sev = _max_severity([old_sev, *[Severity(a.severity) for a in alerts]])
        stages = {c["stage"] for c in incident.attack_chain}
        if len(stages) >= self.rules["multi_stage_chain"]["min_stages"] and new_sev.rank < Severity.HIGH.rank:
            new_sev = Severity.HIGH
        if new_sev.rank > old_sev.rank:
            incident.severity = new_sev
            change.escalated_from = old_sev
            self.db.add(
                IncidentActivity(
                    incident_id=incident.id,
                    activity_type=ActivityType.ESCALATED,
                    from_value=old_sev.value,
                    to_value=new_sev.value,
                    message="Severity escalated by correlation.",
                )
            )
        if not change.created and len(stages) >= 2:
            incident.title = _title(self._incident_alerts(incident) + alerts, incident.correlation_key or "actor:?")[
                :255
            ]
        self._link_assets(incident, alerts)

    def _incident_alerts(self, incident: Incident) -> list[Alert]:
        return list(self.db.scalars(select(Alert).where(Alert.incident_id == incident.id)).all())

    def _create(self, key: str, alerts: list[Alert], rule: str) -> Incident:
        top = max(alerts, key=lambda a: a.risk_score)
        incident = Incident(
            title=_title(alerts, key)[:255],
            description=top.description,
            severity=_max_severity([Severity(a.severity) for a in alerts]),
            status=IncidentStatus.NEW,
            classification=(
                Classification.POTENTIAL_UNKNOWN
                if any(a.classification == Classification.POTENTIAL_UNKNOWN for a in alerts)
                else top.classification
            ),
            risk_score=top.risk_score,
            correlation_key=key,
            correlation_rule=rule,
            attack_chain=[],
            primary_src_ip=top.src_ip,
            first_seen=min(a.first_seen for a in alerts),
            last_seen=max(a.last_seen for a in alerts),
            is_demo=any(a.is_demo for a in alerts),
        )
        self.db.add(incident)
        self.db.flush()
        self.changes[incident.id] = IncidentChange(incident, created=True)
        self.db.add(
            IncidentActivity(
                incident_id=incident.id,
                activity_type=ActivityType.CREATED,
                to_value=IncidentStatus.NEW.value,
                message=f"Opened automatically by correlation rule '{rule}'.",
            )
        )
        self._attach(incident, alerts, via=rule)
        INCIDENTS_CREATED.inc()
        audit_service.record(
            self.db,
            "INCIDENT_CREATED",
            actor_label="system:correlation",
            resource_type="incident",
            resource_id=incident.id,
            details={"rule": rule, "key": key},
        )
        return incident

    # -- entry point -------------------------------------------------------

    def process(self, alerts: list[Alert]) -> dict[int, IncidentChange]:
        single = self.rules["single_alert_incident"]
        chain_rule = self.rules["multi_stage_chain"]
        for alert in sorted(alerts, key=lambda a: a.first_seen):
            if alert.incident_id is not None or alert.status not in (AlertStatus.OPEN, AlertStatus.ACKNOWLEDGED):
                continue
            key = correlation_key(alert)
            incident = self._open_incident_by_key(key, alert.last_seen)
            via = "same actor"
            if incident is None and alert.src_ip is not None and alert.category != "ddos":
                incident = self._open_incident_with_target(str(alert.src_ip), alert.last_seen)
                via = "pivot from a previously targeted host"
            if incident is not None:
                self._attach(incident, [alert], via)
                continue

            if chain_rule["enabled"]:
                siblings = list(
                    self.db.scalars(
                        select(Alert).where(
                            Alert.incident_id.is_(None),
                            Alert.status.in_([AlertStatus.OPEN, AlertStatus.ACKNOWLEDGED]),
                            Alert.src_ip == alert.src_ip,
                            Alert.last_seen >= alert.last_seen - self.window,
                            Alert.id != alert.id,
                        )
                    ).all()
                )
                stages = {stage_of(a.category) for a in [alert, *siblings]} - {"policy"}
                if len(stages) >= chain_rule["min_stages"]:
                    self._create(key, [alert, *siblings], "multi_stage_chain")
                    continue
            if single["enabled"]:
                severe = Severity(alert.severity).rank >= Severity(single["min_severity"]).rank
                unknown = (
                    alert.classification == Classification.POTENTIAL_UNKNOWN
                    and alert.risk_score >= single["potential_unknown_min_risk"]
                    and (
                        alert.risk_score >= single.get("potential_unknown_high_risk", 85)
                        or alert.occurrence_count >= single.get("potential_unknown_min_occurrences", 3)
                    )
                )
                if severe or unknown:
                    self._create(key, [alert], "single_alert_incident")
        return self.changes


# --- analyst workflow ---------------------------------------------------------

TRANSITIONS: dict[IncidentStatus, set[IncidentStatus]] = {
    IncidentStatus.NEW: {IncidentStatus.ACKNOWLEDGED, IncidentStatus.INVESTIGATING, IncidentStatus.RESOLVED},
    IncidentStatus.ACKNOWLEDGED: {IncidentStatus.INVESTIGATING, IncidentStatus.RESOLVED},
    IncidentStatus.INVESTIGATING: {IncidentStatus.CONFIRMED, IncidentStatus.RESOLVED},
    IncidentStatus.CONFIRMED: {IncidentStatus.CONTAINED, IncidentStatus.RESOLVED},
    IncidentStatus.CONTAINED: {IncidentStatus.RESOLVED},
    IncidentStatus.RESOLVED: {IncidentStatus.INVESTIGATING},
}


def get_incident(db: Session, incident_id: int, *, lock: bool = False) -> Incident:
    stmt = select(Incident).where(Incident.id == incident_id)
    if lock:
        stmt = stmt.with_for_update(of=Incident, key_share=True)
    incident = db.scalar(stmt)
    if incident is None:
        raise NotFoundError("Incident not found")
    return incident


def _activity(
    db: Session, incident: Incident, user: User, kind: ActivityType, frm: str | None, to: str | None, message: str
) -> None:
    db.add(
        IncidentActivity(
            incident_id=incident.id, actor_id=user.id, activity_type=kind, from_value=frm, to_value=to, message=message
        )
    )


def change_status(
    db: Session,
    incident: Incident,
    status: IncidentStatus,
    user: User,
    meta: RequestMeta,
    *,
    resolution: IncidentResolution | None = None,
    notes: str | None = None,
) -> Incident:
    if status == incident.status:
        return incident
    if status not in TRANSITIONS[incident.status]:
        raise InvalidStateTransitionError(
            f"Cannot move incident from {incident.status.value} to {status.value}",
            details={"allowed": sorted(s.value for s in TRANSITIONS[incident.status])},
        )
    if status == IncidentStatus.RESOLVED:
        if resolution is None or not (notes and notes.strip()):
            raise ValidationFailedError("Resolving an incident requires a resolution and resolution notes")
        incident.resolution = resolution
        incident.resolution_notes = notes.strip()
        incident.resolved_at = datetime.now(UTC)
    elif incident.status == IncidentStatus.RESOLVED:
        incident.resolution = None
        incident.resolution_notes = None
        incident.resolved_at = None
    old = incident.status
    incident.status = status
    _activity(
        db,
        incident,
        user,
        ActivityType.STATUS_CHANGED,
        old.value,
        status.value,
        f"Status {old.value} → {status.value}" + (f" ({resolution.value})" if resolution else ""),
    )
    audit_service.record(
        db,
        "INCIDENT_UPDATED",
        actor=user,
        resource_type="incident",
        resource_id=incident.id,
        meta=meta,
        details={
            "field": "status",
            "from": old.value,
            "to": status.value,
            "resolution": resolution.value if resolution else None,
        },
    )
    return incident


def change_severity(
    db: Session, incident: Incident, severity: Severity, user: User, meta: RequestMeta, reason: str
) -> Incident:
    if severity == incident.severity:
        return incident
    old = incident.severity
    incident.severity = severity
    _activity(db, incident, user, ActivityType.SEVERITY_CHANGED, old.value, severity.value, reason)
    audit_service.record(
        db,
        "INCIDENT_UPDATED",
        actor=user,
        resource_type="incident",
        resource_id=incident.id,
        meta=meta,
        details={"field": "severity", "from": old.value, "to": severity.value, "reason": reason},
    )
    return incident


def assign(db: Session, incident: Incident, assignee: User | None, user: User, meta: RequestMeta) -> Incident:
    old = incident.assigned_to_id
    if assignee is not None and not assignee.is_active:
        raise ValidationFailedError("Cannot assign to an inactive user")
    incident.assigned_to_id = assignee.id if assignee else None
    incident.assigned_to = assignee  # keep the loaded relationship in sync for the response
    _activity(
        db,
        incident,
        user,
        ActivityType.ASSIGNED,
        str(old) if old else None,
        assignee.email if assignee else None,
        f"Assigned to {assignee.name}" if assignee else "Unassigned",
    )
    audit_service.record(
        db,
        "INCIDENT_ASSIGNED",
        actor=user,
        resource_type="incident",
        resource_id=incident.id,
        meta=meta,
        details={"from": old, "to": incident.assigned_to_id},
    )
    return incident


def add_note(db: Session, incident: Incident, text: str, user: User, meta: RequestMeta) -> Evidence:
    text = text.strip()
    if not text:
        raise ValidationFailedError("Note cannot be empty")
    note = Evidence(incident_id=incident.id, evidence_type=EvidenceType.NOTE, content=text, created_by_id=user.id)
    db.add(note)
    db.flush()
    _activity(db, incident, user, ActivityType.NOTE_ADDED, None, None, text[:500])
    audit_service.record(
        db,
        "INCIDENT_NOTE_ADDED",
        actor=user,
        resource_type="incident",
        resource_id=incident.id,
        meta=meta,
        details={"evidence_id": note.id},
    )
    return note


def add_evidence(
    db: Session,
    incident: Incident,
    user: User,
    meta: RequestMeta,
    *,
    evidence_type: EvidenceType,
    event_id: int | None = None,
    detection_id: int | None = None,
    threat_intel_id: int | None = None,
    content: str | None = None,
    attachment: dict[str, Any] | None = None,
) -> Evidence:
    ev = Evidence(
        incident_id=incident.id,
        evidence_type=evidence_type,
        event_id=event_id,
        detection_id=detection_id,
        threat_intel_id=threat_intel_id,
        content=content,
        attachment=attachment,
        created_by_id=user.id,
    )
    db.add(ev)
    db.flush()
    _activity(
        db,
        incident,
        user,
        ActivityType.EVIDENCE_ADDED,
        None,
        evidence_type.value,
        content[:300] if content else f"{evidence_type.value} evidence attached",
    )
    audit_service.record(
        db,
        "INCIDENT_EVIDENCE_ADDED",
        actor=user,
        resource_type="incident",
        resource_id=incident.id,
        meta=meta,
        details={"evidence_id": ev.id, "type": evidence_type.value},
    )
    return ev
