"""Evidence retrieval for the AI security assistant.

The question is parsed deterministically (IPs, INC-/ALT-/DET- references,
time words) and the matching records are pulled from the database. Every
evidence item carries a citation ID (INC-1004, ALT-12, DET-55, EVT-901, IOC-3,
RSP-2). The assistant may only state facts contained in these items.
"""

from __future__ import annotations

import ipaddress
import re
from dataclasses import dataclass, field
from datetime import UTC, datetime, timedelta
from typing import Any

from sqlalchemy import func, or_, select
from sqlalchemy.orm import Session

from app.models.alert import Alert, alert_detections
from app.models.detection import Detection
from app.models.enums import Classification, IncidentStatus, IocType, Permission, Severity
from app.models.incident import Evidence, Incident, IncidentActivity
from app.models.network_event import NetworkEvent
from app.models.response import ResponseAction
from app.models.threat_intel import ThreatIntelIndicator
from app.models.user import User

_IP = re.compile(r"\b(?:\d{1,3}\.){3}\d{1,3}\b|\b[0-9a-fA-F:]{3,39}:[0-9a-fA-F]{1,4}\b")
_REF = re.compile(r"\b(INC|ALT|DET|EVT)-(\d{1,12})\b", re.IGNORECASE)
MAX_ITEMS = 40


@dataclass
class EvidenceItem:
    cite: str
    kind: str
    data: dict[str, Any]


@dataclass
class Retrieval:
    question: str
    ips: list[str]
    refs: list[str]
    items: list[EvidenceItem] = field(default_factory=list)
    scope_notes: list[str] = field(default_factory=list)

    @property
    def citations(self) -> set[str]:
        return {i.cite for i in self.items}

    def add(self, cite: str, kind: str, data: dict[str, Any]) -> None:
        if cite not in self.citations and len(self.items) < MAX_ITEMS:
            self.items.append(EvidenceItem(cite, kind, data))


def _iso(v: Any) -> Any:
    return v.isoformat() if isinstance(v, datetime) else v


def _incident(i: Incident) -> dict[str, Any]:
    return {
        "reference": i.reference,
        "title": i.title,
        "status": i.status.value,
        "severity": i.severity.value,
        "classification": i.classification.value if i.classification else None,
        "risk_score": i.risk_score,
        "first_seen": _iso(i.first_seen),
        "last_seen": _iso(i.last_seen),
        "primary_source": str(i.primary_src_ip) if i.primary_src_ip else None,
        "attack_chain": [{"stage": c["stage"], "alert": f"ALT-{c['alert_id']}"} for c in i.attack_chain],
        "assigned_to": i.assigned_to.name if i.assigned_to else None,
        "resolution": i.resolution.value if i.resolution else None,
        "demo": i.is_demo,
    }


def _alert(a: Alert) -> dict[str, Any]:
    return {
        "title": a.title,
        "status": a.status.value,
        "severity": a.severity.value,
        "category": a.category,
        "classification": a.classification.value if a.classification else None,
        "src": str(a.src_ip) if a.src_ip else None,
        "dst": str(a.dst_ip) if a.dst_ip else None,
        "risk_score": a.risk_score,
        "occurrences": a.occurrence_count,
        "first_seen": _iso(a.first_seen),
        "last_seen": _iso(a.last_seen),
        "incident": f"INC-{a.incident_id}" if a.incident_id else None,
        "primary_detection": f"DET-{a.primary_detection_id}" if a.primary_detection_id else None,
        "demo": a.is_demo,
    }


def _detection(d: Detection) -> dict[str, Any]:
    return {
        "ts": _iso(d.ts),
        "classification": d.classification.value,
        "category": d.category,
        "detectors": d.detectors_fired,
        "src": str(d.src_ip),
        "dst": f"{d.dst_ip}:{d.dst_port}",
        "anomaly_score": d.anomaly_score,
        "confidence": d.confidence,
        "risk_score": d.risk_score,
        "risk_reason": d.risk_components.get("reason"),
        "risk_components": {
            k: d.risk_components.get(k)
            for k in ("signature", "anomaly", "behavioral", "threat_intel", "asset_criticality", "correlation")
        },
        "explanation": [f.get("detail") for f in d.explanation[:6]],
        "rule": d.rule_id,
        "model": d.model_version,
        "mitre": [
            {"technique": m.technique_id, "confidence": m.confidence, "evidence": m.evidence} for m in d.mitre_mappings
        ],
        "demo": d.is_demo,
    }


def retrieve(db: Session, user: User, question: str) -> Retrieval:
    q = question.strip()
    ips: list[str] = []
    for m in _IP.findall(q):
        try:
            ips.append(str(ipaddress.ip_address(m)))
        except ValueError:
            continue
    refs = [f"{k.upper()}-{v}" for k, v in _REF.findall(q)]
    r = Retrieval(q, sorted(set(ips)), refs)
    now = datetime.now(UTC)
    lower = q.lower()
    since = now - timedelta(days=1) if "today" in lower or "24" in lower else now - timedelta(days=7)
    can = user.has_permission

    for ref in refs:
        kind, num = ref.split("-")
        n = int(num)
        if kind == "INC" and can(Permission.VIEW_INCIDENTS.value):
            inc = db.get(Incident, n)
            if inc is None:
                r.scope_notes.append(f"{ref} does not exist.")
                continue
            r.add(ref, "incident", _incident(inc))
            for a in db.scalars(select(Alert).where(Alert.incident_id == n).order_by(Alert.first_seen).limit(15)):
                r.add(f"ALT-{a.id}", "alert", _alert(a))
                if a.primary_detection_id and (d := db.get(Detection, a.primary_detection_id)):
                    r.add(f"DET-{d.id}", "detection", _detection(d))
            for act in db.scalars(
                select(IncidentActivity)
                .where(IncidentActivity.incident_id == n)
                .order_by(IncidentActivity.created_at)
                .limit(15)
            ):
                r.add(
                    f"{ref}/ACT-{act.id}",
                    "incident_activity",
                    {
                        "ts": _iso(act.created_at),
                        "type": act.activity_type.value,
                        "message": act.message,
                        "actor": act.actor.name if act.actor else "system",
                    },
                )
            for ev in db.scalars(
                select(Evidence).where(Evidence.incident_id == n, Evidence.content.isnot(None)).limit(10)
            ):
                r.add(f"{ref}/EV-{ev.id}", "evidence", {"type": ev.evidence_type.value, "content": ev.content})
            for ra in db.scalars(select(ResponseAction).where(ResponseAction.incident_id == n)):
                r.add(
                    f"RSP-{ra.id}",
                    "response_action",
                    {
                        "action": ra.action_type.value,
                        "target": ra.target,
                        "status": ra.status.value,
                        "executed_at": _iso(ra.executed_at),
                        "adapter": ra.adapter,
                    },
                )
        elif kind == "ALT" and can(Permission.VIEW_ALERTS.value):
            a = db.get(Alert, n)
            if a is None:
                r.scope_notes.append(f"{ref} does not exist.")
                continue
            r.add(ref, "alert", _alert(a))
            for d in db.scalars(
                select(Detection)
                .join(alert_detections, alert_detections.c.detection_id == Detection.id)
                .where(alert_detections.c.alert_id == n)
                .order_by(Detection.ts.desc())
                .limit(5)
            ):
                r.add(f"DET-{d.id}", "detection", _detection(d))
        elif kind == "DET" and can(Permission.VIEW_DETECTIONS.value):
            d = db.get(Detection, n)
            if d is None:
                r.scope_notes.append(f"{ref} does not exist.")
                continue
            r.add(ref, "detection", _detection(d))
        elif kind == "EVT" and can(Permission.VIEW_EVENTS.value):
            e = db.get(NetworkEvent, n)
            if e is None:
                r.scope_notes.append(f"{ref} does not exist.")
                continue
            r.add(
                ref,
                "event",
                {
                    "ts": _iso(e.ts),
                    "src": f"{e.src_ip}:{e.src_port}",
                    "dst": f"{e.dst_ip}:{e.dst_port}",
                    "protocol": e.protocol.value,
                    "bytes_out": e.bytes_out,
                    "bytes_in": e.bytes_in,
                    "classification": e.classification.value if e.classification else None,
                    "anomaly_score": e.anomaly_score,
                    "demo": e.is_demo,
                },
            )
        else:
            r.scope_notes.append(f"You do not have permission to view {ref}.")

    for ip in r.ips:
        if can(Permission.VIEW_EVENTS.value):
            row = db.execute(
                select(
                    func.count(),
                    func.min(NetworkEvent.ts),
                    func.max(NetworkEvent.ts),
                    func.count().filter(NetworkEvent.classification != Classification.NORMAL),
                ).where(or_(NetworkEvent.src_ip == ip, NetworkEvent.dst_ip == ip), NetworkEvent.ts >= since)
            ).one()
            r.add(
                f"IP-{ip}",
                "ip_activity",
                {
                    "ip": ip,
                    "window_start": _iso(since),
                    "flows": int(row[0]),
                    "first_seen": _iso(row[1]),
                    "last_seen": _iso(row[2]),
                    "non_normal_flows": int(row[3]),
                },
            )
        if can(Permission.VIEW_ALERTS.value):
            for a in db.scalars(
                select(Alert)
                .where(or_(Alert.src_ip == ip, Alert.dst_ip == ip))
                .order_by(Alert.last_seen.desc())
                .limit(8)
            ):
                r.add(f"ALT-{a.id}", "alert", _alert(a))
                if a.primary_detection_id and (d := db.get(Detection, a.primary_detection_id)):
                    r.add(f"DET-{d.id}", "detection", _detection(d))
        if can(Permission.VIEW_INCIDENTS.value):
            for inc in db.scalars(
                select(Incident).where(Incident.primary_src_ip == ip).order_by(Incident.last_seen.desc()).limit(5)
            ):
                r.add(inc.reference, "incident", _incident(inc))
        if can(Permission.VIEW_THREAT_INTEL.value):
            for ind in db.scalars(
                select(ThreatIntelIndicator).where(
                    ThreatIntelIndicator.ioc_type == IocType.IP, ThreatIntelIndicator.ioc_value == ip
                )
            ):
                r.add(
                    f"IOC-{ind.id}",
                    "threat_intel",
                    {
                        "ip": ip,
                        "provider": ind.provider,
                        "reputation": ind.reputation.value,
                        "confidence": ind.confidence,
                        "fetched_at": _iso(ind.fetched_at),
                    },
                )

    if not refs and not r.ips and can(Permission.VIEW_INCIDENTS.value):
        stmt = select(Incident).where(Incident.created_at >= since)
        if "critical" in lower:
            stmt = stmt.where(Incident.severity == Severity.CRITICAL)
        if "unknown" in lower or "zero" in lower:
            stmt = stmt.where(Incident.classification == Classification.POTENTIAL_UNKNOWN)
        if "open" in lower or "active" in lower:
            stmt = stmt.where(Incident.status != IncidentStatus.RESOLVED)
        for inc in db.scalars(stmt.order_by(Incident.risk_score.desc()).limit(15)):
            r.add(inc.reference, "incident", _incident(inc))
        r.scope_notes.append(f"Incidents created since {since:%Y-%m-%d %H:%M} UTC were searched.")
    return r
