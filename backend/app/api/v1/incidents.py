"""/api/v1/incidents — incident queue, workflow, evidence and the investigation view."""

from __future__ import annotations

import hashlib
import re
import uuid
from datetime import timedelta
from pathlib import Path
from typing import Annotated, Any

from fastapi import APIRouter, Depends, File, Query, UploadFile
from fastapi.responses import FileResponse
from sqlalchemy import or_, select
from starlette.concurrency import run_in_threadpool

from app.api.deps import DbSession, Meta, require
from app.api.query import apply_sort, page_params, paginate, parse_ip
from app.core.config import PROJECT_DIR
from app.core.exceptions import NotFoundError, ValidationFailedError
from app.models.alert import Alert
from app.models.asset import Asset
from app.models.audit import AuditLog
from app.models.detection import Detection
from app.models.enums import (
    Classification,
    EvidenceType,
    IncidentStatus,
    IocType,
    NotificationEvent,
    Permission,
    Severity,
)
from app.models.incident import Evidence, Incident, IncidentActivity, IncidentAsset
from app.models.network_event import NetworkEvent
from app.models.response import ResponseAction
from app.models.threat_intel import ThreatIntelIndicator
from app.models.user import User
from app.schemas.common import Page, PageParams
from app.schemas.events import EventOut
from app.schemas.soc import (
    ActivityOut,
    AlertOut,
    AssetOut,
    EvidenceIn,
    EvidenceOut,
    IncidentOut,
    IncidentUpdate,
    NoteIn,
    ResponseActionOut,
)
from app.services import incident_service, notification_service
from app.services.notification_service import Message
from app.services.serializers import detection_out, incident_out
from app.websocket.events import RealtimeEvent, publish

router = APIRouter(prefix="/incidents", tags=["incidents"])
Viewer = Annotated[User, Depends(require(Permission.VIEW_INCIDENTS))]
Editor = Annotated[User, Depends(require(Permission.MANAGE_INCIDENTS))]

EVIDENCE_DIR = PROJECT_DIR / "var" / "evidence"
MAX_ATTACHMENT_BYTES = 4 * 1024 * 1024
ALLOWED_ATTACHMENTS = {
    ".txt": "text/plain",
    ".log": "text/plain",
    ".csv": "text/csv",
    ".json": "application/json",
    ".pdf": "application/pdf",
    ".png": "image/png",
    ".jpg": "image/jpeg",
    ".jpeg": "image/jpeg",
    ".pcap": "application/vnd.tcpdump.pcap",
}
_MAGIC = {
    ".pdf": b"%PDF",
    ".png": b"\x89PNG",
    ".jpg": b"\xff\xd8\xff",
    ".jpeg": b"\xff\xd8\xff",
    ".pcap": (b"\xd4\xc3\xb2\xa1", b"\xa1\xb2\xc3\xd4", b"\x0a\x0d\x0d\x0a"),
}

_SORT = {
    "last_seen": Incident.last_seen,
    "created_at": Incident.created_at,
    "risk_score": Incident.risk_score,
    "id": Incident.id,
}


@router.get("", response_model=Page[IncidentOut])
def list_incidents(
    db: DbSession,
    user: Viewer,
    params: Annotated[PageParams, Depends(page_params)],
    status: IncidentStatus | None = None,
    severity: Severity | None = None,
    classification: Classification | None = None,
    active_only: bool = False,
    assigned_to_me: bool = False,
    ip: str | None = Query(None, max_length=45),
    demo: bool | None = None,
    q: str | None = Query(None, max_length=100),
    sort: str | None = Query(None, max_length=32),
) -> Page[IncidentOut]:
    stmt = select(Incident)
    if status:
        stmt = stmt.where(Incident.status == status)
    if active_only:
        stmt = stmt.where(Incident.status != IncidentStatus.RESOLVED)
    if severity:
        stmt = stmt.where(Incident.severity == severity)
    if classification:
        stmt = stmt.where(Incident.classification == classification)
    if assigned_to_me:
        stmt = stmt.where(Incident.assigned_to_id == user.id)
    if (addr := parse_ip(ip)) is not None:
        stmt = stmt.where(Incident.primary_src_ip == addr)
    if demo is not None:
        stmt = stmt.where(Incident.is_demo.is_(demo))
    if q:
        m = re.fullmatch(r"(?i)inc-(\d{1,9})", q.strip())
        if m:
            stmt = stmt.where(Incident.id == int(m.group(1)))
        else:
            needle = q.replace("\\", "\\\\").replace("%", "\\%").replace("_", "\\_")
            stmt = stmt.where(Incident.title.ilike(f"%{needle}%", escape="\\"))
    stmt = apply_sort(stmt, sort, _SORT, Incident.last_seen.desc())
    return paginate(db, stmt, params, incident_out)


@router.get("/{incident_id}", response_model=IncidentOut)
def get_incident(incident_id: int, db: DbSession, _: Viewer) -> IncidentOut:
    return incident_out(incident_service.get_incident(db, incident_id))


@router.get("/{incident_id}/investigation")
def investigation(incident_id: int, db: DbSession, user: Viewer) -> dict[str, Any]:
    """Everything an analyst needs for one incident, from real platform data only."""
    inc = incident_service.get_incident(db, incident_id)
    alerts = list(db.scalars(select(Alert).where(Alert.incident_id == inc.id).order_by(Alert.first_seen)).all())
    det_ids = [a.primary_detection_id for a in alerts if a.primary_detection_id]
    evidence = list(
        db.scalars(select(Evidence).where(Evidence.incident_id == inc.id).order_by(Evidence.created_at)).all()
    )
    det_ids += [e.detection_id for e in evidence if e.detection_id]
    detections = list(db.scalars(select(Detection).where(Detection.id.in_(set(det_ids)))).all()) if det_ids else []
    assets = db.execute(
        select(Asset, IncidentAsset.role)
        .join(IncidentAsset, IncidentAsset.asset_id == Asset.id)
        .where(IncidentAsset.incident_id == inc.id)
    ).all()
    activities = list(
        db.scalars(
            select(IncidentActivity).where(IncidentActivity.incident_id == inc.id).order_by(IncidentActivity.created_at)
        ).all()
    )
    ips = sorted({str(ip) for a in alerts for ip in (a.src_ip, a.dst_ip) if ip is not None})
    window_start = inc.first_seen - timedelta(minutes=10)
    window_end = inc.last_seen + timedelta(minutes=10)
    events: list[NetworkEvent] = []
    if inc.primary_src_ip is not None and user.has_permission(Permission.VIEW_EVENTS.value):
        events = list(
            db.scalars(
                select(NetworkEvent)
                .where(
                    or_(NetworkEvent.src_ip == inc.primary_src_ip, NetworkEvent.dst_ip == inc.primary_src_ip),
                    NetworkEvent.ts >= window_start,
                    NetworkEvent.ts <= window_end,
                )
                .order_by(NetworkEvent.ts.desc())
                .limit(200)
            ).all()
        )
    related = []
    if ips:
        related = list(
            db.scalars(
                select(Incident)
                .where(Incident.id != inc.id, Incident.primary_src_ip.in_(ips))
                .order_by(Incident.last_seen.desc())
                .limit(20)
            ).all()
        )
    intel = (
        list(
            db.scalars(
                select(ThreatIntelIndicator).where(
                    ThreatIntelIndicator.ioc_type == IocType.IP, ThreatIntelIndicator.ioc_value.in_(ips)
                )
            ).all()
        )
        if ips
        else []
    )
    responses = list(
        db.scalars(
            select(ResponseAction).where(ResponseAction.incident_id == inc.id).order_by(ResponseAction.created_at)
        ).all()
    )
    audit = []
    if user.has_permission(Permission.VIEW_AUDIT.value):
        audit = list(
            db.scalars(
                select(AuditLog)
                .where(AuditLog.resource_type == "incident", AuditLog.resource_id == str(inc.id))
                .order_by(AuditLog.ts)
            ).all()
        )

    det_out = [detection_out(d).model_dump(mode="json") for d in sorted(detections, key=lambda d: d.ts)]
    mitre: dict[str, dict[str, Any]] = {}
    for d in det_out:
        for m in d["mitre"]:
            cur = mitre.get(m["technique_id"])
            if cur is None or m["confidence"] > cur["confidence"]:
                mitre[m["technique_id"]] = {**m, "detection_id": d["id"]}

    timeline: list[dict[str, Any]] = []
    for d in det_out:
        timeline.append(
            {
                "ts": d["ts"],
                "kind": "detection",
                "id": d["id"],
                "title": d["summary"][:200],
                "severity": d["severity"],
                "classification": d["classification"],
            }
        )
    for a in alerts:
        timeline.append(
            {
                "ts": a.first_seen.isoformat(),
                "kind": "alert",
                "id": a.id,
                "title": a.title,
                "severity": a.severity.value,
                "occurrences": a.occurrence_count,
            }
        )
    for act in activities:
        timeline.append(
            {
                "ts": act.created_at.isoformat(),
                "kind": "activity",
                "id": act.id,
                "title": act.message,
                "activity_type": act.activity_type.value,
                "actor": act.actor.name if act.actor else "system",
            }
        )
    for r in responses:
        timeline.append(
            {
                "ts": r.created_at.isoformat(),
                "kind": "response",
                "id": r.id,
                "title": f"{r.action_type.value} {r.target} ({r.status.value})",
            }
        )
    timeline.sort(key=lambda t: t["ts"])

    top = max(detections, key=lambda d: d.risk_score, default=None)
    return {
        "incident": incident_out(inc).model_dump(mode="json"),
        "description": inc.description,
        "resolution_notes": inc.resolution_notes,
        "attack_chain": inc.attack_chain,
        "summary": {
            "sources": sorted({str(a.src_ip) for a in alerts if a.src_ip}),
            "destinations": sorted({str(a.dst_ip) for a in alerts if a.dst_ip}),
            "alert_count": len(alerts),
            "detection_count": len(detections),
            "stages": [c["stage"] for c in inc.attack_chain],
            "risk_components": top.risk_components if top else None,
            "primary_explanation": top.explanation if top else [],
        },
        "affected_assets": [{**AssetOut.model_validate(a).model_dump(mode="json"), "role": role} for a, role in assets],
        "alerts": [AlertOut.model_validate(a).model_dump(mode="json") for a in alerts],
        "detections": det_out,
        "timeline": timeline,
        "related_events": [EventOut.model_validate(e).model_dump(mode="json") for e in events],
        "related_events_visible": user.has_permission(Permission.VIEW_EVENTS.value),
        "related_incidents": [incident_out(r).model_dump(mode="json") for r in related],
        "threat_intelligence": [
            {
                "id": i.id,
                "ioc_value": i.ioc_value,
                "provider": i.provider,
                "reputation": i.reputation.value,
                "confidence": i.confidence,
                "source": i.source,
                "fetched_at": i.fetched_at,
            }
            for i in intel
        ],
        "mitre": sorted(mitre.values(), key=lambda m: -m["confidence"]),
        "notes": [
            EvidenceOut.model_validate(e).model_dump(mode="json")
            for e in evidence
            if e.evidence_type == EvidenceType.NOTE
        ],
        "evidence": [
            EvidenceOut.model_validate(e).model_dump(mode="json")
            for e in evidence
            if e.evidence_type != EvidenceType.NOTE
        ],
        "response_actions": [ResponseActionOut.model_validate(r).model_dump(mode="json") for r in responses],
        "activity": [ActivityOut.model_validate(a).model_dump(mode="json") for a in activities],
        "audit_history": [
            {"ts": a.ts, "actor": a.actor_label, "action": a.action, "result": a.result.value, "details": a.details}
            for a in audit
        ],
        "audit_visible": user.has_permission(Permission.VIEW_AUDIT.value),
    }


@router.patch("/{incident_id}", response_model=IncidentOut)
def update_incident(incident_id: int, body: IncidentUpdate, db: DbSession, user: Editor, meta: Meta) -> IncidentOut:
    inc = incident_service.get_incident(db, incident_id, lock=True)
    notifications = []
    escalated = False
    if body.severity is not None and body.severity != inc.severity:
        if not body.severity_reason:
            raise ValidationFailedError("Changing severity requires severity_reason")
        escalated = Severity(body.severity).rank > Severity(inc.severity).rank
        incident_service.change_severity(db, inc, body.severity, user, meta, body.severity_reason)
    if body.assigned_to_id is not None or body.unassign:
        assignee = None
        if body.assigned_to_id is not None:
            assignee = db.get(User, body.assigned_to_id)
            if assignee is None:
                raise NotFoundError("Assignee not found")
        incident_service.assign(db, inc, assignee, user, meta)
        if assignee is not None and assignee.id != user.id:
            notifications += notification_service.notify(
                db,
                Message(
                    NotificationEvent.INCIDENT_ASSIGNED,
                    f"{inc.reference} assigned to you",
                    inc.title,
                    inc.severity,
                    "incident",
                    str(inc.id),
                ),
                users=[assignee],
            )
    if body.status is not None:
        incident_service.change_status(
            db, inc, body.status, user, meta, resolution=body.resolution, notes=body.resolution_notes
        )
    if escalated:
        notifications += notification_service.notify(
            db,
            Message(
                NotificationEvent.INCIDENT_ESCALATED,
                f"{inc.reference} escalated to {inc.severity.value}",
                inc.title,
                inc.severity,
                "incident",
                str(inc.id),
            ),
        )
    db.commit()
    notification_service.publish_created(notifications)
    out = incident_out(inc)
    publish(RealtimeEvent.INCIDENT_UPDATED, out.model_dump(mode="json"))
    return out


@router.post("/{incident_id}/notes", response_model=EvidenceOut, status_code=201)
def add_note(incident_id: int, body: NoteIn, db: DbSession, user: Editor, meta: Meta) -> EvidenceOut:
    inc = incident_service.get_incident(db, incident_id)
    note = incident_service.add_note(db, inc, body.text, user, meta)
    db.commit()
    publish(RealtimeEvent.INCIDENT_UPDATED, {"id": inc.id, "reference": inc.reference, "change": "note"})
    return EvidenceOut.model_validate(note)


@router.post("/{incident_id}/evidence", response_model=EvidenceOut, status_code=201)
def add_evidence(incident_id: int, body: EvidenceIn, db: DbSession, user: Editor, meta: Meta) -> EvidenceOut:
    inc = incident_service.get_incident(db, incident_id)
    refs = {
        EvidenceType.EVENT: (body.event_id, NetworkEvent),
        EvidenceType.DETECTION: (body.detection_id, Detection),
        EvidenceType.THREAT_INTEL: (body.threat_intel_id, ThreatIntelIndicator),
    }
    ref_id, model = refs[body.evidence_type]
    if ref_id is None or db.get(model, ref_id) is None:
        raise ValidationFailedError(f"{body.evidence_type.value} evidence must reference an existing record")
    ev = incident_service.add_evidence(
        db,
        inc,
        user,
        meta,
        evidence_type=body.evidence_type,
        event_id=body.event_id,
        detection_id=body.detection_id,
        threat_intel_id=body.threat_intel_id,
        content=body.content,
    )
    db.commit()
    return EvidenceOut.model_validate(ev)


def _safe_name(name: str) -> str:
    base = Path(name).name
    cleaned = re.sub(r"[^A-Za-z0-9._-]", "_", base)[:100]
    return cleaned or "attachment"


@router.post("/{incident_id}/attachments", response_model=EvidenceOut, status_code=201)
async def upload_attachment(
    incident_id: int, db: DbSession, user: Editor, meta: Meta, file: Annotated[UploadFile, File()]
) -> EvidenceOut:
    """Evidence files: extension allow-list, magic-byte check, size cap, stored outside any web root
    under a random name; only metadata + SHA-256 go into the database."""
    filename = _safe_name(file.filename or "attachment")
    ext = Path(filename).suffix.lower()
    if ext not in ALLOWED_ATTACHMENTS:
        raise ValidationFailedError(
            f"File type {ext or '(none)'} not allowed", details={"allowed": sorted(ALLOWED_ATTACHMENTS)}
        )
    data = await file.read(MAX_ATTACHMENT_BYTES + 1)
    if len(data) > MAX_ATTACHMENT_BYTES:
        raise ValidationFailedError("Attachment exceeds 4 MB")
    if not data:
        raise ValidationFailedError("Attachment is empty")
    magic = _MAGIC.get(ext)
    if magic is not None and not data.startswith(magic if isinstance(magic, tuple) else (magic,)):
        raise ValidationFailedError("File content does not match its extension")
    if ext in (".txt", ".log", ".csv", ".json"):
        try:
            data.decode("utf-8")
        except UnicodeDecodeError as exc:
            raise ValidationFailedError("Text attachments must be UTF-8") from exc
    digest = hashlib.sha256(data).hexdigest()
    key = f"{uuid.uuid4().hex}{ext}"
    EVIDENCE_DIR.mkdir(parents=True, exist_ok=True)
    (EVIDENCE_DIR / key).write_bytes(data)

    def _store() -> Evidence:
        inc = incident_service.get_incident(db, incident_id)
        ev = incident_service.add_evidence(
            db,
            inc,
            user,
            meta,
            evidence_type=EvidenceType.ATTACHMENT,
            content=f"Attachment {filename}",
            attachment={
                "filename": filename,
                "size": len(data),
                "sha256": digest,
                "content_type": ALLOWED_ATTACHMENTS[ext],
                "storage_key": key,
            },
        )
        db.commit()
        return ev

    try:
        ev = await run_in_threadpool(_store)
    except Exception:
        (EVIDENCE_DIR / key).unlink(missing_ok=True)
        raise
    return EvidenceOut.model_validate(ev)


@router.get("/{incident_id}/attachments/{evidence_id}")
def download_attachment(incident_id: int, evidence_id: int, db: DbSession, _: Viewer) -> FileResponse:
    ev = db.get(Evidence, evidence_id)
    if ev is None or ev.incident_id != incident_id or ev.evidence_type != EvidenceType.ATTACHMENT or not ev.attachment:
        raise NotFoundError("Attachment not found")
    key = str(ev.attachment.get("storage_key", ""))
    if not re.fullmatch(r"[0-9a-f]{32}\.[a-z]{2,5}", key):
        raise NotFoundError("Attachment not found")
    path = EVIDENCE_DIR / key
    if not path.is_file():
        raise NotFoundError("Attachment file missing")
    return FileResponse(
        path,
        media_type="application/octet-stream",
        filename=ev.attachment["filename"],
        headers={"X-Content-Type-Options": "nosniff"},
    )


@router.get("/{incident_id}/timeline", response_model=list[ActivityOut])
def activity(incident_id: int, db: DbSession, _: Viewer) -> list[ActivityOut]:
    incident_service.get_incident(db, incident_id)
    rows = db.scalars(
        select(IncidentActivity)
        .where(IncidentActivity.incident_id == incident_id)
        .order_by(IncidentActivity.created_at)
    ).all()
    return [ActivityOut.model_validate(r) for r in rows]
