"""/api/v1/detections — detection center and the unknown-attack center."""

from __future__ import annotations

from datetime import datetime
from typing import Annotated, Any

from fastapi import APIRouter, Depends, Query
from sqlalchemy import or_, select

from app.api.deps import DbSession, require
from app.api.query import apply_sort, page_params, paginate, parse_ip
from app.core.exceptions import NotFoundError
from app.models.alert import Alert, alert_detections
from app.models.asset import Asset
from app.models.detection import Detection
from app.models.enums import Classification, Criticality, DetectorType, Permission, Severity
from app.models.incident import Incident
from app.models.user import User
from app.schemas.common import Page, PageParams
from app.schemas.soc import DetectionOut
from app.services.serializers import detection_out

router = APIRouter(prefix="/detections", tags=["detections"])
Viewer = Annotated[User, Depends(require(Permission.VIEW_DETECTIONS))]

_SORT = {
    "ts": Detection.ts,
    "risk_score": Detection.risk_score,
    "anomaly_score": Detection.anomaly_score,
    "confidence": Detection.confidence,
}


@router.get("", response_model=Page[DetectionOut])
def list_detections(
    db: DbSession,
    _: Viewer,
    params: Annotated[PageParams, Depends(page_params)],
    classification: Classification | None = None,
    detector: DetectorType | None = None,
    severity: Severity | None = None,
    category: str | None = Query(None, max_length=64, pattern=r"^[a-z0-9_]+$"),
    ip: str | None = Query(None, max_length=45),
    min_risk: float | None = Query(None, ge=0, le=100),
    demo: bool | None = None,
    since: datetime | None = None,
    until: datetime | None = None,
    sort: str | None = Query(None, max_length=32),
) -> Page[DetectionOut]:
    stmt = select(Detection)
    if classification:
        stmt = stmt.where(Detection.classification == classification)
    if detector:
        stmt = stmt.where(Detection.detectors_fired.contains([detector.value]))
    if severity:
        stmt = stmt.where(Detection.severity == severity)
    if category:
        stmt = stmt.where(Detection.category == category)
    if (addr := parse_ip(ip)) is not None:
        stmt = stmt.where(or_(Detection.src_ip == addr, Detection.dst_ip == addr))
    if min_risk is not None:
        stmt = stmt.where(Detection.risk_score >= min_risk)
    if demo is not None:
        stmt = stmt.where(Detection.is_demo.is_(demo))
    if since:
        stmt = stmt.where(Detection.ts >= since)
    if until:
        stmt = stmt.where(Detection.ts < until)
    stmt = apply_sort(stmt, sort, _SORT, Detection.ts.desc())
    return paginate(db, stmt, params, detection_out)


@router.get("/unknown")
def unknown_attack_center(
    db: DbSession,
    _: Viewer,
    params: Annotated[PageParams, Depends(page_params)],
    min_risk: float | None = Query(None, ge=0, le=100),
    demo: bool | None = None,
    sort: str | None = Query(None, max_length=32),
) -> dict[str, Any]:
    """Potential unknown attacks with their incident, asset criticality and status.

    One row per alert (deduplicated), not per flow, so an analyst sees each
    unknown behaviour once with its occurrence count.
    """
    stmt = (
        select(Alert, Incident)
        .outerjoin(Incident, Incident.id == Alert.incident_id)
        .where(Alert.classification == Classification.POTENTIAL_UNKNOWN)
    )
    if min_risk is not None:
        stmt = stmt.where(Alert.risk_score >= min_risk)
    if demo is not None:
        stmt = stmt.where(Alert.is_demo.is_(demo))
    stmt = apply_sort(
        stmt, sort, {"last_seen": Alert.last_seen, "risk_score": Alert.risk_score}, Alert.last_seen.desc()
    )

    def row(r: Any) -> dict[str, Any]:
        alert, incident = r
        det = db.get(Detection, alert.primary_detection_id) if alert.primary_detection_id else None
        # The internal asset involved: the more critical of source and destination.
        ips = [ip for ip in (alert.src_ip, alert.dst_ip) if ip is not None]
        involved = db.scalars(select(Asset).where(Asset.ip_address.in_(ips))).all() if ips else []
        asset = max(involved, key=lambda a: Criticality(a.criticality).score, default=None)
        return {
            "alert_id": alert.id,
            "incident_id": incident.id if incident else None,
            "incident_reference": incident.reference if incident else None,
            "incident_status": incident.status.value if incident else None,
            "alert_status": alert.status.value,
            "title": alert.title,
            "src_ip": str(alert.src_ip) if alert.src_ip else None,
            "dst_ip": str(alert.dst_ip) if alert.dst_ip else None,
            "first_seen": alert.first_seen,
            "last_seen": alert.last_seen,
            "occurrences": alert.occurrence_count,
            "anomaly_score": det.anomaly_score if det else None,
            "confidence": det.confidence if det else None,
            "risk_score": alert.risk_score,
            "severity": alert.severity.value,
            "asset_criticality": asset.criticality.value if asset else None,
            "asset_hostname": asset.hostname if asset else None,
            "top_factors": [f.get("detail") for f in (det.explanation if det else [])[:3]],
            "is_demo": alert.is_demo,
        }

    page = paginate(db, stmt, params, row, scalars=False)
    return page.model_dump(mode="json")


@router.get("/{detection_id}", response_model=DetectionOut)
def get_detection(detection_id: int, db: DbSession, _: Viewer) -> DetectionOut:
    det = db.get(Detection, detection_id)
    if det is None:
        raise NotFoundError("Detection not found")
    return detection_out(det)


@router.get("/{detection_id}/alerts")
def detection_alerts(detection_id: int, db: DbSession, _: Viewer) -> list[int]:
    return list(
        db.scalars(select(alert_detections.c.alert_id).where(alert_detections.c.detection_id == detection_id)).all()
    )
