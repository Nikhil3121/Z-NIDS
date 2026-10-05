"""/api/v1/alerts — alert queue and analyst workflow."""

from __future__ import annotations

from datetime import datetime
from typing import Annotated

from fastapi import APIRouter, Depends, Query
from sqlalchemy import or_, select

from app.api.deps import DbSession, Meta, require
from app.api.query import apply_sort, page_params, paginate, parse_ip
from app.core.exceptions import NotFoundError
from app.models.alert import Alert, alert_detections
from app.models.detection import Detection
from app.models.enums import AlertStatus, AlertType, Classification, Permission, Severity
from app.models.user import User
from app.schemas.common import Page, PageParams
from app.schemas.soc import AlertOut, AlertUpdate
from app.services import alert_service
from app.services.serializers import detection_out
from app.websocket.events import RealtimeEvent, publish

router = APIRouter(prefix="/alerts", tags=["alerts"])
Viewer = Annotated[User, Depends(require(Permission.VIEW_ALERTS))]
Manager = Annotated[User, Depends(require(Permission.MANAGE_ALERTS))]

_SORT = {
    "last_seen": Alert.last_seen,
    "first_seen": Alert.first_seen,
    "risk_score": Alert.risk_score,
    "occurrence_count": Alert.occurrence_count,
}


@router.get("", response_model=Page[AlertOut])
def list_alerts(
    db: DbSession,
    user: Viewer,
    params: Annotated[PageParams, Depends(page_params)],
    status: AlertStatus | None = None,
    severity: Severity | None = None,
    classification: Classification | None = None,
    alert_type: AlertType | None = None,
    category: str | None = Query(None, max_length=64, pattern=r"^[a-z0-9_]+$"),
    ip: str | None = Query(None, max_length=45),
    assigned_to_me: bool = False,
    open_only: bool = False,
    demo: bool | None = None,
    since: datetime | None = None,
    q: str | None = Query(None, max_length=100),
    sort: str | None = Query(None, max_length=32),
) -> Page[AlertOut]:
    stmt = select(Alert)
    if status:
        stmt = stmt.where(Alert.status == status)
    if open_only:
        stmt = stmt.where(Alert.status.in_([AlertStatus.OPEN, AlertStatus.ACKNOWLEDGED]))
    if severity:
        stmt = stmt.where(Alert.severity == severity)
    if classification:
        stmt = stmt.where(Alert.classification == classification)
    if alert_type:
        stmt = stmt.where(Alert.alert_type == alert_type)
    if category:
        stmt = stmt.where(Alert.category == category)
    if (addr := parse_ip(ip)) is not None:
        stmt = stmt.where(or_(Alert.src_ip == addr, Alert.dst_ip == addr))
    if assigned_to_me:
        stmt = stmt.where(Alert.assigned_to_id == user.id)
    if demo is not None:
        stmt = stmt.where(Alert.is_demo.is_(demo))
    if since:
        stmt = stmt.where(Alert.last_seen >= since)
    if q:
        # Parameterised ILIKE; wildcard characters in the input are escaped.
        needle = q.replace("\\", "\\\\").replace("%", "\\%").replace("_", "\\_")
        stmt = stmt.where(Alert.title.ilike(f"%{needle}%", escape="\\"))
    stmt = apply_sort(stmt, sort, _SORT, Alert.last_seen.desc())
    return paginate(db, stmt, params, AlertOut.model_validate)


@router.get("/{alert_id}")
def get_alert(alert_id: int, db: DbSession, _: Viewer) -> dict:
    alert = alert_service.get_alert(db, alert_id)
    detections = db.scalars(
        select(Detection)
        .join(alert_detections, alert_detections.c.detection_id == Detection.id)
        .where(alert_detections.c.alert_id == alert_id)
        .order_by(Detection.ts.desc())
        .limit(50)
    ).all()
    return {
        "alert": AlertOut.model_validate(alert).model_dump(mode="json"),
        "detections": [detection_out(d).model_dump(mode="json") for d in detections],
    }


@router.patch("/{alert_id}", response_model=AlertOut)
def update_alert(alert_id: int, body: AlertUpdate, db: DbSession, user: Manager, meta: Meta) -> AlertOut:
    alert = db.scalar(select(Alert).where(Alert.id == alert_id).with_for_update(key_share=True))
    if alert is None:
        raise NotFoundError("Alert not found")
    if body.status is not None:
        alert_service.change_status(db, alert, body.status, user, meta, body.note)
    if body.assigned_to_id is not None or body.unassign:
        assignee = None
        if body.assigned_to_id is not None:
            assignee = db.get(User, body.assigned_to_id)
            if assignee is None or not assignee.is_active:
                raise NotFoundError("Assignee not found")
        alert_service.assign(db, alert, assignee, user, meta)
    db.commit()
    out = AlertOut.model_validate(alert)
    publish(RealtimeEvent.ALERT_UPDATED, out.model_dump(mode="json"))
    return out
