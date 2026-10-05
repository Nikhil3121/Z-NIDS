"""/api/v1/response — response engine status, requests, approvals, reverts."""

from __future__ import annotations

from typing import Annotated, Any

from fastapi import APIRouter, Depends, Query
from sqlalchemy import select

from app.api.deps import DbSession, Meta, require
from app.api.query import page_params, paginate
from app.core.config import get_settings
from app.models.enums import Permission, ResponseStatus
from app.models.response import LabBlocklistEntry, ResponseAction
from app.models.user import User
from app.schemas.common import Page, PageParams
from app.schemas.soc import ResponseActionOut, ResponseDecision, ResponseRequest
from app.services import response_service
from app.websocket.events import RealtimeEvent, publish

router = APIRouter(prefix="/response", tags=["response"])
Viewer = Annotated[User, Depends(require(Permission.VIEW_INCIDENTS))]
Requester = Annotated[User, Depends(require(Permission.REQUEST_RESPONSE))]
Approver = Annotated[User, Depends(require(Permission.APPROVE_RESPONSE))]


def _publish(action: ResponseAction) -> None:
    publish(
        RealtimeEvent.RESPONSE_UPDATED,
        {"id": action.id, "status": action.status.value, "incident_id": action.incident_id},
    )


@router.get("/status")
def status(_: Viewer) -> dict[str, Any]:
    s = get_settings()
    return {
        "mode": s.response_mode.value,
        "adapter": response_service.adapter().name,
        "adapter_is_sandbox": s.response_adapter == "lab",
        "explanation": {
            "DETECTION_ONLY": "No response actions can be proposed or executed.",
            "MANUAL_APPROVAL": "Actions are proposed and run only after approval by a second authorised user.",
            "AUTOMATIC": "System-proposed actions execute immediately (explicitly enabled).",
        }[s.response_mode.value],
    }


@router.get("/actions", response_model=Page[ResponseActionOut])
def list_actions(
    db: DbSession,
    _: Viewer,
    params: Annotated[PageParams, Depends(page_params)],
    status: ResponseStatus | None = None,
    incident_id: int | None = Query(None, ge=1),
) -> Page[ResponseActionOut]:
    stmt = select(ResponseAction)
    if status:
        stmt = stmt.where(ResponseAction.status == status)
    if incident_id:
        stmt = stmt.where(ResponseAction.incident_id == incident_id)
    return paginate(db, stmt.order_by(ResponseAction.created_at.desc()), params, ResponseActionOut.model_validate)


@router.post("/actions", response_model=ResponseActionOut, status_code=201)
def request_action(body: ResponseRequest, db: DbSession, user: Requester, meta: Meta) -> ResponseActionOut:
    action = response_service.propose(
        db,
        action_type=body.action_type,
        target=body.target,
        reason=body.reason,
        incident_id=body.incident_id,
        alert_id=body.alert_id,
        requested_by=user,
        meta=meta,
    )
    db.commit()
    _publish(action)
    return ResponseActionOut.model_validate(action)


@router.post("/actions/{action_id}/decision", response_model=ResponseActionOut)
def decide(action_id: int, body: ResponseDecision, db: DbSession, user: Approver, meta: Meta) -> ResponseActionOut:
    action = response_service.decide(db, action_id, body.approve, user, meta, body.comment)
    db.commit()
    _publish(action)
    return ResponseActionOut.model_validate(action)


@router.post("/actions/{action_id}/revert", response_model=ResponseActionOut)
def revert(action_id: int, db: DbSession, user: Approver, meta: Meta) -> ResponseActionOut:
    action = response_service.revert(db, action_id, user, meta)
    db.commit()
    _publish(action)
    return ResponseActionOut.model_validate(action)


@router.get("/lab-blocklist")
def lab_blocklist(db: DbSession, _: Viewer) -> list[dict[str, Any]]:
    rows = db.scalars(select(LabBlocklistEntry).order_by(LabBlocklistEntry.created_at.desc()).limit(500)).all()
    return [
        {
            "id": r.id,
            "ip_address": str(r.ip_address),
            "reason": r.reason,
            "active": r.active,
            "created_at": r.created_at,
            "expires_at": r.expires_at,
            "response_action_id": r.response_action_id,
        }
        for r in rows
    ]
