"""/api/v1/audit — read-only audit trail."""

from __future__ import annotations

import csv
import io
from datetime import datetime
from typing import Annotated, Any

from fastapi import APIRouter, Depends, Query
from fastapi.responses import StreamingResponse
from sqlalchemy import select

from app.api.deps import DbSession, Meta, require
from app.api.query import apply_sort, page_params, paginate
from app.models.audit import AuditLog
from app.models.enums import AuditResult, Permission
from app.models.user import User
from app.schemas.common import Page, PageParams, Schema
from app.services import audit_service

router = APIRouter(prefix="/audit", tags=["audit"])
Auditor = Annotated[User, Depends(require(Permission.VIEW_AUDIT))]


class AuditOut(Schema):
    id: int
    ts: datetime
    actor_id: int | None
    actor_label: str
    action: str
    resource_type: str | None
    resource_id: str | None
    result: AuditResult
    ip_address: str | None
    user_agent: str | None
    request_id: str | None
    details: dict[str, Any]


def _filtered(
    action: str | None,
    actor: str | None,
    resource_type: str | None,
    resource_id: str | None,
    result: AuditResult | None,
    since: datetime | None,
    until: datetime | None,
):  # type: ignore[no-untyped-def]
    stmt = select(AuditLog)
    if action:
        stmt = stmt.where(AuditLog.action == action)
    if actor:
        needle = actor.replace("\\", "\\\\").replace("%", "\\%").replace("_", "\\_")
        stmt = stmt.where(AuditLog.actor_label.ilike(f"%{needle}%", escape="\\"))
    if resource_type:
        stmt = stmt.where(AuditLog.resource_type == resource_type)
    if resource_id:
        stmt = stmt.where(AuditLog.resource_id == resource_id)
    if result:
        stmt = stmt.where(AuditLog.result == result)
    if since:
        stmt = stmt.where(AuditLog.ts >= since)
    if until:
        stmt = stmt.where(AuditLog.ts < until)
    return stmt


@router.get("", response_model=Page[AuditOut])
def list_audit(
    db: DbSession,
    _: Auditor,
    params: Annotated[PageParams, Depends(page_params)],
    action: str | None = Query(None, max_length=64, pattern=r"^[A-Z_]+$"),
    actor: str | None = Query(None, max_length=254),
    resource_type: str | None = Query(None, max_length=64, pattern=r"^[a-z_]+$"),
    resource_id: str | None = Query(None, max_length=64),
    result: AuditResult | None = None,
    since: datetime | None = None,
    until: datetime | None = None,
    sort: str | None = Query(None, max_length=16),
) -> Page[AuditOut]:
    stmt = _filtered(action, actor, resource_type, resource_id, result, since, until)
    stmt = apply_sort(stmt, sort, {"ts": AuditLog.ts}, AuditLog.ts.desc())
    return paginate(db, stmt, params, AuditOut.model_validate)


@router.get("/actions")
def actions(db: DbSession, _: Auditor) -> list[str]:
    return list(db.scalars(select(AuditLog.action).distinct().order_by(AuditLog.action)).all())


@router.get("/export")
def export_csv(
    db: DbSession,
    user: Auditor,
    meta: Meta,
    since: datetime | None = None,
    until: datetime | None = None,
    action: str | None = Query(None, max_length=64, pattern=r"^[A-Z_]+$"),
) -> StreamingResponse:
    """CSV export (max 50k rows). Exporting is itself audited."""
    rows = db.scalars(
        _filtered(action, None, None, None, None, since, until).order_by(AuditLog.ts.desc()).limit(50_000)
    ).all()
    audit_service.record(
        db,
        "AUDIT_EXPORTED",
        actor=user,
        resource_type="audit",
        meta=meta,
        details={"rows": len(rows), "since": str(since), "until": str(until)},
    )
    db.commit()
    buf = io.StringIO()
    writer = csv.writer(buf)
    writer.writerow(["ts", "actor", "action", "resource_type", "resource_id", "result", "ip", "request_id"])
    for r in rows:
        # Prefix formula-leading cells so the export is safe to open in spreadsheets.
        cells = [
            r.ts.isoformat(),
            r.actor_label,
            r.action,
            r.resource_type or "",
            r.resource_id or "",
            r.result.value,
            r.ip_address or "",
            r.request_id or "",
        ]
        writer.writerow(["'" + c if c[:1] in ("=", "+", "-", "@") else c for c in cells])
    return StreamingResponse(
        iter([buf.getvalue()]),
        media_type="text/csv",
        headers={"Content-Disposition": "attachment; filename=znids-audit.csv"},
    )
