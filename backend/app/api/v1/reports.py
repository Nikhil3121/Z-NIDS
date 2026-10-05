"""/api/v1/reports — period reports built from stored data."""

from __future__ import annotations

from datetime import UTC, datetime, timedelta
from typing import Annotated, Any, Literal

from fastapi import APIRouter, Depends
from fastapi.responses import PlainTextResponse

from app.api.deps import DbSession, Meta, require
from app.core.exceptions import ValidationFailedError
from app.models.enums import Permission
from app.models.user import User
from app.services import audit_service, report_service

router = APIRouter(prefix="/reports", tags=["reports"])
Viewer = Annotated[User, Depends(require(Permission.VIEW_REPORTS))]


@router.get("/summary", response_model=None)
def summary(
    db: DbSession,
    user: Viewer,
    meta: Meta,
    start: datetime | None = None,
    end: datetime | None = None,
    include_demo: bool = False,
    fmt: Literal["json", "markdown"] = "json",
) -> dict[str, Any] | PlainTextResponse:
    end = end or datetime.now(UTC)
    start = start or end - timedelta(days=1)
    if start >= end:
        raise ValidationFailedError("start must be before end")
    if end - start > timedelta(days=90):
        raise ValidationFailedError("Report period is limited to 90 days")
    report = report_service.build_report(db, start, end, include_demo)
    audit_service.record(
        db,
        "REPORT_GENERATED",
        actor=user,
        resource_type="report",
        meta=meta,
        details={"start": start.isoformat(), "end": end.isoformat(), "format": fmt, "include_demo": include_demo},
    )
    db.commit()
    if fmt == "markdown":
        return PlainTextResponse(
            report_service.to_markdown(report),
            media_type="text/markdown",
            headers={"Content-Disposition": "attachment; filename=znids-report.md"},
        )
    return report
