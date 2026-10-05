"""/api/v1/threat-intelligence — provider status, lookups and analyst IOCs."""

from __future__ import annotations

from datetime import datetime
from typing import Annotated, Any

from fastapi import APIRouter, Depends, Query
from pydantic import Field
from sqlalchemy import select

from app.api.deps import DbSession, Meta, require
from app.api.query import apply_sort, page_params, paginate
from app.models.enums import IocType, Permission, Reputation
from app.models.threat_intel import ThreatIntelIndicator
from app.models.user import User
from app.schemas.common import Page, PageParams, Schema, StrictInput
from app.services import threat_intel_service

router = APIRouter(prefix="/threat-intelligence", tags=["threat-intelligence"])
Viewer = Annotated[User, Depends(require(Permission.VIEW_THREAT_INTEL))]
Manager = Annotated[User, Depends(require(Permission.MANAGE_THREAT_INTEL))]


class IndicatorOut(Schema):
    id: int
    ioc_type: IocType
    ioc_value: str
    provider: str
    confidence: float
    reputation: Reputation
    source: str | None
    tags: list[str]
    raw_metadata: dict[str, Any]
    first_seen: datetime | None
    last_seen: datetime | None
    fetched_at: datetime
    expires_at: datetime | None


class LookupIn(StrictInput):
    ioc_type: IocType
    value: str = Field(min_length=1, max_length=2048)
    refresh: bool = False


class IocIn(StrictInput):
    ioc_type: IocType
    value: str = Field(min_length=1, max_length=2048)
    reputation: Reputation
    confidence: float = Field(ge=0, le=100)
    source: str | None = Field(default=None, max_length=255)
    tags: list[str] = Field(default_factory=list, max_length=20)


@router.get("/providers")
def providers(_: Viewer) -> list[dict[str, Any]]:
    return threat_intel_service.provider_statuses()


@router.post("/lookup")
def lookup(body: LookupIn, db: DbSession, user: Manager, meta: Meta) -> dict[str, Any]:
    outcome = threat_intel_service.lookup(db, body.ioc_type, body.value, user=user, meta=meta, refresh=body.refresh)
    db.commit()
    return {
        "ioc_type": outcome.ioc_type.value,
        "ioc_value": outcome.ioc_value,
        "indicators": [IndicatorOut.model_validate(i).model_dump(mode="json") for i in outcome.indicators],
        "providers": outcome.provider_status,
        "note": (
            None if outcome.indicators else "No intelligence available for this indicator from any configured source."
        ),
    }


@router.get("/indicators", response_model=Page[IndicatorOut])
def indicators(
    db: DbSession,
    _: Viewer,
    params: Annotated[PageParams, Depends(page_params)],
    provider: str | None = Query(None, max_length=64, pattern=r"^[a-z0-9_]+$"),
    reputation: Reputation | None = None,
    ioc_type: IocType | None = None,
    q: str | None = Query(None, max_length=200),
    sort: str | None = Query(None, max_length=32),
) -> Page[IndicatorOut]:
    stmt = select(ThreatIntelIndicator)
    if provider:
        stmt = stmt.where(ThreatIntelIndicator.provider == provider)
    if reputation:
        stmt = stmt.where(ThreatIntelIndicator.reputation == reputation)
    if ioc_type:
        stmt = stmt.where(ThreatIntelIndicator.ioc_type == ioc_type)
    if q:
        needle = q.replace("\\", "\\\\").replace("%", "\\%").replace("_", "\\_")
        stmt = stmt.where(ThreatIntelIndicator.ioc_value.ilike(f"%{needle}%", escape="\\"))
    stmt = apply_sort(
        stmt,
        sort,
        {"fetched_at": ThreatIntelIndicator.fetched_at, "confidence": ThreatIntelIndicator.confidence},
        ThreatIntelIndicator.fetched_at.desc(),
    )
    return paginate(db, stmt, params, IndicatorOut.model_validate)


@router.post("/indicators", response_model=IndicatorOut, status_code=201)
def create_ioc(body: IocIn, db: DbSession, user: Manager, meta: Meta) -> IndicatorOut:
    ind = threat_intel_service.create_local_ioc(
        db,
        ioc_type=body.ioc_type,
        value=body.value,
        reputation=body.reputation,
        confidence=body.confidence,
        source=body.source,
        tags=[t[:40] for t in body.tags],
        user=user,
        meta=meta,
    )
    db.commit()
    return IndicatorOut.model_validate(ind)
