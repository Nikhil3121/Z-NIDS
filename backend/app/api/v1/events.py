"""/api/v1/events — sensor ingestion (REST + log adapters) and the events explorer."""

from __future__ import annotations

from datetime import datetime
from typing import Annotated, Literal

from fastapi import APIRouter, Body, Depends, Query, Request
from sqlalchemy import or_, select
from starlette.concurrency import run_in_threadpool

from app.api.deps import CurrentSensor, DbSession, require
from app.api.query import apply_sort, page_params, paginate, parse_ip
from app.core.exceptions import NotFoundError, ValidationFailedError
from app.integrations.ingest.adapters import ADAPTERS
from app.models.detection import Detection
from app.models.enums import Classification, EventSource, FlowDirection, Permission, Protocol
from app.models.network_event import NetworkEvent
from app.models.user import User
from app.schemas.common import Page, PageParams
from app.schemas.events import EventOut, IngestRequest, IngestResponse, RejectedEvent
from app.services import ingest_service
from app.services.serializers import detection_out

router = APIRouter(prefix="/events", tags=["events"])

MAX_LOG_LINES = 5000


def _response(result: ingest_service.IngestResult, extra_rejected: list[dict] | None = None) -> IngestResponse:
    rejected = [RejectedEvent(**r) for r in result.rejected]
    for r in extra_rejected or []:
        rejected.append(RejectedEvent(index=r["line"], errors=[r["error"]]))
    return IngestResponse(
        accepted=len(result.accepted_ids),
        duplicates=result.duplicates,
        rejected=rejected,
        queued=result.queued,
        event_ids=result.accepted_ids[:1000],
    )


@router.post("/ingest", response_model=IngestResponse, status_code=202)
def ingest_events(body: IngestRequest, sensor: CurrentSensor, db: DbSession) -> IngestResponse:
    """Normalised JSON events from an authenticated sensor (header `X-Sensor-Key`)."""
    source = sensor.sensor_type if sensor.sensor_type != EventSource.CSV else EventSource.API
    result = ingest_service.ingest(db, body.events, source_type=source, sensor=sensor)
    return _response(result)


@router.post("/ingest/{fmt}", response_model=IngestResponse, status_code=202)
async def ingest_log(
    fmt: Literal["zeek", "suricata", "netflow"], request: Request, sensor: CurrentSensor, db: DbSession
) -> IngestResponse:
    """Raw sensor log lines (Zeek conn.log TSV/JSON, Suricata EVE JSON, goflow2 JSON) as text/plain."""
    text = (await request.body()).decode("utf-8", errors="replace")
    lines = text.splitlines()
    if len(lines) > MAX_LOG_LINES:
        raise ValidationFailedError(f"At most {MAX_LOG_LINES} lines per request")
    parsed = ADAPTERS[fmt](lines, f"{sensor.name}")
    source = {"zeek": EventSource.ZEEK, "suricata": EventSource.SURICATA, "netflow": EventSource.NETFLOW}[fmt]
    # DB work is synchronous: keep it off the event loop.
    result = await run_in_threadpool(ingest_service.ingest, db, parsed.records, source_type=source, sensor=sensor)
    return _response(result, parsed.errors)


_SORT = {
    "ts": NetworkEvent.ts,
    "risk_score": NetworkEvent.risk_score,
    "anomaly_score": NetworkEvent.anomaly_score,
    "bytes_out": NetworkEvent.bytes_out,
    "id": NetworkEvent.id,
}


@router.get("", response_model=Page[EventOut])
def list_events(
    db: DbSession,
    _: Annotated[User, Depends(require(Permission.VIEW_EVENTS))],
    params: Annotated[PageParams, Depends(page_params)],
    ip: str | None = None,
    src_ip: str | None = None,
    dst_ip: str | None = None,
    dst_port: int | None = Query(None, ge=0, le=65535),
    protocol: Protocol | None = None,
    classification: Classification | None = None,
    direction: FlowDirection | None = None,
    source_type: EventSource | None = None,
    demo: bool | None = None,
    since: datetime | None = None,
    until: datetime | None = None,
    sort: str | None = Query(None, max_length=32),
) -> Page[EventOut]:
    stmt = select(NetworkEvent)
    if (v := parse_ip(ip, "ip")) is not None:
        stmt = stmt.where(or_(NetworkEvent.src_ip == v, NetworkEvent.dst_ip == v))
    if (v := parse_ip(src_ip, "src_ip")) is not None:
        stmt = stmt.where(NetworkEvent.src_ip == v)
    if (v := parse_ip(dst_ip, "dst_ip")) is not None:
        stmt = stmt.where(NetworkEvent.dst_ip == v)
    if dst_port is not None:
        stmt = stmt.where(NetworkEvent.dst_port == dst_port)
    if protocol is not None:
        stmt = stmt.where(NetworkEvent.protocol == protocol)
    if classification is not None:
        stmt = stmt.where(NetworkEvent.classification == classification)
    if direction is not None:
        stmt = stmt.where(NetworkEvent.direction == direction)
    if source_type is not None:
        stmt = stmt.where(NetworkEvent.source_type == source_type)
    if demo is not None:
        stmt = stmt.where(NetworkEvent.is_demo.is_(demo))
    if since is not None:
        stmt = stmt.where(NetworkEvent.ts >= since)
    if until is not None:
        stmt = stmt.where(NetworkEvent.ts < until)
    stmt = apply_sort(stmt, sort, _SORT, NetworkEvent.ts.desc())
    return paginate(db, stmt, params, EventOut.model_validate)


@router.get("/{event_id}")
def get_event(event_id: int, db: DbSession, _: Annotated[User, Depends(require(Permission.VIEW_EVENTS))]) -> dict:
    event = db.get(NetworkEvent, event_id)
    if event is None:
        raise NotFoundError("Event not found")
    detections = db.scalars(select(Detection).where(Detection.event_id == event_id)).all()
    return {
        "event": EventOut.model_validate(event).model_dump(mode="json"),
        "detections": [detection_out(d).model_dump(mode="json") for d in detections],
    }


@router.post("/validate", response_model=IngestResponse)
def validate_only(
    _: Annotated[User, Depends(require(Permission.VIEW_EVENTS))],
    events: Annotated[list[dict], Body(min_length=1, max_length=500)],
) -> IngestResponse:
    """Dry-run validation for sensor developers: nothing is stored."""
    valid, rejected = ingest_service.validate_records(events)
    return IngestResponse(
        accepted=len(valid), duplicates=0, rejected=[RejectedEvent(**r) for r in rejected], queued=False, event_ids=[]
    )
