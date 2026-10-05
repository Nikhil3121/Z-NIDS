"""Event ingestion: validate, normalise, store, hand off to the detection pipeline.

Malformed records are rejected individually (with reasons) — one bad record
never poisons a batch. Re-sending a record with the same (sensor, external_id)
is idempotent.
"""

from __future__ import annotations

import ipaddress
import logging
from dataclasses import dataclass, field
from datetime import UTC, datetime
from functools import lru_cache
from typing import Any

from pydantic import ValidationError
from sqlalchemy import update
from sqlalchemy.dialects.postgresql import insert
from sqlalchemy.orm import Session

from app.core.config import PipelineMode, get_settings
from app.core.metrics import EVENTS_INGESTED, EVENTS_REJECTED
from app.models.asset import Sensor
from app.models.enums import EventSource, FlowDirection, ProcessingStatus
from app.models.network_event import NetworkEvent
from app.schemas.events import EventIn

logger = logging.getLogger(__name__)

PIPELINE_CHUNK = 500


@lru_cache
def _home_networks() -> tuple[ipaddress.IPv4Network | ipaddress.IPv6Network, ...]:
    return tuple(ipaddress.ip_network(n, strict=False) for n in get_settings().home_networks)


def is_internal(ip: str) -> bool:
    addr = ipaddress.ip_address(ip)
    return any(addr in net for net in _home_networks())


def direction_of(src: str, dst: str) -> FlowDirection:
    s, d = is_internal(src), is_internal(dst)
    if s and d:
        return FlowDirection.INTERNAL
    if s:
        return FlowDirection.OUTBOUND
    if d:
        return FlowDirection.INBOUND
    return FlowDirection.EXTERNAL


@dataclass
class IngestResult:
    accepted_ids: list[int] = field(default_factory=list)
    duplicates: int = 0
    rejected: list[dict[str, Any]] = field(default_factory=list)
    queued: bool = False


def validate_records(records: list[dict[str, Any]]) -> tuple[list[EventIn], list[dict[str, Any]]]:
    valid: list[EventIn] = []
    rejected: list[dict[str, Any]] = []
    for i, record in enumerate(records):
        try:
            valid.append(EventIn.model_validate(record))
        except ValidationError as exc:
            rejected.append(
                {"index": i, "errors": [f"{'.'.join(str(p) for p in e['loc'])}: {e['msg']}" for e in exc.errors()][:5]}
            )
    return valid, rejected


def store_events(
    db: Session,
    events: list[EventIn],
    *,
    source_type: EventSource,
    sensor: Sensor | None,
    is_demo: bool,
    allow_labels: bool,
) -> tuple[list[int], int]:
    """Bulk insert; returns (new event ids, duplicate count)."""
    if not events:
        return [], 0
    rows = []
    for ev in events:
        rows.append(
            {
                "external_id": ev.external_id,
                "ts": ev.ts,
                "src_ip": ev.src_ip,
                "src_port": ev.src_port,
                "dst_ip": ev.dst_ip,
                "dst_port": ev.dst_port,
                "protocol": ev.protocol,
                "app_protocol": ev.app_protocol,
                "duration_ms": ev.duration_ms,
                "packets_out": ev.packets_out,
                "packets_in": ev.packets_in,
                "bytes_out": ev.bytes_out,
                "bytes_in": ev.bytes_in,
                "tcp_flags": ev.tcp_flags,
                "conn_state": ev.conn_state,
                "direction": direction_of(ev.src_ip, ev.dst_ip),
                "source_type": source_type,
                "sensor_id": sensor.id if sensor else None,
                "raw_ref": ev.raw_ref,
                "is_demo": is_demo,
                "external_alert": ev.external_alert.model_dump() if ev.external_alert else None,
                "dataset_label": ev.dataset_label if allow_labels else None,
                "processing_status": ProcessingStatus.PENDING,
            }
        )
    ids: list[int] = []
    for i in range(0, len(rows), 1000):
        stmt = (
            insert(NetworkEvent)
            .values(rows[i : i + 1000])
            .on_conflict_do_nothing(constraint="uq_network_events_sensor_external")
            .returning(NetworkEvent.id)
        )
        ids.extend(db.execute(stmt).scalars().all())
    duplicates = len(rows) - len(ids)
    if sensor is not None:
        db.execute(
            update(Sensor)
            .where(Sensor.id == sensor.id)
            .values(last_seen=datetime.now(UTC), events_received=Sensor.events_received + len(ids))
        )
    return ids, duplicates


def dispatch(db: Session, event_ids: list[int]) -> bool:
    """Run the detection pipeline for new events. Returns True if queued to Celery."""
    if not event_ids:
        return False
    settings = get_settings()
    if settings.pipeline_mode == PipelineMode.INLINE:
        from app.services.pipeline import process_events

        for i in range(0, len(event_ids), PIPELINE_CHUNK):
            process_events(db, event_ids[i : i + PIPELINE_CHUNK])
        return False
    from app.workers.tasks.pipeline import process_events_task

    for i in range(0, len(event_ids), PIPELINE_CHUNK):
        process_events_task.delay(event_ids[i : i + PIPELINE_CHUNK])
    return True


def ingest(
    db: Session,
    records: list[dict[str, Any]],
    *,
    source_type: EventSource,
    sensor: Sensor | None,
) -> IngestResult:
    valid, rejected = validate_records(records)
    lab = bool(sensor and sensor.is_demo)
    ids, duplicates = store_events(db, valid, source_type=source_type, sensor=sensor, is_demo=lab, allow_labels=lab)
    db.commit()
    EVENTS_INGESTED.labels(source=source_type.value).inc(len(ids))
    if rejected:
        EVENTS_REJECTED.labels(source=source_type.value).inc(len(rejected))
        logger.warning("rejected malformed events", extra={"count": len(rejected), "source": source_type.value})
    queued = dispatch(db, ids)
    return IngestResult(ids, duplicates, rejected, queued)
