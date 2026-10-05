"""Pipeline tasks."""

from __future__ import annotations

import logging

from app.db.session import get_sessionmaker
from app.services.pipeline import pending_event_ids, process_events
from app.workers.celery_app import celery_app

logger = logging.getLogger(__name__)


@celery_app.task(
    name="app.workers.tasks.pipeline.process_events_task",
    bind=True,
    max_retries=3,
    autoretry_for=(ConnectionError,),
    retry_backoff=True,
)
def process_events_task(self, event_ids: list[int]) -> dict[str, int]:  # type: ignore[no-untyped-def]
    db = get_sessionmaker()()
    try:
        result = process_events(db, [int(i) for i in event_ids])
        return {
            "processed": result.processed,
            "detections": result.detections,
            "alerts_created": result.alerts_created,
            "incidents_created": result.incidents_created,
        }
    finally:
        db.close()


@celery_app.task(name="app.workers.tasks.pipeline.sweep_pending")
def sweep_pending() -> int:
    """Safety net: re-dispatch events left PENDING (e.g. a lost task after a worker crash)."""
    db = get_sessionmaker()()
    try:
        ids = pending_event_ids(db, limit=5000, older_than_seconds=120)
    finally:
        db.close()
    for i in range(0, len(ids), 500):
        process_events_task.delay(ids[i : i + 500])
    if ids:
        logger.info("re-dispatched pending events", extra={"count": len(ids)})
    return len(ids)
