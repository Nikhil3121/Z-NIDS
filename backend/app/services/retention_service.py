"""Data retention: bounded, batched deletes driven by *_RETENTION_DAYS settings."""

from __future__ import annotations

import logging
from datetime import UTC, datetime, timedelta

from sqlalchemy import delete, select
from sqlalchemy.orm import Session

from app.core.config import get_settings
from app.models.audit import AuditLog
from app.models.detection import Detection
from app.models.network_event import EventRollup, NetworkEvent
from app.models.notification import Notification
from app.models.threat_intel import ThreatIntelIndicator
from app.models.user import AuthToken, RefreshToken

logger = logging.getLogger(__name__)


def _purge(db: Session, model: type, ts_col, cutoff: datetime, batch: int, extra=None) -> int:  # type: ignore[no-untyped-def]
    total = 0
    pk = model.__mapper__.primary_key[0]
    while True:
        stmt = select(pk).where(ts_col < cutoff)
        if extra is not None:
            stmt = stmt.where(extra)
        ids = list(db.scalars(stmt.limit(batch)).all())
        if not ids:
            break
        db.execute(delete(model).where(pk.in_(ids)))
        db.commit()
        total += len(ids)
        if len(ids) < batch:
            break
    return total


def apply_retention(db: Session) -> dict[str, int]:
    s = get_settings()
    now = datetime.now(UTC)
    b = s.retention_batch_size
    result = {
        "network_events": _purge(db, NetworkEvent, NetworkEvent.ts, now - timedelta(days=s.event_retention_days), b),
        "event_rollups": _purge(
            db, EventRollup, EventRollup.bucket, now - timedelta(days=s.detection_retention_days), b
        ),
        "detections": _purge(db, Detection, Detection.ts, now - timedelta(days=s.detection_retention_days), b),
        "audit_logs": _purge(db, AuditLog, AuditLog.ts, now - timedelta(days=s.audit_retention_days), b),
        "threat_intel": _purge(
            db,
            ThreatIntelIndicator,
            ThreatIntelIndicator.fetched_at,
            now - timedelta(days=s.threat_intel_retention_days),
            b,
            extra=ThreatIntelIndicator.provider != "local",
        ),
        "notifications": _purge(db, Notification, Notification.created_at, now - timedelta(days=90), b),
        "refresh_tokens": _purge(db, RefreshToken, RefreshToken.expires_at, now - timedelta(days=1), b),
        "auth_tokens": _purge(db, AuthToken, AuthToken.expires_at, now - timedelta(days=1), b),
    }
    logger.info("retention applied", extra={"deleted": result})
    return result
