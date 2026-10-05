"""Periodic maintenance: baselines, asset risk, drift, retention."""

from __future__ import annotations

import logging
from datetime import UTC, datetime, timedelta

from sqlalchemy import func, select, update

from app.core.redis import get_redis
from app.db.session import get_sessionmaker
from app.detection.behavioral.baseline import update_baselines as _update_baselines
from app.models.asset import Asset
from app.models.detection import Detection
from app.models.enums import NotificationEvent
from app.models.notification import Notification
from app.services import notification_service
from app.services.drift_service import run_drift_check
from app.services.notification_service import Message
from app.services.retention_service import apply_retention as _apply_retention
from app.websocket.events import RealtimeEvent, publish
from app.workers.celery_app import celery_app

logger = logging.getLogger(__name__)

_WATERMARK = "znids:baseline:watermark"
_LOCK = "znids:lock:{}"


def _acquire(name: str, ttl: int) -> bool:
    """Single-runner guard across workers (Redis SET NX EX)."""
    return bool(get_redis().set(_LOCK.format(name), "1", nx=True, ex=ttl))


def _release(name: str) -> None:
    get_redis().delete(_LOCK.format(name))


@celery_app.task(name="app.workers.tasks.maintenance.update_baselines")
def update_baselines() -> int:
    if not _acquire("baselines", 120):
        return 0
    try:
        redis = get_redis()
        end = datetime.now(UTC) - timedelta(seconds=60)  # let in-flight minutes settle
        raw = redis.get(_WATERMARK)
        start = datetime.fromisoformat(raw) if raw else end - timedelta(hours=1)
        if start >= end:
            return 0
        db = get_sessionmaker()()
        try:
            minutes = _update_baselines(db, start, end)
            db.commit()
        finally:
            db.close()
        redis.set(_WATERMARK, end.isoformat())
        return minutes
    finally:
        _release("baselines")


@celery_app.task(name="app.workers.tasks.maintenance.recompute_asset_risk")
def recompute_asset_risk(hours: int = 24) -> int:
    """Asset risk = highest detection risk touching the asset in the last `hours` (so it decays)."""
    db = get_sessionmaker()()
    try:
        since = datetime.now(UTC) - timedelta(hours=hours)
        risk: dict[str, float] = {}
        for col in (Detection.src_ip, Detection.dst_ip):
            rows = db.execute(
                select(col, func.max(Detection.risk_score)).where(Detection.ts >= since).group_by(col)
            ).all()
            for ip, r in rows:
                risk[str(ip)] = max(risk.get(str(ip), 0.0), float(r))
        db.execute(update(Asset).where(Asset.risk_score > 0).values(risk_score=0.0))
        if risk:
            for asset in db.scalars(select(Asset).where(Asset.ip_address.in_(list(risk)))).all():
                asset.risk_score = risk[str(asset.ip_address)]
        db.commit()
        return len(risk)
    finally:
        db.close()


@celery_app.task(name="app.workers.tasks.maintenance.drift_check")
def drift_check(hours: int = 24) -> str:
    db = get_sessionmaker()()
    try:
        outcome = run_drift_check(db, hours=hours)
        created: list[Notification] = []
        if outcome.alert is not None and outcome.report is not None:
            created = notification_service.notify(
                db,
                Message(
                    NotificationEvent.MODEL_DRIFT,
                    outcome.alert.title,
                    outcome.alert.description,
                    outcome.alert.severity,
                    "ml_model",
                    str(outcome.report.model_id),
                ),
            )
        db.commit()
        if outcome.report is not None and outcome.report.drifted:
            publish(
                RealtimeEvent.MODEL_DRIFT_DETECTED,
                {
                    "report_id": outcome.report.id,
                    "model_id": outcome.report.model_id,
                    "max_psi": outcome.report.max_psi,
                },
            )
        notification_service.publish_created(created)
        return outcome.reason
    finally:
        db.close()


@celery_app.task(name="app.workers.tasks.maintenance.apply_retention")
def apply_retention() -> dict[str, int]:
    if not _acquire("retention", 3600):
        return {}
    db = get_sessionmaker()()
    try:
        return _apply_retention(db)
    finally:
        db.close()
        _release("retention")
