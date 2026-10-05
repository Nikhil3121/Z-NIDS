"""Follow-up work after the pipeline commits: notifications, TI enrichment, response proposals."""

from __future__ import annotations

import logging
from datetime import UTC, datetime, timedelta

from sqlalchemy import select
from sqlalchemy.orm import Session

from app.db.session import get_sessionmaker
from app.integrations.threat_intel.providers import external_providers
from app.models.alert import Alert
from app.models.enums import (
    Classification,
    DeliveryStatus,
    EvidenceType,
    IocType,
    NotificationEvent,
    Reputation,
    Severity,
)
from app.models.incident import Evidence, Incident
from app.models.notification import Notification
from app.models.response import ResponseAction
from app.services import notification_service, response_service, threat_intel_service
from app.services.ingest_service import is_internal
from app.services.notification_service import Message
from app.websocket.events import RealtimeEvent, publish
from app.workers.celery_app import celery_app

logger = logging.getLogger(__name__)


@celery_app.task(name="app.workers.tasks.followup.handle_new_alerts")
def handle_new_alerts(alert_ids: list[int]) -> int:
    db = get_sessionmaker()()
    created: list[Notification] = []
    try:
        alerts = db.scalars(select(Alert).where(Alert.id.in_(alert_ids))).all()
        for alert in alerts:
            if alert.severity == Severity.CRITICAL:
                created += notification_service.notify(
                    db,
                    Message(
                        NotificationEvent.CRITICAL_ALERT,
                        f"Critical alert: {alert.title}",
                        alert.description,
                        alert.severity,
                        "alert",
                        str(alert.id),
                    ),
                )
            elif alert.classification == Classification.POTENTIAL_UNKNOWN and alert.risk_score >= 65:
                created += notification_service.notify(
                    db,
                    Message(
                        NotificationEvent.UNKNOWN_ANOMALY,
                        f"High-risk potential unknown attack: {alert.title}",
                        alert.description,
                        alert.severity,
                        "alert",
                        str(alert.id),
                    ),
                )
            _enrich(db, alert)
        db.commit()
        notification_service.publish_created(created)
        return len(created)
    finally:
        db.close()


def _enrich(db: Session, alert: Alert) -> None:
    """Look up external endpoints with configured providers; attach malicious hits as evidence."""
    if not any(p.configured() for p in external_providers()):
        return
    ips = {str(ip) for ip in (alert.src_ip, alert.dst_ip) if ip is not None}
    for ip in ips:
        if is_internal(ip):
            continue
        try:
            outcome = threat_intel_service.lookup(db, IocType.IP, ip, user=None, meta=None)
        except Exception:
            logger.exception("threat intel enrichment failed", extra={"alert_id": alert.id})
            continue
        for ind in outcome.indicators:
            if ind.reputation in (Reputation.MALICIOUS, Reputation.SUSPICIOUS) and alert.incident_id:
                db.add(
                    Evidence(
                        incident_id=alert.incident_id,
                        evidence_type=EvidenceType.THREAT_INTEL,
                        threat_intel_id=ind.id,
                        content=f"{ip} rated {ind.reputation.value} by {ind.provider} "
                        f"(confidence {ind.confidence:.0f})",
                    )
                )


@celery_app.task(name="app.workers.tasks.followup.handle_new_incidents")
def handle_new_incidents(new_ids: list[int], escalated_ids: list[int]) -> int:
    db = get_sessionmaker()()
    created: list[Notification] = []
    proposals: list[ResponseAction] = []
    try:
        for inc in db.scalars(select(Incident).where(Incident.id.in_(new_ids + escalated_ids))).all():
            if inc.id in escalated_ids:
                created += notification_service.notify(
                    db,
                    Message(
                        NotificationEvent.INCIDENT_ESCALATED,
                        f"{inc.reference} escalated to {inc.severity.value}",
                        inc.title,
                        inc.severity,
                        "incident",
                        str(inc.id),
                    ),
                )
            if Severity(inc.severity).rank >= Severity.HIGH.rank:
                src = str(inc.primary_src_ip) if inc.primary_src_ip else None
                proposals += response_service.suggest_for_incident(db, inc.id, src, inc.is_demo)
        if proposals:
            lines = [f"#{p.id} {p.action_type.value} {p.target}: {p.reason}" for p in proposals]
            created += notification_service.notify(
                db,
                Message(
                    NotificationEvent.RESPONSE_APPROVAL,
                    f"{len(proposals)} response action(s) awaiting approval",
                    "\n".join(lines),
                    Severity.HIGH,
                    "incident",
                    str(proposals[0].incident_id),
                ),
            )
        db.commit()
        notification_service.publish_created(created)
        for p in proposals:
            publish(
                RealtimeEvent.RESPONSE_UPDATED, {"id": p.id, "status": p.status.value, "incident_id": p.incident_id}
            )
        return len(created)
    finally:
        db.close()


@celery_app.task(name="app.workers.tasks.followup.retry_failed_notifications")
def retry_failed_notifications(max_attempts: int = 5) -> int:
    db = get_sessionmaker()()
    try:
        cutoff = datetime.now(UTC) - timedelta(days=1)
        pending = db.scalars(
            select(Notification)
            .where(
                Notification.delivery_status.in_([DeliveryStatus.FAILED, DeliveryStatus.PENDING]),
                Notification.attempts < max_attempts,
                Notification.created_at >= cutoff,
            )
            .limit(200)
        ).all()
        for n in pending:
            notification_service.deliver(db, n)
        db.commit()
        return len(pending)
    finally:
        db.close()
