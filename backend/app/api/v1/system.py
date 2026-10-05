"""/api/v1/system — non-secret configuration and component status for the Settings page."""

from __future__ import annotations

from typing import Annotated, Any

from fastapi import APIRouter, Depends
from sqlalchemy import func, select

from app.api.deps import CurrentUser, DbSession, Meta, require
from app.core.config import get_settings
from app.integrations.notifications.email import email_configured
from app.ml.inference.service import model_cache
from app.models.enums import Permission, ProcessingStatus
from app.models.network_event import NetworkEvent
from app.models.user import User
from app.services import audit_service, pipeline, threat_intel_service
from app.services.risk_service import get_weights

router = APIRouter(prefix="/system", tags=["system"])
Admin = Annotated[User, Depends(require(Permission.MANAGE_SETTINGS))]


@router.get("/info")
def info(_: CurrentUser) -> dict[str, Any]:
    """Minimal flags every signed-in user needs (demo banner, response mode)."""
    s = get_settings()
    return {"environment": s.environment.value, "demo_mode": s.demo_mode, "response_mode": s.response_mode.value}


@router.get("/status")
def status(db: DbSession, _: Admin) -> dict[str, Any]:
    s = get_settings()
    active = model_cache.get(db)
    backlog = dict(
        db.execute(
            select(NetworkEvent.processing_status, func.count())
            .where(NetworkEvent.processing_status != ProcessingStatus.PROCESSED)
            .group_by(NetworkEvent.processing_status)
        ).all()
    )
    sig = pipeline.signature_detector()
    return {
        "environment": s.environment.value,
        "demo_mode": s.demo_mode,
        "pipeline_mode": s.pipeline_mode.value,
        "response": {"mode": s.response_mode.value, "adapter": s.response_adapter},
        "detectors": {
            "signature": sig.status(),
            "anomaly": {"available": active is not None, "model": active.tag if active else None},
            "behavioral": {"available": True, "min_observations": s.baseline_min_observations},
            "threat_intel": threat_intel_service.provider_statuses(),
        },
        "risk_weights": {"version": get_weights().version, "trust": get_weights().trust},
        "alerting": {
            "email_configured": email_configured(),
            "email_backend": s.email_backend,
            "webhook_signing_configured": bool(s.webhook_signing_secret),
            "slack_default_configured": bool(s.slack_webhook_url),
        },
        "assistant": {"llm_configured": bool(s.anthropic_api_key), "model": s.assistant_model},
        "retention_days": {
            "events": s.event_retention_days,
            "detections": s.detection_retention_days,
            "audit": s.audit_retention_days,
            "threat_intel": s.threat_intel_retention_days,
        },
        "processing_backlog": {getattr(k, "value", k): int(v) for k, v in backlog.items()},
        "home_networks": s.home_networks,
    }


@router.post("/reload-rules")
def reload_rules(db: DbSession, user: Admin, meta: Meta) -> dict[str, Any]:
    """Re-read signature rules from disk (validated). Other workers pick them up on restart."""
    detector = pipeline.reload_signatures()
    get_weights.cache_clear()
    audit_service.record(
        db,
        "CONFIGURATION_CHANGED",
        actor=user,
        resource_type="signature_rules",
        meta=meta,
        details={"version": detector.ruleset.version, "enabled_rules": len(detector.rules)},
    )
    db.commit()
    return detector.status()


@router.get("/signature-rules")
def rules(_: Admin) -> dict[str, Any]:
    d = pipeline.signature_detector()
    return {"version": d.ruleset.version, "rules": [r.model_dump() for r in d.ruleset.rules]}
