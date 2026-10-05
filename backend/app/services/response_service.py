"""Controlled response engine.

Modes (RESPONSE_MODE):
  DETECTION_ONLY   default. No action is proposed or executed.
  MANUAL_APPROVAL  the system and analysts may *propose*; a different user with
                   response:approve must approve before anything executes.
  AUTOMATIC        system proposals for eligible actions execute immediately
                   (explicit opt-in; refused with the lab adapter in production).

Adapters perform the action. The built-in `lab` adapter only changes state
inside Z-NIDS (a lab blocklist, and lab-flagged assets); it never touches a
real network device. Guardrails refuse blocking internal addresses and
quarantining non-lab assets. Every transition is audited.
"""

from __future__ import annotations

import ipaddress
import logging
from abc import ABC, abstractmethod
from datetime import UTC, datetime, timedelta
from typing import Any

from sqlalchemy import select
from sqlalchemy.orm import Session

from app.core.config import ResponseMode, get_settings
from app.core.exceptions import (
    ConflictError,
    InvalidStateTransitionError,
    NotFoundError,
    PermissionDeniedError,
    ValidationFailedError,
)
from app.models.asset import Asset
from app.models.enums import ActivityType, AssetStatus, Permission, ResponseActionType, ResponseStatus
from app.models.incident import IncidentActivity
from app.models.response import LabBlocklistEntry, ResponseAction
from app.models.user import User
from app.services import audit_service
from app.services.audit_service import RequestMeta
from app.services.ingest_service import is_internal

logger = logging.getLogger(__name__)


class ResponseAdapter(ABC):
    name: str

    @abstractmethod
    def execute(self, db: Session, action: ResponseAction) -> dict[str, Any]: ...

    @abstractmethod
    def revert(self, db: Session, action: ResponseAction) -> dict[str, Any]: ...


class LabAdapter(ResponseAdapter):
    """Sandbox enforcement: state changes inside Z-NIDS only."""

    name = "lab"

    def execute(self, db: Session, action: ResponseAction) -> dict[str, Any]:
        if action.action_type == ResponseActionType.BLOCK_IP:
            existing = db.scalar(
                select(LabBlocklistEntry).where(
                    LabBlocklistEntry.ip_address == action.target, LabBlocklistEntry.active.is_(True)
                )
            )
            if existing:
                return {"blocklist_entry_id": existing.id, "note": "already blocked in lab firewall"}
            entry = LabBlocklistEntry(
                ip_address=action.target,
                reason=action.reason,
                response_action_id=action.id,
                expires_at=datetime.now(UTC) + timedelta(hours=24),
            )
            db.add(entry)
            db.flush()
            return {
                "blocklist_entry_id": entry.id,
                "enforcement": "lab blocklist (no real device changed)",
                "expires_at": entry.expires_at.isoformat() if entry.expires_at else None,
            }
        if action.action_type in (ResponseActionType.QUARANTINE_ASSET, ResponseActionType.DISABLE_LAB_ASSET):
            asset = db.scalar(select(Asset).where(Asset.ip_address == action.target))
            if asset is None or not asset.is_lab:
                raise ValidationFailedError("Only lab assets can be quarantined or disabled by the lab adapter")
            previous = asset.status.value
            asset.status = (
                AssetStatus.QUARANTINED
                if action.action_type == ResponseActionType.QUARANTINE_ASSET
                else AssetStatus.DISABLED
            )
            return {"asset_id": asset.id, "previous_status": previous, "new_status": asset.status.value}
        if action.action_type == ResponseActionType.NOTIFY_ANALYST:
            return {"note": "notification dispatched"}
        raise ValidationFailedError(f"Unsupported action {action.action_type.value}")

    def revert(self, db: Session, action: ResponseAction) -> dict[str, Any]:
        if action.action_type == ResponseActionType.BLOCK_IP:
            for entry in db.scalars(
                select(LabBlocklistEntry).where(
                    LabBlocklistEntry.ip_address == action.target, LabBlocklistEntry.active.is_(True)
                )
            ).all():
                entry.active = False
                entry.removed_at = datetime.now(UTC)
            return {"unblocked": action.target}
        if action.action_type in (ResponseActionType.QUARANTINE_ASSET, ResponseActionType.DISABLE_LAB_ASSET):
            asset = db.scalar(select(Asset).where(Asset.ip_address == action.target))
            if asset is not None and asset.is_lab:
                asset.status = AssetStatus(action.result.get("previous_status", AssetStatus.ACTIVE.value))
            return {"restored": action.target}
        return {}


class UnconfiguredAdapter(ResponseAdapter):
    """Placeholder for a production firewall/EDR integration that is not configured."""

    name = "none"

    def execute(self, db: Session, action: ResponseAction) -> dict[str, Any]:
        raise ValidationFailedError("No response adapter is configured (RESPONSE_ADAPTER)")

    def revert(self, db: Session, action: ResponseAction) -> dict[str, Any]:
        raise ValidationFailedError("No response adapter is configured (RESPONSE_ADAPTER)")


def adapter() -> ResponseAdapter:
    return LabAdapter() if get_settings().response_adapter == "lab" else UnconfiguredAdapter()


def _guard(db: Session, action_type: ResponseActionType, target: str) -> str:
    try:
        ip = str(ipaddress.ip_address(target))
    except ValueError as exc:
        raise ValidationFailedError("Response target must be an IP address") from exc
    if action_type == ResponseActionType.BLOCK_IP and is_internal(ip):
        raise ValidationFailedError("Refusing to block an internal address; quarantine the asset instead")
    if action_type in (ResponseActionType.QUARANTINE_ASSET, ResponseActionType.DISABLE_LAB_ASSET):
        asset = db.scalar(select(Asset).where(Asset.ip_address == ip))
        if asset is None:
            raise ValidationFailedError("Target is not a known asset")
        if action_type == ResponseActionType.DISABLE_LAB_ASSET and not asset.is_lab:
            raise ValidationFailedError("Only lab assets can be disabled")
    return ip


def _incident_activity(db: Session, action: ResponseAction, user: User | None, message: str) -> None:
    if action.incident_id:
        db.add(
            IncidentActivity(
                incident_id=action.incident_id,
                actor_id=user.id if user else None,
                activity_type=ActivityType.RESPONSE,
                to_value=action.status.value,
                message=message,
            )
        )


def propose(
    db: Session,
    *,
    action_type: ResponseActionType,
    target: str,
    reason: str,
    incident_id: int | None,
    alert_id: int | None,
    requested_by: User | None,
    meta: RequestMeta | None = None,
) -> ResponseAction:
    settings = get_settings()
    if settings.response_mode == ResponseMode.DETECTION_ONLY:
        raise PermissionDeniedError("Response engine is in DETECTION_ONLY mode", code="RESPONSE_DISABLED")
    target = _guard(db, action_type, target)
    duplicate = db.scalar(
        select(ResponseAction).where(
            ResponseAction.action_type == action_type,
            ResponseAction.target == target,
            ResponseAction.status.in_([ResponseStatus.PROPOSED, ResponseStatus.APPROVED]),
        )
    )
    if duplicate is not None:
        raise ConflictError(f"An open {action_type.value} action for {target} already exists (#{duplicate.id})")
    action = ResponseAction(
        action_type=action_type,
        target=target,
        reason=reason.strip()[:2000],
        status=ResponseStatus.PROPOSED,
        mode=settings.response_mode.value,
        adapter=adapter().name,
        incident_id=incident_id,
        alert_id=alert_id,
        requested_by_id=requested_by.id if requested_by else None,
    )
    db.add(action)
    db.flush()
    audit_service.record(
        db,
        "RESPONSE_PROPOSED",
        actor=requested_by,
        actor_label=None if requested_by else "system",
        resource_type="response_action",
        resource_id=action.id,
        meta=meta,
        details={"type": action_type.value, "target": target, "incident_id": incident_id},
    )
    _incident_activity(db, action, requested_by, f"Response proposed: {action_type.value} {target}")
    if settings.response_mode == ResponseMode.AUTOMATIC and requested_by is None:
        _execute(db, action, None, meta, automatic=True)
    return action


def get_action(db: Session, action_id: int) -> ResponseAction:
    action = db.scalar(select(ResponseAction).where(ResponseAction.id == action_id).with_for_update(key_share=True))
    if action is None:
        raise NotFoundError("Response action not found")
    return action


def decide(
    db: Session, action_id: int, approve: bool, user: User, meta: RequestMeta, comment: str | None
) -> ResponseAction:
    if not user.has_permission(Permission.APPROVE_RESPONSE.value):
        raise PermissionDeniedError("Approving response actions requires response:approve")
    action = get_action(db, action_id)
    if action.status != ResponseStatus.PROPOSED:
        raise InvalidStateTransitionError(f"Action is {action.status.value}, not PROPOSED")
    if action.requested_by_id == user.id:
        raise PermissionDeniedError(
            "Four-eyes rule: you cannot approve your own response request", code="SELF_APPROVAL_FORBIDDEN"
        )
    action.decided_by_id = user.id
    action.decided_at = datetime.now(UTC)
    if not approve:
        action.status = ResponseStatus.REJECTED
        action.result = {**action.result, "comment": comment}
        audit_service.record(
            db,
            "RESPONSE_REJECTED",
            actor=user,
            resource_type="response_action",
            resource_id=action.id,
            meta=meta,
            details={"comment": comment},
        )
        _incident_activity(db, action, user, f"Response rejected: {action.action_type.value} {action.target}")
        return action
    action.status = ResponseStatus.APPROVED
    audit_service.record(
        db,
        "RESPONSE_APPROVED",
        actor=user,
        resource_type="response_action",
        resource_id=action.id,
        meta=meta,
        details={"comment": comment},
    )
    return _execute(db, action, user, meta)


def _execute(
    db: Session, action: ResponseAction, user: User | None, meta: RequestMeta | None, automatic: bool = False
) -> ResponseAction:
    try:
        with db.begin_nested():
            result = adapter().execute(db, action)
        action.status = ResponseStatus.EXECUTED
        action.executed_at = datetime.now(UTC)
        action.result = {**action.result, **result, "automatic": automatic}
        outcome = "SUCCESS"
    except (ValidationFailedError, ValueError) as exc:
        action.status = ResponseStatus.FAILED
        action.result = {**action.result, "error": str(exc)[:500]}
        outcome = "FAILURE"
        logger.warning("response action failed", extra={"action_id": action.id, "error": str(exc)})
    audit_service.record(
        db,
        "RESPONSE_EXECUTED",
        actor=user,
        actor_label=None if user else "system:automatic",
        resource_type="response_action",
        resource_id=action.id,
        meta=meta,
        result=audit_service.AuditResult.SUCCESS if outcome == "SUCCESS" else audit_service.AuditResult.FAILURE,
        details={"type": action.action_type.value, "target": action.target, "result": action.result},
    )
    _incident_activity(
        db, action, user, f"Response {action.status.value.lower()}: {action.action_type.value} {action.target}"
    )
    return action


def revert(db: Session, action_id: int, user: User, meta: RequestMeta) -> ResponseAction:
    if not user.has_permission(Permission.APPROVE_RESPONSE.value):
        raise PermissionDeniedError("Reverting response actions requires response:approve")
    action = get_action(db, action_id)
    if action.status != ResponseStatus.EXECUTED:
        raise InvalidStateTransitionError("Only executed actions can be reverted")
    result = adapter().revert(db, action)
    action.status = ResponseStatus.REVERTED
    action.result = {**action.result, "revert": result}
    audit_service.record(
        db,
        "RESPONSE_REVERTED",
        actor=user,
        resource_type="response_action",
        resource_id=action.id,
        meta=meta,
        details=result,
    )
    _incident_activity(db, action, user, f"Response reverted: {action.action_type.value} {action.target}")
    return action


def suggest_for_incident(db: Session, incident_id: int, src_ip: str | None, is_demo: bool) -> list[ResponseAction]:
    """System proposals for a new/escalated incident (never in DETECTION_ONLY)."""
    settings = get_settings()
    if settings.response_mode == ResponseMode.DETECTION_ONLY or not src_ip:
        return []
    action_type = ResponseActionType.QUARANTINE_ASSET if is_internal(src_ip) else ResponseActionType.BLOCK_IP
    if action_type == ResponseActionType.QUARANTINE_ASSET:
        asset = db.scalar(select(Asset).where(Asset.ip_address == src_ip))
        if asset is None or not asset.is_lab:
            return []  # the lab adapter could not act; don't propose what cannot run
    try:
        return [
            propose(
                db,
                action_type=action_type,
                target=src_ip,
                reason=f"Containment suggested for INC-{incident_id}",
                incident_id=incident_id,
                alert_id=None,
                requested_by=None,
            )
        ]
    except (ConflictError, ValidationFailedError, PermissionDeniedError) as exc:
        logger.info("no response proposal", extra={"incident_id": incident_id, "reason": str(exc)})
        return []
