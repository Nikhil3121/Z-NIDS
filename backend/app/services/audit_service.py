"""Audit trail writer.

Audit rows are written inside the caller's transaction for successful actions
(so the action and its audit commit or roll back together). Denied/failed
attempts are written in their own short transaction so they survive the
rollback of the request that triggered them.
"""

from __future__ import annotations

import logging
from dataclasses import dataclass
from typing import Any

from sqlalchemy.orm import Session

from app.core.logging import redact, request_id_var
from app.db.session import session_scope
from app.models.audit import AuditLog
from app.models.enums import AuditResult
from app.models.user import User

logger = logging.getLogger("znids.audit")


@dataclass(frozen=True)
class RequestMeta:
    ip: str | None = None
    user_agent: str | None = None


SYSTEM = "system"


def _build(
    action: str,
    *,
    actor: User | None,
    actor_label: str | None,
    resource_type: str | None,
    resource_id: object,
    result: AuditResult,
    meta: RequestMeta | None,
    details: dict[str, Any] | None,
) -> AuditLog:
    return AuditLog(
        actor_id=actor.id if actor else None,
        actor_label=actor.email if actor else (actor_label or SYSTEM),
        action=action,
        resource_type=resource_type,
        resource_id=None if resource_id is None else str(resource_id),
        result=result,
        ip_address=meta.ip if meta else None,
        user_agent=(meta.user_agent or "")[:255] if meta else None,
        request_id=request_id_var.get(),
        details=redact(details or {}),
    )


def record(
    db: Session,
    action: str,
    *,
    actor: User | None = None,
    actor_label: str | None = None,
    resource_type: str | None = None,
    resource_id: object = None,
    result: AuditResult = AuditResult.SUCCESS,
    meta: RequestMeta | None = None,
    details: dict[str, Any] | None = None,
) -> AuditLog:
    entry = _build(
        action,
        actor=actor,
        actor_label=actor_label,
        resource_type=resource_type,
        resource_id=resource_id,
        result=result,
        meta=meta,
        details=details,
    )
    db.add(entry)
    logger.info(
        "audit",
        extra={"action": action, "result": result.value, "resource": f"{resource_type}:{resource_id}"},
    )
    return entry


def record_independent(
    action: str,
    *,
    actor: User | None = None,
    actor_label: str | None = None,
    resource_type: str | None = None,
    resource_id: object = None,
    result: AuditResult = AuditResult.FAILURE,
    meta: RequestMeta | None = None,
    details: dict[str, Any] | None = None,
) -> None:
    """Commit an audit row in a separate transaction (for denials / failures)."""
    with session_scope() as db:
        db.add(
            _build(
                action,
                actor=actor,
                actor_label=actor_label,
                resource_type=resource_type,
                resource_id=resource_id,
                result=result,
                meta=meta,
                details=details,
            )
        )
    logger.warning("audit", extra={"action": action, "result": result.value})
