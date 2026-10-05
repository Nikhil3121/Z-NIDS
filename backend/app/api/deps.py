"""Shared FastAPI dependencies: DB session, authentication, authorisation."""

from __future__ import annotations

from collections.abc import Callable
from datetime import UTC, datetime
from typing import Annotated

from fastapi import Depends, Header, Request
from fastapi.security import HTTPAuthorizationCredentials, HTTPBearer
from sqlalchemy import select
from sqlalchemy.orm import Session

from app.core.config import get_settings
from app.core.exceptions import AuthenticationError, PermissionDeniedError
from app.core.rate_limit import client_ip, rate_limiter
from app.core.security import decode_access_token, hash_token
from app.db.session import get_db
from app.models.asset import Sensor
from app.models.enums import AuditResult, Permission
from app.models.user import User
from app.services import audit_service
from app.services.audit_service import RequestMeta

DbSession = Annotated[Session, Depends(get_db)]

_bearer = HTTPBearer(auto_error=False)


def request_meta(request: Request) -> RequestMeta:
    return RequestMeta(ip=client_ip(request), user_agent=request.headers.get("user-agent"))


Meta = Annotated[RequestMeta, Depends(request_meta)]


def authenticate_token(db: Session, token: str) -> User:
    """Resolve an access token to an active user (shared by HTTP and WebSocket auth)."""
    claims = decode_access_token(token)
    user = db.get(User, claims.user_id)
    if user is None or not user.is_active:
        raise AuthenticationError("Invalid access token", code="TOKEN_INVALID")
    if user.token_version != claims.token_version:
        raise AuthenticationError("Access token revoked", code="TOKEN_REVOKED")
    if user.locked_until and user.locked_until > datetime.now(UTC):
        raise AuthenticationError("Account locked", code="ACCOUNT_LOCKED")
    return user


def get_current_user(
    request: Request,
    db: DbSession,
    credentials: Annotated[HTTPAuthorizationCredentials | None, Depends(_bearer)],
) -> User:
    if credentials is None or credentials.scheme.lower() != "bearer":
        raise AuthenticationError("Authentication required", code="AUTHENTICATION_REQUIRED")
    user = authenticate_token(db, credentials.credentials)
    request.state.user = user
    settings = get_settings()
    rate_limiter.hit("api", f"user:{user.id}", settings.rate_limit_api_per_minute)
    return user


CurrentUser = Annotated[User, Depends(get_current_user)]


def require(*permissions: Permission) -> Callable[..., User]:
    """Dependency factory: the current user must hold *all* listed permissions.

    Denials are written to the audit log (independent transaction) because
    repeated denials are a privilege-escalation signal.
    """

    def _dependency(request: Request, user: CurrentUser) -> User:
        missing = [p.value for p in permissions if not user.has_permission(p.value)]
        if missing:
            audit_service.record_independent(
                "AUTHORIZATION_DENIED",
                actor=user,
                resource_type="endpoint",
                resource_id=f"{request.method} {request.url.path}",
                result=AuditResult.DENIED,
                meta=request_meta(request),
                details={"missing": missing},
            )
            raise PermissionDeniedError("You do not have permission to perform this action")
        return user

    return _dependency


def get_sensor(
    request: Request,
    db: DbSession,
    x_sensor_key: Annotated[str | None, Header(alias="X-Sensor-Key")] = None,
) -> Sensor:
    """Authenticate a telemetry sensor by API key (stored hashed)."""
    if not x_sensor_key:
        raise AuthenticationError("Sensor key required", code="SENSOR_KEY_REQUIRED")
    sensor = db.scalar(select(Sensor).where(Sensor.api_key_hash == hash_token(x_sensor_key)))
    if sensor is None or not sensor.is_active:
        audit_service.record_independent(
            "SENSOR_AUTH_FAILED",
            actor_label="sensor",
            result=AuditResult.DENIED,
            meta=request_meta(request),
            details={"key_prefix": x_sensor_key[:8]},
        )
        raise AuthenticationError("Invalid sensor key", code="SENSOR_KEY_INVALID")
    settings = get_settings()
    rate_limiter.hit("ingest", f"sensor:{sensor.id}", settings.rate_limit_ingest_per_minute)
    return sensor


CurrentSensor = Annotated[Sensor, Depends(get_sensor)]
