"""/api/v1/users — user administration (ADMIN) and notification preferences (self)."""

from __future__ import annotations

import logging
from typing import Annotated

from fastapi import APIRouter, Depends, Query
from pydantic import Field
from sqlalchemy import select, update

from app.api.deps import CurrentUser, DbSession, Meta, require
from app.api.query import apply_sort, page_params, paginate
from app.core.exceptions import ConflictError, NotFoundError, PermissionDeniedError
from app.models.enums import NotificationEvent, Permission, RoleName, TokenPurpose
from app.models.user import NotificationPreference, RefreshToken, Role, User
from app.schemas.auth import RoleOut, UserOut
from app.schemas.common import Email, Message, Page, PageParams, Schema, StrictInput
from app.services import audit_service, auth_service
from app.services.notification_service import DEFAULT_EMAIL, DEFAULT_IN_APP

router = APIRouter(prefix="/users", tags=["users"])
Admin = Annotated[User, Depends(require(Permission.MANAGE_USERS))]
logger = logging.getLogger(__name__)


class UserCreate(StrictInput):
    email: Email
    name: str = Field(min_length=1, max_length=120)
    role: RoleName


class UserPatch(StrictInput):
    name: str | None = Field(default=None, min_length=1, max_length=120)
    role: RoleName | None = None
    is_active: bool | None = None


class UserCreated(UserOut):
    activation_email_sent: bool


class PreferenceOut(Schema):
    event_type: NotificationEvent
    in_app: bool
    email: bool


class PreferenceIn(StrictInput):
    event_type: NotificationEvent
    in_app: bool
    email: bool


def _role(db, name: RoleName) -> Role:  # type: ignore[no-untyped-def]
    role = db.scalar(select(Role).where(Role.name == name.value))
    if role is None:
        raise NotFoundError("Role not found")
    return role


@router.get("/roles", response_model=list[RoleOut])
def roles(db: DbSession, _: Admin) -> list[RoleOut]:
    return [RoleOut.model_validate(r) for r in db.scalars(select(Role).order_by(Role.id)).all()]


@router.get("/directory")
def directory(db: DbSession, user: CurrentUser) -> list[dict]:
    """Minimal active-user list (id, name) for assignment pickers."""
    if not user.has_permission(Permission.MANAGE_INCIDENTS.value) and not user.has_permission(
        Permission.MANAGE_ALERTS.value
    ):
        raise PermissionDeniedError("Not allowed")
    rows = db.scalars(select(User).where(User.is_active.is_(True)).order_by(User.name)).all()
    return [{"id": u.id, "name": u.name, "role": u.role.name} for u in rows]


@router.get("", response_model=Page[UserOut])
def list_users(
    db: DbSession,
    _: Admin,
    params: Annotated[PageParams, Depends(page_params)],
    q: str | None = Query(None, max_length=100),
    sort: str | None = Query(None, max_length=32),
) -> Page[UserOut]:
    stmt = select(User)
    if q:
        needle = q.replace("\\", "\\\\").replace("%", "\\%").replace("_", "\\_")
        stmt = stmt.where(User.email.ilike(f"%{needle}%", escape="\\") | User.name.ilike(f"%{needle}%", escape="\\"))
    stmt = apply_sort(
        stmt,
        sort,
        {"email": User.email, "created_at": User.created_at, "last_login": User.last_login},
        User.created_at.desc(),
    )
    return paginate(db, stmt, params, UserOut.model_validate)


@router.post("", response_model=UserCreated, status_code=201)
def create_user(body: UserCreate, db: DbSession, admin: Admin, meta: Meta) -> UserCreated:
    email = auth_service.normalize_email(body.email)
    if db.scalar(select(User).where(User.email == email)) is not None:
        raise ConflictError("A user with this email already exists")
    user = User(email=email, name=body.name.strip(), role_id=_role(db, body.role).id, is_active=False)
    db.add(user)
    db.flush()
    raw = auth_service.create_one_time_token(db, user, TokenPurpose.ACTIVATION)
    audit_service.record(
        db,
        "USER_CREATED",
        actor=admin,
        resource_type="user",
        resource_id=user.id,
        meta=meta,
        details={"email": email, "role": body.role.value},
    )
    db.commit()
    db.refresh(user)
    sent = True
    try:
        auth_service.send_activation_email(user, raw)
    except Exception:
        sent = False
        logger.exception("activation email failed", extra={"user_id": user.id})
    return UserCreated(**UserOut.model_validate(user).model_dump(), activation_email_sent=sent)


@router.post("/{user_id}/resend-activation", response_model=Message)
def resend_activation(user_id: int, db: DbSession, admin: Admin, meta: Meta) -> Message:
    user = db.get(User, user_id)
    if user is None:
        raise NotFoundError("User not found")
    if user.is_active:
        raise ConflictError("User is already active")
    raw = auth_service.create_one_time_token(db, user, TokenPurpose.ACTIVATION)
    audit_service.record(db, "ACTIVATION_RESENT", actor=admin, resource_type="user", resource_id=user.id, meta=meta)
    db.commit()
    auth_service.send_activation_email(user, raw)
    return Message(message="Activation email sent")


@router.patch("/{user_id}", response_model=UserOut)
def update_user(user_id: int, body: UserPatch, db: DbSession, admin: Admin, meta: Meta) -> UserOut:
    user = db.get(User, user_id)
    if user is None:
        raise NotFoundError("User not found")
    if user.id == admin.id and (body.role not in (None, RoleName.ADMIN) or body.is_active is False):
        raise PermissionDeniedError("You cannot demote or deactivate your own account")
    revoke = False
    if body.name is not None:
        user.name = body.name.strip()
    if body.role is not None and body.role.value != user.role.name:
        old = user.role.name
        user.role_id = _role(db, body.role).id
        revoke = True
        audit_service.record(
            db,
            "ROLE_CHANGED",
            actor=admin,
            resource_type="user",
            resource_id=user.id,
            meta=meta,
            details={"from": old, "to": body.role.value},
        )
    if body.is_active is not None and body.is_active != user.is_active:
        if body.is_active and user.password_hash is None:
            raise ConflictError("User has not set a password yet; resend the activation email instead")
        user.is_active = body.is_active
        revoke = revoke or not body.is_active
        audit_service.record(
            db,
            "USER_ACTIVATED" if body.is_active else "USER_DEACTIVATED",
            actor=admin,
            resource_type="user",
            resource_id=user.id,
            meta=meta,
        )
    if revoke:
        # Permission changes take effect immediately: kill existing sessions.
        user.token_version += 1
        db.execute(
            update(RefreshToken)
            .where(RefreshToken.user_id == user.id, RefreshToken.revoked_at.is_(None))
            .values(revoked_at=auth_service._now())
        )
    db.commit()
    db.refresh(user)
    return UserOut.model_validate(user)


@router.get("/me/notification-preferences", response_model=list[PreferenceOut])
def my_preferences(db: DbSession, user: CurrentUser) -> list[PreferenceOut]:
    saved = {
        p.event_type: p
        for p in db.scalars(select(NotificationPreference).where(NotificationPreference.user_id == user.id)).all()
    }
    out = []
    for event in NotificationEvent:
        p = saved.get(event)
        out.append(
            PreferenceOut(
                event_type=event,
                in_app=p.in_app if p else DEFAULT_IN_APP,
                email=p.email if p else event in DEFAULT_EMAIL,
            )
        )
    return out


@router.put("/me/notification-preferences", response_model=list[PreferenceOut])
def set_preferences(body: list[PreferenceIn], db: DbSession, user: CurrentUser, meta: Meta) -> list[PreferenceOut]:
    for pref in body:
        row = db.scalar(
            select(NotificationPreference).where(
                NotificationPreference.user_id == user.id, NotificationPreference.event_type == pref.event_type
            )
        )
        if row is None:
            row = NotificationPreference(user_id=user.id, event_type=pref.event_type)
            db.add(row)
        row.in_app, row.email = pref.in_app, pref.email
    audit_service.record(
        db,
        "NOTIFICATION_PREFERENCES_CHANGED",
        actor=user,
        resource_type="user",
        resource_id=user.id,
        meta=meta,
        details={"count": len(body)},
    )
    db.commit()
    return my_preferences(db, user)
