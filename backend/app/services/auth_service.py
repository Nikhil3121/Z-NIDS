"""Authentication business logic.

Login: argon2id verification, per-account failed-login counter with timed
lockout, uniform error messages (no user enumeration).

Refresh tokens: opaque, hashed at rest, rotated on every use. Presenting an
already-rotated token is treated as theft — the whole token family is revoked.
"""

from __future__ import annotations

import logging
import uuid
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta

from sqlalchemy import select, update
from sqlalchemy.orm import Session

from app.core.config import get_settings
from app.core.exceptions import AuthenticationError, NotFoundError, ValidationFailedError
from app.core.security import (
    create_access_token,
    generate_opaque_token,
    hash_password,
    hash_token,
    needs_rehash,
    validate_password_strength,
    verify_password,
)
from app.integrations.notifications.email import send_email
from app.models.enums import AuditResult, TokenPurpose
from app.models.user import AuthToken, RefreshToken, User
from app.services import audit_service
from app.services.audit_service import RequestMeta

logger = logging.getLogger(__name__)

GENERIC_LOGIN_ERROR = "Invalid email or password"


@dataclass
class IssuedTokens:
    access_token: str
    expires_in: int
    refresh_token: str
    refresh_expires_at: datetime


def _now() -> datetime:
    return datetime.now(UTC)


def normalize_email(email: str) -> str:
    return email.strip().lower()


def _issue_refresh(db: Session, user: User, family_id: str, meta: RequestMeta) -> tuple[RefreshToken, str]:
    settings = get_settings()
    raw = generate_opaque_token(48)
    token = RefreshToken(
        user_id=user.id,
        family_id=family_id,
        token_hash=hash_token(raw),
        expires_at=_now() + timedelta(days=settings.refresh_token_ttl_days),
        created_ip=meta.ip,
        user_agent=(meta.user_agent or "")[:255] or None,
    )
    db.add(token)
    db.flush()
    return token, raw


def _issue_tokens(db: Session, user: User, family_id: str, meta: RequestMeta) -> IssuedTokens:
    refresh, raw_refresh = _issue_refresh(db, user, family_id, meta)
    access, expires_in = create_access_token(user.id, user.token_version)
    return IssuedTokens(access, expires_in, raw_refresh, refresh.expires_at)


def login(db: Session, email: str, password: str, meta: RequestMeta) -> tuple[User, IssuedTokens]:
    settings = get_settings()
    email = normalize_email(email)
    user = db.scalar(select(User).where(User.email == email).with_for_update(key_share=True))

    if user is not None and user.locked_until and user.locked_until > _now():
        # Still verify to keep timing uniform, but never succeed while locked.
        verify_password(password, user.password_hash)
        audit_service.record_independent(
            "LOGIN_FAILED", actor=user, result=AuditResult.DENIED, meta=meta, details={"reason": "locked"}
        )
        raise AuthenticationError("Account temporarily locked. Try again later.", code="ACCOUNT_LOCKED")

    valid = verify_password(password, user.password_hash if user else None)
    if user is None or not valid or not user.is_active:
        reason = "unknown_user" if user is None else ("inactive" if valid else "bad_password")
        if user is not None and not valid:
            user.failed_login_count += 1
            if user.failed_login_count >= settings.max_failed_logins:
                user.locked_until = _now() + timedelta(minutes=settings.lockout_minutes)
                reason = "bad_password_locked"
            db.commit()
        audit_service.record_independent(
            "LOGIN_FAILED",
            actor=user,
            actor_label=email if user is None else None,
            result=AuditResult.FAILURE,
            meta=meta,
            details={"reason": reason},
        )
        raise AuthenticationError(GENERIC_LOGIN_ERROR, code="INVALID_CREDENTIALS")

    if user.password_hash and needs_rehash(user.password_hash):
        user.password_hash = hash_password(password)
    user.failed_login_count = 0
    user.locked_until = None
    user.last_login = _now()
    tokens = _issue_tokens(db, user, uuid.uuid4().hex, meta)
    audit_service.record(db, "LOGIN", actor=user, resource_type="user", resource_id=user.id, meta=meta)
    db.commit()
    return user, tokens


def refresh(db: Session, raw_token: str, meta: RequestMeta) -> tuple[User, IssuedTokens]:
    token = db.scalar(select(RefreshToken).where(RefreshToken.token_hash == hash_token(raw_token)).with_for_update(key_share=True))
    if token is None:
        raise AuthenticationError("Invalid refresh token", code="REFRESH_INVALID")

    if token.revoked_at is not None:
        # A rotated/revoked token came back: assume it was stolen. Kill the family.
        revoke_family(db, token.family_id)
        audit_service.record(
            db,
            "TOKEN_REUSE_DETECTED",
            actor_label=f"user:{token.user_id}",
            resource_type="user",
            resource_id=token.user_id,
            result=AuditResult.DENIED,
            meta=meta,
        )
        db.commit()
        raise AuthenticationError("Refresh token reuse detected; session revoked", code="REFRESH_REUSED")

    if token.expires_at <= _now():
        raise AuthenticationError("Refresh token expired", code="REFRESH_EXPIRED")

    user = db.get(User, token.user_id)
    if user is None or not user.is_active:
        revoke_family(db, token.family_id)
        db.commit()
        raise AuthenticationError("Invalid refresh token", code="REFRESH_INVALID")

    tokens = _issue_tokens(db, user, token.family_id, meta)
    new_token = db.scalar(select(RefreshToken).where(RefreshToken.token_hash == hash_token(tokens.refresh_token)))
    token.revoked_at = _now()
    token.replaced_by_id = new_token.id if new_token else None
    db.commit()
    return user, tokens


def revoke_family(db: Session, family_id: str) -> None:
    db.execute(
        update(RefreshToken)
        .where(RefreshToken.family_id == family_id, RefreshToken.revoked_at.is_(None))
        .values(revoked_at=_now())
    )


def logout(db: Session, raw_token: str | None, user: User | None, meta: RequestMeta) -> None:
    if raw_token:
        token = db.scalar(select(RefreshToken).where(RefreshToken.token_hash == hash_token(raw_token)))
        if token is not None:
            revoke_family(db, token.family_id)
            if user is None:
                user = db.get(User, token.user_id)
    audit_service.record(
        db, "LOGOUT", actor=user, resource_type="user", resource_id=user.id if user else None, meta=meta
    )
    db.commit()


def logout_all(db: Session, user: User, meta: RequestMeta) -> None:
    """Revoke every session: bump token_version (kills JWTs) and all refresh tokens."""
    user.token_version += 1
    db.execute(
        update(RefreshToken)
        .where(RefreshToken.user_id == user.id, RefreshToken.revoked_at.is_(None))
        .values(revoked_at=_now())
    )
    audit_service.record(db, "LOGOUT_ALL", actor=user, resource_type="user", resource_id=user.id, meta=meta)
    db.commit()


# --- one-time tokens ---------------------------------------------------------


def create_one_time_token(db: Session, user: User, purpose: TokenPurpose) -> str:
    settings = get_settings()
    ttl = (
        timedelta(hours=settings.activation_token_ttl_hours)
        if purpose == TokenPurpose.ACTIVATION
        else timedelta(minutes=settings.password_reset_ttl_minutes)
    )
    # Invalidate earlier unused tokens of the same purpose.
    db.execute(
        update(AuthToken)
        .where(AuthToken.user_id == user.id, AuthToken.purpose == purpose, AuthToken.used_at.is_(None))
        .values(used_at=_now())
    )
    raw = generate_opaque_token(32)
    db.add(AuthToken(user_id=user.id, purpose=purpose, token_hash=hash_token(raw), expires_at=_now() + ttl))
    db.flush()
    return raw


def _consume_token(db: Session, raw: str, purpose: TokenPurpose) -> User:
    token = db.scalar(
        select(AuthToken).where(AuthToken.token_hash == hash_token(raw), AuthToken.purpose == purpose).with_for_update(key_share=True)
    )
    if token is None or token.used_at is not None or token.expires_at <= _now():
        raise ValidationFailedError("Token is invalid or has expired", code="TOKEN_INVALID")
    token.used_at = _now()
    user = db.get(User, token.user_id)
    if user is None:
        raise NotFoundError("User not found")
    return user


def send_activation_email(user: User, raw_token: str) -> None:
    settings = get_settings()
    link = f"{settings.frontend_base_url}/activate?token={raw_token}"
    send_email(
        user.email,
        "Activate your Z-NIDS account",
        f"Hello {user.name},\n\nAn administrator created a Z-NIDS account for you.\n"
        f"Set your password within {settings.activation_token_ttl_hours} hours:\n\n{link}\n\n"
        "If you did not expect this, ignore this email.",
    )


def activate(db: Session, raw_token: str, password: str, meta: RequestMeta) -> User:
    user = _consume_token(db, raw_token, TokenPurpose.ACTIVATION)
    validate_password_strength(password, email=user.email)
    user.password_hash = hash_password(password)
    user.password_changed_at = _now()
    user.is_active = True
    user.email_verified_at = _now()
    audit_service.record(db, "ACCOUNT_ACTIVATED", actor=user, resource_type="user", resource_id=user.id, meta=meta)
    db.commit()
    return user


def request_password_reset(db: Session, email: str, meta: RequestMeta) -> None:
    """Always succeeds from the caller's view; only active users get an email."""
    user = db.scalar(select(User).where(User.email == normalize_email(email)))
    if user is None or not user.is_active:
        audit_service.record(
            db,
            "PASSWORD_RESET_REQUESTED",
            actor_label=normalize_email(email),
            result=AuditResult.FAILURE,
            meta=meta,
            details={"reason": "no_active_user"},
        )
        db.commit()
        return
    raw = create_one_time_token(db, user, TokenPurpose.PASSWORD_RESET)
    audit_service.record(
        db, "PASSWORD_RESET_REQUESTED", actor=user, resource_type="user", resource_id=user.id, meta=meta
    )
    db.commit()
    settings = get_settings()
    try:
        send_email(
            user.email,
            "Z-NIDS password reset",
            f"A password reset was requested for your account.\n\n"
            f"{settings.frontend_base_url}/reset-password?token={raw}\n\n"
            f"The link expires in {settings.password_reset_ttl_minutes} minutes. "
            "If you did not request this, ignore this email.",
        )
    except Exception:
        logger.exception("password reset email failed")


def confirm_password_reset(db: Session, raw_token: str, new_password: str, meta: RequestMeta) -> None:
    user = _consume_token(db, raw_token, TokenPurpose.PASSWORD_RESET)
    validate_password_strength(new_password, email=user.email)
    _set_password(db, user, new_password)
    audit_service.record(db, "PASSWORD_RESET", actor=user, resource_type="user", resource_id=user.id, meta=meta)
    db.commit()


def change_password(db: Session, user: User, current: str, new: str, meta: RequestMeta) -> None:
    if not verify_password(current, user.password_hash):
        audit_service.record_independent("PASSWORD_CHANGE_FAILED", actor=user, meta=meta)
        raise AuthenticationError("Current password is incorrect", code="INVALID_CREDENTIALS")
    validate_password_strength(new, email=user.email)
    _set_password(db, user, new)
    audit_service.record(db, "PASSWORD_CHANGED", actor=user, resource_type="user", resource_id=user.id, meta=meta)
    db.commit()


def _set_password(db: Session, user: User, password: str) -> None:
    user.password_hash = hash_password(password)
    user.password_changed_at = _now()
    user.failed_login_count = 0
    user.locked_until = None
    # A password change ends every existing session.
    user.token_version += 1
    db.execute(
        update(RefreshToken)
        .where(RefreshToken.user_id == user.id, RefreshToken.revoked_at.is_(None))
        .values(revoked_at=_now())
    )
