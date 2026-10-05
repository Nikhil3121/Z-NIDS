"""/api/v1/auth — login, token refresh/rotation, logout, activation, password reset.

The access token is returned in the body and kept in memory by the SPA. The
refresh token lives only in an HttpOnly, SameSite=Strict cookie scoped to this
router's path. Cookie-authenticated endpoints additionally require the custom
`X-ZNIDS-CSRF` header, which a cross-site form or image cannot send and a
cross-origin script cannot send without passing the CORS allow-list.
"""

from __future__ import annotations

from typing import Annotated

from fastapi import APIRouter, Cookie, Depends, Header, Response, status

from app.api.deps import CurrentUser, DbSession, Meta
from app.core.config import get_settings
from app.core.exceptions import AuthenticationError, PermissionDeniedError
from app.core.rate_limit import limit, rate_limiter
from app.models.user import User
from app.schemas.auth import (
    ActivateRequest,
    ChangePasswordRequest,
    LoginRequest,
    MeOut,
    PasswordResetConfirm,
    PasswordResetRequest,
    TokenResponse,
)
from app.schemas.common import Message
from app.services import auth_service

router = APIRouter(prefix="/auth", tags=["auth"])

REFRESH_COOKIE = "znids_refresh"
CSRF_HEADER = "X-ZNIDS-CSRF"


def _cookie_path() -> str:
    return f"{get_settings().api_prefix}/auth"


def _set_refresh_cookie(response: Response, tokens: auth_service.IssuedTokens) -> None:
    settings = get_settings()
    response.set_cookie(
        REFRESH_COOKIE,
        tokens.refresh_token,
        max_age=settings.refresh_token_ttl_days * 86400,
        httponly=True,
        secure=settings.secure_cookies,
        samesite="strict",
        path=_cookie_path(),
    )


def _clear_refresh_cookie(response: Response) -> None:
    settings = get_settings()
    response.delete_cookie(
        REFRESH_COOKIE, path=_cookie_path(), httponly=True, secure=settings.secure_cookies, samesite="strict"
    )


def _require_csrf(x_znids_csrf: Annotated[str | None, Header(alias=CSRF_HEADER)] = None) -> None:
    if x_znids_csrf != "1":
        raise PermissionDeniedError("Missing CSRF header", code="CSRF_REQUIRED")


def me_out(user: User) -> MeOut:
    return MeOut.model_validate(
        {
            "id": user.id,
            "email": user.email,
            "name": user.name,
            "role": user.role,
            "is_active": user.is_active,
            "last_login": user.last_login,
            "created_at": user.created_at,
            "permissions": sorted(user.role.permission_codes),
        }
    )


@router.post(
    "/login",
    response_model=TokenResponse,
    dependencies=[Depends(limit("login", "rate_limit_login_per_minute", fail_closed=True))],
)
def login(body: LoginRequest, response: Response, db: DbSession, meta: Meta) -> TokenResponse:
    # Second limiter keyed on the account defeats distributed guessing against one user.
    rate_limiter.hit(
        "login-account",
        auth_service.normalize_email(body.email),
        get_settings().rate_limit_login_per_minute,
        fail_closed=True,
    )
    user, tokens = auth_service.login(db, body.email, body.password, meta)
    _set_refresh_cookie(response, tokens)
    return TokenResponse(access_token=tokens.access_token, expires_in=tokens.expires_in, user=me_out(user))


@router.post(
    "/refresh",
    response_model=TokenResponse,
    dependencies=[Depends(_require_csrf), Depends(limit("refresh", "rate_limit_login_per_minute"))],
)
def refresh(
    response: Response,
    db: DbSession,
    meta: Meta,
    znids_refresh: Annotated[str | None, Cookie(alias=REFRESH_COOKIE)] = None,
) -> TokenResponse:
    if not znids_refresh:
        raise AuthenticationError("No refresh token", code="REFRESH_MISSING")
    user, tokens = auth_service.refresh(db, znids_refresh, meta)
    _set_refresh_cookie(response, tokens)
    return TokenResponse(access_token=tokens.access_token, expires_in=tokens.expires_in, user=me_out(user))


@router.post("/logout", response_model=Message, dependencies=[Depends(_require_csrf)])
def logout(
    response: Response,
    db: DbSession,
    meta: Meta,
    znids_refresh: Annotated[str | None, Cookie(alias=REFRESH_COOKIE)] = None,
) -> Message:
    auth_service.logout(db, znids_refresh, None, meta)
    _clear_refresh_cookie(response)
    return Message(message="Logged out")


@router.post("/logout-all", response_model=Message)
def logout_all(response: Response, user: CurrentUser, db: DbSession, meta: Meta) -> Message:
    auth_service.logout_all(db, user, meta)
    _clear_refresh_cookie(response)
    return Message(message="All sessions revoked")


@router.get("/me", response_model=MeOut)
def me(user: CurrentUser) -> MeOut:
    return me_out(user)


@router.post(
    "/activate",
    response_model=Message,
    dependencies=[Depends(limit("activate", "rate_limit_login_per_minute", fail_closed=True))],
)
def activate(body: ActivateRequest, db: DbSession, meta: Meta) -> Message:
    auth_service.activate(db, body.token, body.password, meta)
    return Message(message="Account activated. You can now sign in.")


@router.post(
    "/password-reset/request",
    response_model=Message,
    status_code=status.HTTP_202_ACCEPTED,
    dependencies=[Depends(limit("reset", "rate_limit_login_per_minute", fail_closed=True))],
)
def request_password_reset(body: PasswordResetRequest, db: DbSession, meta: Meta) -> Message:
    auth_service.request_password_reset(db, body.email, meta)
    return Message(message="If an active account exists for that address, a reset link has been sent.")


@router.post(
    "/password-reset/confirm",
    response_model=Message,
    dependencies=[Depends(limit("reset", "rate_limit_login_per_minute", fail_closed=True))],
)
def confirm_password_reset(body: PasswordResetConfirm, db: DbSession, meta: Meta) -> Message:
    auth_service.confirm_password_reset(db, body.token, body.new_password, meta)
    return Message(message="Password updated. Sign in with your new password.")


@router.post("/change-password", response_model=Message)
def change_password(
    body: ChangePasswordRequest, response: Response, user: CurrentUser, db: DbSession, meta: Meta
) -> Message:
    auth_service.change_password(db, user, body.current_password, body.new_password, meta)
    _clear_refresh_cookie(response)
    return Message(message="Password changed. Please sign in again.")
