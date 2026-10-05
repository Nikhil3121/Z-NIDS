"""Authentication request/response schemas."""

from __future__ import annotations

from datetime import datetime

from pydantic import Field

from app.schemas.common import Email, Schema, StrictInput


class LoginRequest(StrictInput):
    email: Email
    password: str = Field(min_length=1, max_length=256)


class RoleOut(Schema):
    id: int
    name: str


class UserOut(Schema):
    id: int
    email: str
    name: str
    role: RoleOut
    is_active: bool
    last_login: datetime | None
    created_at: datetime


class MeOut(UserOut):
    permissions: list[str]


class TokenResponse(Schema):
    access_token: str
    token_type: str = "bearer"  # noqa: S105 - OAuth token type name
    expires_in: int
    user: MeOut


class ActivateRequest(StrictInput):
    token: str = Field(min_length=16, max_length=128)
    password: str = Field(min_length=1, max_length=256)


class PasswordResetRequest(StrictInput):
    email: Email


class PasswordResetConfirm(StrictInput):
    token: str = Field(min_length=16, max_length=128)
    new_password: str = Field(min_length=1, max_length=256)


class ChangePasswordRequest(StrictInput):
    current_password: str = Field(min_length=1, max_length=256)
    new_password: str = Field(min_length=1, max_length=256)
