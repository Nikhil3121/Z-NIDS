"""Password hashing, JWT access tokens and opaque token helpers."""

from __future__ import annotations

import hashlib
import hmac
import secrets
import uuid
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
from typing import Any

import jwt
from argon2 import PasswordHasher
from argon2.exceptions import InvalidHashError, VerificationError, VerifyMismatchError

from app.core.config import get_settings
from app.core.exceptions import AuthenticationError, ValidationFailedError

# Argon2id with library defaults (RFC 9106 "low memory" profile).
_hasher = PasswordHasher()

# Verified against when the user does not exist, so unknown-email and
# wrong-password logins take the same time (no user enumeration by timing).
_DUMMY_HASH = _hasher.hash(secrets.token_urlsafe(16))


def hash_password(password: str) -> str:
    return _hasher.hash(password)


def verify_password(password: str, password_hash: str | None) -> bool:
    try:
        return _hasher.verify(password_hash or _DUMMY_HASH, password) and password_hash is not None
    except (VerifyMismatchError, VerificationError, InvalidHashError):
        return False


def needs_rehash(password_hash: str) -> bool:
    return _hasher.check_needs_rehash(password_hash)


_COMMON_PASSWORDS = {
    "password1234",
    "passwordpassword",
    "123456789012",
    "qwertyuiopas",
    "administrator",
    "letmein12345",
    "welcome12345",
}


def validate_password_strength(password: str, *, email: str | None = None) -> None:
    """Length-first policy (NIST SP 800-63B): long passphrases beat composition rules."""
    settings = get_settings()
    problems: list[str] = []
    if len(password) < settings.password_min_length:
        problems.append(f"must be at least {settings.password_min_length} characters")
    if len(password) > 256:
        problems.append("must be at most 256 characters")
    if password.lower() in _COMMON_PASSWORDS or len(set(password)) < 5:
        problems.append("is too common or repetitive")
    if email and email.split("@")[0].lower() in password.lower():
        problems.append("must not contain your email name")
    if problems:
        raise ValidationFailedError("Password " + "; ".join(problems), code="WEAK_PASSWORD")


@dataclass(frozen=True)
class AccessTokenClaims:
    user_id: int
    token_version: int
    jti: str
    expires_at: datetime


def create_access_token(user_id: int, token_version: int, *, extra: dict[str, Any] | None = None) -> tuple[str, int]:
    settings = get_settings()
    now = datetime.now(UTC)
    ttl = timedelta(minutes=settings.access_token_ttl_minutes)
    payload: dict[str, Any] = {
        "sub": str(user_id),
        "ver": token_version,
        "iat": now,
        "nbf": now,
        "exp": now + ttl,
        "iss": settings.jwt_issuer,
        "aud": settings.jwt_audience,
        "jti": uuid.uuid4().hex,
        "typ": "access",
    }
    if extra:
        payload.update(extra)
    token = jwt.encode(payload, settings.secret_key, algorithm=settings.jwt_algorithm)
    return token, int(ttl.total_seconds())


def decode_access_token(token: str) -> AccessTokenClaims:
    settings = get_settings()
    try:
        payload = jwt.decode(
            token,
            settings.secret_key,
            algorithms=[settings.jwt_algorithm],  # never trust the header's alg
            audience=settings.jwt_audience,
            issuer=settings.jwt_issuer,
            options={"require": ["exp", "iat", "sub", "jti", "iss", "aud"]},
        )
    except jwt.ExpiredSignatureError as exc:
        raise AuthenticationError("Access token expired", code="TOKEN_EXPIRED") from exc
    except jwt.PyJWTError as exc:
        raise AuthenticationError("Invalid access token", code="TOKEN_INVALID") from exc
    if payload.get("typ") != "access":
        raise AuthenticationError("Invalid access token", code="TOKEN_INVALID")
    try:
        user_id = int(payload["sub"])
        version = int(payload.get("ver", -1))
    except (TypeError, ValueError) as exc:
        raise AuthenticationError("Invalid access token", code="TOKEN_INVALID") from exc
    return AccessTokenClaims(
        user_id=user_id,
        token_version=version,
        jti=str(payload["jti"]),
        expires_at=datetime.fromtimestamp(payload["exp"], UTC),
    )


def generate_opaque_token(nbytes: int = 32) -> str:
    return secrets.token_urlsafe(nbytes)


def hash_token(token: str) -> str:
    """SHA-256 of a high-entropy opaque token (safe without salting: tokens are random)."""
    return hashlib.sha256(token.encode("utf-8")).hexdigest()


def constant_time_equals(a: str, b: str) -> bool:
    return hmac.compare_digest(a.encode(), b.encode())


def sign_payload(body: bytes, secret: str, timestamp: int) -> str:
    """HMAC-SHA256 signature over `timestamp.body` for outbound/inbound webhooks."""
    mac = hmac.new(secret.encode(), f"{timestamp}.".encode() + body, hashlib.sha256)
    return f"t={timestamp},v1={mac.hexdigest()}"


def verify_signature(body: bytes, secret: str, header: str, *, tolerance_seconds: int = 300) -> bool:
    try:
        parts = dict(item.split("=", 1) for item in header.split(","))
        timestamp = int(parts["t"])
        provided = parts["v1"]
    except (KeyError, ValueError):
        return False
    if abs(datetime.now(UTC).timestamp() - timestamp) > tolerance_seconds:
        return False
    expected = sign_payload(body, secret, timestamp).split("v1=", 1)[1]
    return hmac.compare_digest(expected, provided)
