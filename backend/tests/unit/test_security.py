from __future__ import annotations

import time
from datetime import UTC, datetime, timedelta

import jwt
import pytest

from app.core.config import get_settings
from app.core.exceptions import AuthenticationError, ValidationFailedError
from app.core.logging import redact, redact_text
from app.core.security import (
    create_access_token,
    decode_access_token,
    hash_password,
    hash_token,
    sign_payload,
    validate_password_strength,
    verify_password,
    verify_signature,
)


def test_password_hash_roundtrip_and_salting() -> None:
    h1, h2 = hash_password("correct horse battery"), hash_password("correct horse battery")
    assert h1 != h2 and h1.startswith("$argon2id$")
    assert verify_password("correct horse battery", h1)
    assert not verify_password("wrong", h1)
    assert not verify_password("anything", None)
    assert not verify_password("anything", "not-a-hash")


def test_password_policy() -> None:
    validate_password_strength("a long enough passphrase", email="bob@example.com")
    with pytest.raises(ValidationFailedError):
        validate_password_strength("short")
    with pytest.raises(ValidationFailedError):
        validate_password_strength("aaaaaaaaaaaaaaaa")
    with pytest.raises(ValidationFailedError):
        validate_password_strength("alice-is-my-password", email="alice@example.com")


def test_access_token_roundtrip() -> None:
    token, ttl = create_access_token(42, 3)
    claims = decode_access_token(token)
    assert (claims.user_id, claims.token_version) == (42, 3)
    assert ttl == get_settings().access_token_ttl_minutes * 60


def test_expired_token_rejected() -> None:
    s = get_settings()
    now = datetime.now(UTC)
    token = jwt.encode({"sub": "1", "ver": 0, "iat": now - timedelta(hours=2), "exp": now - timedelta(hours=1),
                        "iss": s.jwt_issuer, "aud": s.jwt_audience, "jti": "x", "typ": "access"},
                       s.secret_key, algorithm="HS256")
    with pytest.raises(AuthenticationError) as exc:
        decode_access_token(token)
    assert exc.value.code == "TOKEN_EXPIRED"


@pytest.mark.parametrize("mutate", ["wrong_key", "alg_none", "wrong_aud", "not_access", "garbage"])
def test_forged_tokens_rejected(mutate: str) -> None:
    s = get_settings()
    now = datetime.now(UTC)
    claims = {"sub": "1", "ver": 0, "iat": now, "exp": now + timedelta(minutes=5), "iss": s.jwt_issuer,
              "aud": s.jwt_audience, "jti": "x", "typ": "access"}
    if mutate == "wrong_key":
        token = jwt.encode(claims, "another-secret-key-that-is-long-enough!!", algorithm="HS256")
    elif mutate == "alg_none":
        token = jwt.encode(claims, None, algorithm="none")
    elif mutate == "wrong_aud":
        token = jwt.encode({**claims, "aud": "other"}, s.secret_key, algorithm="HS256")
    elif mutate == "not_access":
        token = jwt.encode({**claims, "typ": "refresh"}, s.secret_key, algorithm="HS256")
    else:
        token = "definitely.not.ajwt"
    with pytest.raises(AuthenticationError):
        decode_access_token(token)


def test_token_hash_is_stable_and_not_plaintext() -> None:
    assert hash_token("abc") == hash_token("abc") != "abc"
    assert len(hash_token("abc")) == 64


def test_webhook_signature() -> None:
    body = b'{"a":1}'
    header = sign_payload(body, "s3cret", int(time.time()))
    assert verify_signature(body, "s3cret", header)
    assert not verify_signature(body + b" ", "s3cret", header)
    assert not verify_signature(body, "other", header)
    old = sign_payload(body, "s3cret", int(time.time()) - 3600)
    assert not verify_signature(body, "s3cret", old)
    assert not verify_signature(body, "s3cret", "garbage")


def test_log_redaction() -> None:
    out = redact({"user": "a", "password": "p", "nested": {"api_key": "k", "ok": 1}, "list": [{"token": "t"}]})
    assert out == {"user": "a", "password": "[REDACTED]", "nested": {"api_key": "[REDACTED]", "ok": 1},
                   "list": [{"token": "[REDACTED]"}]}
    assert "abc.def" not in redact_text("Authorization: Bearer abc.def")
    assert "hunter2" not in redact_text("url?password=hunter2&x=1")
