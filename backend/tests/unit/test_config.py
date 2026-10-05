from __future__ import annotations

import pytest
from pydantic import ValidationError

from app.core.config import Settings

BASE = {"database_url": "postgresql+psycopg://u:p@h/d", "redis_url": "redis://h", "secret_key": "k" * 40}


def test_valid_development_settings() -> None:
    s = Settings(**BASE, environment="development", cors_origins="http://a,http://b")
    assert s.cors_origins == ["http://a", "http://b"]


def test_missing_secret_fails() -> None:
    with pytest.raises(ValidationError, match="SECRET_KEY"):
        Settings(**{**BASE, "secret_key": "changeme"}, environment="development")


@pytest.mark.parametrize(
    "override, message",
    [
        ({"cors_origins": "*"}, "CORS_ORIGINS"),
        ({"secure_cookies": False}, "SECURE_COOKIES"),
        ({"demo_mode": True}, "DEMO_MODE"),
        ({"email_backend": "file"}, "EMAIL_BACKEND"),
        ({"pipeline_mode": "inline"}, "PIPELINE_MODE"),
        ({"response_mode": "AUTOMATIC", "response_adapter": "lab"}, "RESPONSE_MODE"),
    ],
)
def test_production_fails_safe(override: dict, message: str) -> None:
    safe = {"cors_origins": "https://soc.example.com", "secure_cookies": True, "email_backend": "smtp",
            "pipeline_mode": "queue", "demo_mode": False}
    Settings(**BASE, environment="production", **safe)  # baseline is valid
    with pytest.raises(ValidationError, match=message):
        Settings(**BASE, environment="production", **{**safe, **override})
