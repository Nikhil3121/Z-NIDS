"""Application configuration.

All configuration comes from environment variables (optionally a local `.env`
file in development). Nothing security-sensitive has a usable default: the
production/staging profiles refuse to start when a required secret is missing
or obviously weak, rather than silently falling back to something insecure.
"""

from __future__ import annotations

from enum import StrEnum
from functools import lru_cache
from pathlib import Path
from typing import Annotated

from pydantic import Field, field_validator, model_validator
from pydantic_settings import BaseSettings, NoDecode, SettingsConfigDict

BACKEND_DIR = Path(__file__).resolve().parents[2]
PROJECT_DIR = BACKEND_DIR.parent


class Environment(StrEnum):
    DEVELOPMENT = "development"
    TESTING = "testing"
    STAGING = "staging"
    PRODUCTION = "production"


class ResponseMode(StrEnum):
    """How the response engine may act on detections."""

    DETECTION_ONLY = "DETECTION_ONLY"
    MANUAL_APPROVAL = "MANUAL_APPROVAL"
    AUTOMATIC = "AUTOMATIC"


class PipelineMode(StrEnum):
    """`queue` hands batches to Celery; `inline` processes in-request (tests, CLI)."""

    QUEUE = "queue"
    INLINE = "inline"


_WEAK_SECRETS = {"", "changeme", "change-me", "secret", "dev", "development", "please-change-me"}


def _split_csv(value: object) -> object:
    if isinstance(value, str):
        return [item.strip() for item in value.split(",") if item.strip()]
    return value


class Settings(BaseSettings):
    model_config = SettingsConfigDict(
        env_file=(PROJECT_DIR / ".env", BACKEND_DIR / ".env"),
        env_file_encoding="utf-8",
        extra="ignore",
        case_sensitive=False,
    )

    # --- APPLICATION -------------------------------------------------------
    app_name: str = "Z-NIDS"
    environment: Environment = Environment.DEVELOPMENT
    api_prefix: str = "/api/v1"
    max_request_bytes: int = 5 * 1024 * 1024
    request_timeout_seconds: float = 30.0
    expose_docs: bool = True

    # --- DATABASE ----------------------------------------------------------
    database_url: str = ""
    database_pool_size: int = 10
    database_max_overflow: int = 20
    database_statement_timeout_ms: int = 15000

    # --- REDIS -------------------------------------------------------------
    redis_url: str = ""
    celery_broker_url: str = ""
    celery_result_backend: str = ""
    pipeline_mode: PipelineMode = PipelineMode.QUEUE

    # --- AUTH --------------------------------------------------------------
    secret_key: str = ""
    jwt_algorithm: str = "HS256"
    jwt_issuer: str = "z-nids"
    jwt_audience: str = "z-nids-api"
    access_token_ttl_minutes: int = 15
    refresh_token_ttl_days: int = 7
    activation_token_ttl_hours: int = 48
    password_reset_ttl_minutes: int = 30
    password_min_length: int = 12
    max_failed_logins: int = 5
    lockout_minutes: int = 15
    secure_cookies: bool = True
    frontend_base_url: str = "http://localhost:5180"

    # --- CORS --------------------------------------------------------------
    cors_origins: Annotated[list[str], NoDecode] = Field(default_factory=list)

    # --- RATE_LIMIT --------------------------------------------------------
    rate_limit_enabled: bool = True
    rate_limit_login_per_minute: int = 10
    rate_limit_api_per_minute: int = 600
    rate_limit_ingest_per_minute: int = 1200
    rate_limit_assistant_per_minute: int = 20

    # --- ML ----------------------------------------------------------------
    model_artifact_dir: Path = PROJECT_DIR / "ml" / "models"
    ml_reports_dir: Path = PROJECT_DIR / "ml" / "reports"
    ml_datasets_dir: Path = PROJECT_DIR / "ml" / "datasets"
    anomaly_model_name: str = "z-nids-anomaly"
    known_attack_confidence: float = 0.80
    drift_psi_threshold: float = 0.25
    drift_min_samples: int = 500
    baseline_min_observations: int = 30
    # Networks considered "internal" when deriving flow direction and discovering assets.
    home_networks: Annotated[list[str], NoDecode] = Field(
        default_factory=lambda: ["10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16"]
    )
    # Minimum risk for a non-normal detection to raise an alert.
    alert_min_risk: float = 40.0
    alert_dedup_minutes: int = 30
    correlation_window_minutes: int = 120

    # --- THREAT_INTELLIGENCE ----------------------------------------------
    abuseipdb_api_key: str = ""
    threat_intel_cache_ttl_hours: int = 24
    threat_intel_requests_per_minute: int = 30
    threat_intel_timeout_seconds: float = 5.0

    # --- EMAIL -------------------------------------------------------------
    smtp_host: str = ""
    smtp_port: int = 587
    smtp_username: str = ""
    smtp_password: str = ""
    smtp_use_tls: bool = True
    email_from: str = ""
    # `smtp` sends mail; `file` writes .eml files to email_file_dir (development only).
    email_backend: str = "smtp"
    email_file_dir: Path = PROJECT_DIR / "var" / "mail"

    # --- WEBHOOKS ----------------------------------------------------------
    webhook_signing_secret: str = ""
    webhook_timeout_seconds: float = 5.0
    webhook_allow_private_targets: bool = False
    slack_webhook_url: str = ""

    # --- LOGGING -----------------------------------------------------------
    log_level: str = "INFO"
    log_json: bool = True

    # --- RETENTION ---------------------------------------------------------
    event_retention_days: int = 30
    detection_retention_days: int = 90
    audit_retention_days: int = 365
    threat_intel_retention_days: int = 30
    retention_batch_size: int = 5000

    # --- DEMO --------------------------------------------------------------
    demo_mode: bool = False

    # --- RESPONSE_ENGINE ---------------------------------------------------
    response_mode: ResponseMode = ResponseMode.DETECTION_ONLY
    response_adapter: str = "lab"

    # --- AI ASSISTANT ------------------------------------------------------
    anthropic_api_key: str = ""
    assistant_model: str = "claude-opus-5"
    assistant_max_tokens: int = 4096
    assistant_timeout_seconds: float = 60.0

    # --- Signature rules ---------------------------------------------------
    signature_rules_path: Path = BACKEND_DIR / "config" / "signature_rules.json"
    risk_weights_path: Path = BACKEND_DIR / "config" / "risk_weights.json"
    correlation_rules_path: Path = BACKEND_DIR / "config" / "correlation_rules.json"

    @field_validator("cors_origins", "home_networks", mode="before")
    @classmethod
    def _parse_origins(cls, value: object) -> object:
        return _split_csv(value)

    @property
    def is_production_like(self) -> bool:
        return self.environment in (Environment.PRODUCTION, Environment.STAGING)

    @property
    def is_testing(self) -> bool:
        return self.environment == Environment.TESTING

    @property
    def broker_url(self) -> str:
        return self.celery_broker_url or self.redis_url

    @property
    def result_backend(self) -> str:
        return self.celery_result_backend or self.redis_url

    @model_validator(mode="after")
    def _validate_security(self) -> Settings:
        problems: list[str] = []
        if not self.database_url:
            problems.append("DATABASE_URL is required")
        if not self.redis_url and not self.is_testing:
            problems.append("REDIS_URL is required")
        if self.secret_key.strip().lower() in _WEAK_SECRETS or len(self.secret_key) < 32:
            problems.append("SECRET_KEY must be set to a random value of at least 32 characters")

        if self.is_production_like:
            if "*" in self.cors_origins:
                problems.append("CORS_ORIGINS may not contain '*' outside development")
            if not self.secure_cookies:
                problems.append("SECURE_COOKIES must be true outside development")
            if self.demo_mode and self.environment == Environment.PRODUCTION:
                problems.append("DEMO_MODE may not be enabled in production")
            if self.email_backend != "smtp":
                problems.append("EMAIL_BACKEND must be 'smtp' outside development")
            if self.pipeline_mode != PipelineMode.QUEUE:
                problems.append("PIPELINE_MODE must be 'queue' outside development")
            if self.response_mode == ResponseMode.AUTOMATIC and self.response_adapter == "lab":
                # Automatic response only makes sense against a real, explicitly
                # configured adapter; refuse the combination rather than guess.
                problems.append("RESPONSE_MODE=AUTOMATIC requires a non-lab RESPONSE_ADAPTER")
        if problems:
            raise ValueError("Invalid Z-NIDS configuration: " + "; ".join(problems))
        return self


@lru_cache
def get_settings() -> Settings:
    return Settings()
