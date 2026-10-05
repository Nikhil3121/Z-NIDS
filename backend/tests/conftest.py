"""Shared test configuration.

Unit/ML tests need no services. Integration & security tests need PostgreSQL
and Redis: set TEST_DATABASE_URL / TEST_REDIS_URL (docker-compose.dev.yml
provides both). They are skipped — loudly — when those are absent.
"""

from __future__ import annotations

import os
import tempfile
from pathlib import Path

# Deterministic, isolated settings for every test run. Must happen before app imports.
os.environ["ENVIRONMENT"] = "testing"
os.environ["SECRET_KEY"] = "test-secret-key-" + "x" * 40
os.environ.setdefault("TEST_DATABASE_URL", "")
os.environ["DATABASE_URL"] = os.environ.get("TEST_DATABASE_URL") or "postgresql+psycopg://unused:unused@localhost:1/unused"
os.environ["REDIS_URL"] = os.environ.get("TEST_REDIS_URL") or "redis://127.0.0.1:1/0"
os.environ["PIPELINE_MODE"] = "inline"
os.environ["EMAIL_BACKEND"] = "file"
os.environ["RATE_LIMIT_ENABLED"] = "true"
os.environ["DEMO_MODE"] = "true"
os.environ["LOG_JSON"] = "false"
os.environ["LOG_LEVEL"] = "WARNING"
os.environ["CORS_ORIGINS"] = "http://testserver.local"
os.environ["ANTHROPIC_API_KEY"] = ""
os.environ["ABUSEIPDB_API_KEY"] = ""
_TMP = Path(tempfile.mkdtemp(prefix="znids-tests-"))
os.environ["MODEL_ARTIFACT_DIR"] = str(_TMP / "models")
os.environ["ML_REPORTS_DIR"] = str(_TMP / "reports")
os.environ["ML_DATASETS_DIR"] = str(_TMP / "datasets")
os.environ["EMAIL_FILE_DIR"] = str(_TMP / "mail")
os.environ["RESPONSE_MODE"] = "MANUAL_APPROVAL"


# --------------------------------------------------------------------------- DB-backed fixtures
from collections.abc import Iterator  # noqa: E402
from typing import Any  # noqa: E402

import fakeredis  # noqa: E402
import pytest  # noqa: E402

DB_AVAILABLE = bool(os.environ.get("TEST_DATABASE_URL"))
requires_db = pytest.mark.skipif(not DB_AVAILABLE, reason="TEST_DATABASE_URL not set (needs PostgreSQL)")

_FAKE_REDIS = fakeredis.FakeRedis(decode_responses=True)


def _patch_redis() -> None:
    from app.core.redis import set_redis_client

    set_redis_client(_FAKE_REDIS)


@pytest.fixture(scope="session")
def migrated_db() -> Iterator[None]:
    if not DB_AVAILABLE:
        pytest.skip("TEST_DATABASE_URL not set (needs PostgreSQL)")
    from alembic.config import Config

    from alembic import command

    cfg = Config(str(Path(__file__).resolve().parents[1] / "alembic.ini"))
    cfg.set_main_option("script_location", str(Path(__file__).resolve().parents[1] / "alembic"))
    from sqlalchemy import create_engine, text

    engine = create_engine(os.environ["TEST_DATABASE_URL"])
    with engine.begin() as conn:  # start from an empty schema every session
        conn.execute(text("DROP SCHEMA public CASCADE"))
        conn.execute(text("CREATE SCHEMA public"))
    engine.dispose()
    command.upgrade(cfg, "head")
    yield


REFERENCE_TABLES = {"roles", "permissions", "role_permissions", "mitre_techniques", "alembic_version"}


@pytest.fixture
def db(migrated_db: None) -> Iterator[Any]:
    """Clean database (reference data kept) and a clean fake Redis for every test."""
    from sqlalchemy import text

    import app.main
    import app.workers.tasks.followup
    import app.workers.tasks.maintenance  # noqa: F401
    from app.db.base import Base
    from app.db.session import get_sessionmaker
    from app.ml.inference.service import model_cache

    _patch_redis()
    _FAKE_REDIS.flushall()
    model_cache.clear()
    tables = [t for t in Base.metadata.tables if t not in REFERENCE_TABLES]
    session = get_sessionmaker()()
    session.execute(text("TRUNCATE " + ", ".join(f'"{t}"' for t in tables) + " RESTART IDENTITY CASCADE"))
    session.commit()
    try:
        yield session
    finally:
        session.rollback()
        session.close()


@pytest.fixture
def fake_redis() -> fakeredis.FakeRedis:
    return _FAKE_REDIS


@pytest.fixture
def client(db: Any) -> Iterator[Any]:
    from fastapi.testclient import TestClient

    from app.main import app

    with TestClient(app, base_url="http://testserver.local") as c:
        yield c
