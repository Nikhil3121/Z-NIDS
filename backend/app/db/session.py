"""Database engine and session management.

The API uses synchronous SQLAlchemy sessions on psycopg 3. FastAPI runs sync
dependencies/endpoints in its threadpool, and the Celery workers share the same
code path, which keeps the detection pipeline identical in both places.
"""

from __future__ import annotations

from collections.abc import Iterator
from contextlib import contextmanager
from functools import lru_cache

from sqlalchemy import Engine, create_engine, event
from sqlalchemy.orm import Session, sessionmaker

from app.core.config import get_settings


@lru_cache
def get_engine() -> Engine:
    settings = get_settings()
    engine = create_engine(
        settings.database_url,
        pool_size=settings.database_pool_size,
        max_overflow=settings.database_max_overflow,
        pool_pre_ping=True,
        pool_recycle=1800,
        future=True,
    )

    timeout = settings.database_statement_timeout_ms

    @event.listens_for(engine, "connect")
    def _set_timeouts(dbapi_conn, _record):  # type: ignore[no-untyped-def]
        # Bound every statement so a pathological query cannot pin a worker.
        with dbapi_conn.cursor() as cur:
            cur.execute(f"SET statement_timeout = {int(timeout)}")
        dbapi_conn.commit()

    return engine


@lru_cache
def get_sessionmaker() -> sessionmaker[Session]:
    return sessionmaker(bind=get_engine(), autoflush=False, expire_on_commit=False)


def get_db() -> Iterator[Session]:
    """FastAPI dependency: one session per request, rolled back on error."""
    session = get_sessionmaker()()
    try:
        yield session
    except Exception:
        session.rollback()
        raise
    finally:
        session.close()


@contextmanager
def session_scope() -> Iterator[Session]:
    """Transactional scope for workers and CLI scripts."""
    session = get_sessionmaker()()
    try:
        yield session
        session.commit()
    except Exception:
        session.rollback()
        raise
    finally:
        session.close()
