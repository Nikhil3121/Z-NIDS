"""Celery application: broker/result backend on Redis, beat schedule for maintenance."""

from __future__ import annotations

from celery import Celery
from celery.schedules import crontab
from celery.signals import setup_logging

from app.core.config import get_settings
from app.core.logging import configure_logging

settings = get_settings()

celery_app = Celery(
    "znids",
    broker=settings.broker_url or "memory://",
    backend=settings.result_backend or "cache+memory://",
    include=[
        "app.workers.tasks.pipeline",
        "app.workers.tasks.followup",
        "app.workers.tasks.maintenance",
        "app.workers.tasks.ml",
    ],
)
celery_app.conf.update(
    task_serializer="json",
    accept_content=["json"],
    result_serializer="json",
    result_expires=3600,
    task_acks_late=True,
    task_reject_on_worker_lost=True,
    worker_prefetch_multiplier=4,
    task_time_limit=300,
    task_soft_time_limit=240,
    broker_connection_retry_on_startup=True,
    task_default_queue="znids",
    task_routes={
        "app.workers.tasks.pipeline.*": {"queue": "pipeline"},
        "app.workers.tasks.followup.*": {"queue": "followup"},
        "app.workers.tasks.maintenance.*": {"queue": "maintenance"},
        "app.workers.tasks.ml.*": {"queue": "ml"},
    },
    # Tests run tasks eagerly in-process.
    task_always_eager=settings.is_testing,
    task_eager_propagates=settings.is_testing,
    beat_schedule={
        "sweep-pending-events": {"task": "app.workers.tasks.pipeline.sweep_pending", "schedule": 30.0},
        "update-baselines": {"task": "app.workers.tasks.maintenance.update_baselines", "schedule": 60.0},
        "recompute-asset-risk": {"task": "app.workers.tasks.maintenance.recompute_asset_risk", "schedule": 300.0},
        "drift-check": {"task": "app.workers.tasks.maintenance.drift_check", "schedule": crontab(minute=5)},
        "retention": {"task": "app.workers.tasks.maintenance.apply_retention", "schedule": crontab(hour=3, minute=15)},
        "retry-notifications": {"task": "app.workers.tasks.followup.retry_failed_notifications", "schedule": 300.0},
    },
)


@setup_logging.connect
def _logging(**_: object) -> None:
    configure_logging(settings.log_level, settings.log_json)
