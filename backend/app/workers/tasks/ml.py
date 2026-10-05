"""Background ML jobs triggered from the API (training / evaluation / drift)."""

from __future__ import annotations

import logging

from app.db.session import get_sessionmaker
from app.ml.training.train import TrainingConfig
from app.models.user import User
from app.services import ml_pipeline
from app.workers.celery_app import celery_app

logger = logging.getLogger(__name__)


@celery_app.task(name="app.workers.tasks.ml.train_model", time_limit=3600, soft_time_limit=3500)
def train_model(
    dataset: str, heldout: list[str], members: list[str], user_id: int | None, train_fraction: float = 0.6
) -> dict:
    db = get_sessionmaker()()
    try:
        user = db.get(User, user_id) if user_id else None
        outcome = ml_pipeline.train_and_register(
            db,
            dataset=dataset,
            heldout=heldout,
            config=TrainingConfig(members=members),
            train_fraction=train_fraction,
            user=user,
            notes="trained via API",
        )
        db.commit()
        return {"model_id": outcome.model.id, "tag": outcome.model.tag, "evaluation_id": outcome.evaluation_id}
    except Exception:
        db.rollback()
        logger.exception("training job failed", extra={"dataset": dataset})
        raise
    finally:
        db.close()
