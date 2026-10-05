"""Loads and caches the ACTIVE model bundle for live inference.

The cache is keyed by (model id, checksum); each pipeline batch performs one
cheap query for the active row, so activating a new version takes effect on
the next batch in every worker without restarts or pub/sub.
"""

from __future__ import annotations

import logging
import threading
from dataclasses import dataclass

from sqlalchemy import select
from sqlalchemy.orm import Session

from app.core.config import get_settings
from app.ml.models.bundle import ModelBundle
from app.ml.registry.store import ArtifactIntegrityError, load_bundle
from app.models.enums import ModelStatus
from app.models.ml import MLModel

logger = logging.getLogger(__name__)


@dataclass(frozen=True)
class ActiveModel:
    model_id: int
    tag: str
    bundle: ModelBundle


class ModelCache:
    def __init__(self) -> None:
        self._lock = threading.Lock()
        self._key: tuple[int, str] | None = None
        self._active: ActiveModel | None = None
        self._failed_key: tuple[int, str] | None = None

    def get(self, db: Session) -> ActiveModel | None:
        settings = get_settings()
        row = db.execute(
            select(MLModel.id, MLModel.name, MLModel.version, MLModel.checksum_sha256, MLModel.artifact_path).where(
                MLModel.name == settings.anomaly_model_name, MLModel.status == ModelStatus.ACTIVE
            )
        ).first()
        if row is None:
            return None
        key = (row.id, row.checksum_sha256)
        with self._lock:
            if self._key == key and self._active is not None:
                return self._active
            if self._failed_key == key:
                return None  # already logged; don't hammer the disk every batch
            try:
                bundle = load_bundle(settings.model_artifact_dir / row.artifact_path, row.checksum_sha256)
            except (ArtifactIntegrityError, OSError, ValueError) as exc:
                self._failed_key = key
                logger.error(
                    "active model failed to load; anomaly detection unavailable",
                    extra={"model_id": row.id, "error": str(exc)},
                )
                return None
            self._key = key
            self._failed_key = None
            self._active = ActiveModel(row.id, f"{row.name}-v{row.version}", bundle)
            logger.info("active model loaded", extra={"model": self._active.tag})
            return self._active

    def clear(self) -> None:
        with self._lock:
            self._key = None
            self._active = None
            self._failed_key = None


model_cache = ModelCache()
