"""Model registry: versioning, evaluation records and explicit activation."""

from __future__ import annotations

import json
import logging
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

from sqlalchemy import func, select, update
from sqlalchemy.orm import Session

from app.core.config import get_settings
from app.core.exceptions import ConflictError, NotFoundError, ValidationFailedError
from app.ml.models.bundle import ModelBundle
from app.ml.registry.store import save_bundle, sha256_file
from app.models.enums import ModelStatus
from app.models.ml import MLModel, ModelEvaluation, ModelMetric
from app.models.user import User
from app.services import audit_service
from app.services.audit_service import RequestMeta

logger = logging.getLogger(__name__)


def next_version(db: Session, name: str) -> int:
    current = db.scalar(select(func.max(MLModel.version)).where(MLModel.name == name))
    return int(current or 0) + 1


def register_model(
    db: Session,
    bundle: ModelBundle,
    *,
    name: str,
    dataset_name: str,
    dataset_sha256: str,
    training_config: dict[str, Any],
    metrics: dict[str, Any],
    notes: str | None = None,
    created_by: User | None = None,
) -> MLModel:
    settings = get_settings()
    version = next_version(db, name)
    path, checksum = save_bundle(bundle, settings.model_artifact_dir, name, version)
    model = MLModel(
        name=name,
        version=version,
        model_type="ensemble:"
        + "+".join(m.name for m in bundle.members)
        + ("+rf_known_family" if bundle.classifier is not None else ""),
        feature_version=bundle.feature_version,
        training_dataset=dataset_name,
        dataset_sha256=dataset_sha256,
        training_config=training_config,
        trained_at=datetime.now(UTC),
        metrics=metrics,
        status=ModelStatus.TRAINED,
        artifact_path=path.name,
        checksum_sha256=checksum,
        notes=notes,
        created_by_id=created_by.id if created_by else None,
    )
    db.add(model)
    db.flush()
    audit_service.record(
        db,
        "MODEL_REGISTERED",
        actor=created_by,
        resource_type="ml_model",
        resource_id=model.id,
        details={"tag": model.tag, "sha256": checksum},
    )
    logger.info("model registered", extra={"model": model.tag})
    return model


_FLAT_METRICS = ("precision", "recall", "f1", "roc_auc", "pr_auc", "false_positive_rate", "detection_rate")


def record_evaluation(
    db: Session,
    model: MLModel,
    *,
    dataset: str,
    dataset_sha256: str,
    heldout: list[str],
    is_synthetic: bool,
    config: dict[str, Any],
    summary: dict[str, Any],
    confusion_matrix: dict[str, Any],
    per_family: dict[str, Any],
    report_path: str | None,
) -> ModelEvaluation:
    evaluation = ModelEvaluation(
        model_id=model.id,
        dataset=dataset,
        dataset_sha256=dataset_sha256,
        heldout_families=heldout,
        is_synthetic=is_synthetic,
        config=config,
        summary=summary,
        confusion_matrix=confusion_matrix,
        per_family=per_family,
        report_path=report_path,
    )
    db.add(evaluation)
    db.flush()
    rows: list[ModelMetric] = []
    for scope in ("overall", "known_attacks", "unknown_attacks", "anomaly_detector_only"):
        block = summary.get(scope) or {}
        for key in _FLAT_METRICS:
            if key in block:
                rows.append(
                    ModelMetric(
                        model_id=model.id,
                        evaluation_id=evaluation.id,
                        scope=scope,
                        metric_name=key,
                        metric_value=block[key],
                    )
                )
    unknown = summary.get("unknown_attacks") or {}
    for key in ("unknown_attack_detection_rate", "macro_detection_rate", "misattributed_to_known_family_rate"):
        if key in unknown:
            rows.append(
                ModelMetric(
                    model_id=model.id,
                    evaluation_id=evaluation.id,
                    scope="unknown_attacks",
                    metric_name=key,
                    metric_value=unknown[key],
                )
            )
    for fam, block in per_family.items():
        rows.append(
            ModelMetric(
                model_id=model.id,
                evaluation_id=evaluation.id,
                scope=f"family:{fam}",
                metric_name="detection_rate",
                metric_value=block["detection_rate"],
            )
        )
    latency = summary.get("detection_latency") or {}
    for key in ("median_seconds_known", "median_seconds_unknown", "inference_ms_per_1000_flows"):
        if latency.get(key) is not None:
            rows.append(
                ModelMetric(
                    model_id=model.id,
                    evaluation_id=evaluation.id,
                    scope="latency",
                    metric_name=key,
                    metric_value=latency[key],
                )
            )
    db.add_all(rows)
    return evaluation


def get_model(db: Session, model_id: int) -> MLModel:
    model = db.get(MLModel, model_id)
    if model is None:
        raise NotFoundError("Model not found")
    return model


def activate(db: Session, model_id: int, user: User | None, meta: RequestMeta | None = None) -> MLModel:
    """Promote a model to ACTIVE; the previously active version is ARCHIVED.

    Verifies the artifact checksum first — a tampered or missing artifact can
    never become the production model.
    """
    model = db.scalar(select(MLModel).where(MLModel.id == model_id).with_for_update(key_share=True))
    if model is None:
        raise NotFoundError("Model not found")
    if model.status == ModelStatus.ACTIVE:
        raise ConflictError("Model is already active")
    if model.status == ModelStatus.REJECTED:
        raise ValidationFailedError("A rejected model cannot be activated")
    path = get_settings().model_artifact_dir / model.artifact_path
    if not path.is_file() or sha256_file(path) != model.checksum_sha256:
        audit_service.record_independent(
            "MODEL_ACTIVATION_BLOCKED",
            actor=user,
            resource_type="ml_model",
            resource_id=model.id,
            meta=meta,
            details={"reason": "artifact missing or checksum mismatch"},
        )
        raise ConflictError("Model artifact failed integrity verification", code="ARTIFACT_INTEGRITY_FAILED")
    previous = db.scalars(select(MLModel).where(MLModel.name == model.name, MLModel.status == ModelStatus.ACTIVE)).all()
    db.execute(
        update(MLModel)
        .where(MLModel.name == model.name, MLModel.status == ModelStatus.ACTIVE)
        .values(status=ModelStatus.ARCHIVED)
    )
    db.flush()
    model.status = ModelStatus.ACTIVE
    model.activated_at = datetime.now(UTC)
    model.activated_by_id = user.id if user else None
    audit_service.record(
        db,
        "MODEL_ACTIVATED",
        actor=user,
        resource_type="ml_model",
        resource_id=model.id,
        meta=meta,
        details={"tag": model.tag, "previous": [p.tag for p in previous]},
    )
    return model


def set_status(db: Session, model_id: int, status: ModelStatus, user: User, meta: RequestMeta) -> MLModel:
    if status == ModelStatus.ACTIVE:
        return activate(db, model_id, user, meta)
    model = get_model(db, model_id)
    if model.status == ModelStatus.ACTIVE and status != ModelStatus.ACTIVE:
        raise ConflictError("Activate another version instead of demoting the active model directly")
    old = model.status
    model.status = status
    audit_service.record(
        db,
        "MODEL_STATUS_CHANGED",
        actor=user,
        resource_type="ml_model",
        resource_id=model.id,
        meta=meta,
        details={"from": old.value, "to": status.value},
    )
    return model


def write_report(directory: Path, name: str, payload: dict[str, Any]) -> Path:
    directory.mkdir(parents=True, exist_ok=True)
    path = directory / f"{name}.json"
    path.write_text(json.dumps(payload, indent=2, default=str))
    return path
