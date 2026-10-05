"""/api/v1/models — model registry, evaluations, comparison, drift and training jobs."""

from __future__ import annotations

from datetime import datetime
from typing import Annotated, Any

from fastapi import APIRouter, Depends, Query
from pydantic import Field
from sqlalchemy import select

from app.api.deps import DbSession, Meta, require
from app.core.exceptions import NotFoundError, ValidationFailedError
from app.ml.features.registry import FEATURE_VERSION, FEATURES
from app.ml.inference.service import model_cache
from app.ml.models.members import MEMBER_REGISTRY
from app.ml.synthetic.generator import ATTACK_FAMILIES
from app.models.enums import ModelStatus, Permission
from app.models.ml import DriftReport, MLModel, ModelEvaluation
from app.models.user import User
from app.schemas.common import Schema, StrictInput
from app.services import audit_service, ml_pipeline, model_service
from app.services.drift_service import run_drift_check
from app.websocket.events import RealtimeEvent, publish

router = APIRouter(prefix="/models", tags=["models"])
Viewer = Annotated[User, Depends(require(Permission.VIEW_MODELS))]
Manager = Annotated[User, Depends(require(Permission.MANAGE_MODELS))]


class ModelOut(Schema):
    id: int
    name: str
    version: int
    tag: str
    model_type: str
    feature_version: str
    training_dataset: str
    dataset_sha256: str
    training_config: dict[str, Any]
    trained_at: datetime
    metrics: dict[str, Any]
    status: ModelStatus
    artifact_path: str
    checksum_sha256: str
    notes: str | None
    activated_at: datetime | None
    created_at: datetime


class EvaluationOut(Schema):
    id: int
    model_id: int
    dataset: str
    dataset_sha256: str
    heldout_families: list[str]
    is_synthetic: bool
    config: dict[str, Any]
    summary: dict[str, Any]
    confusion_matrix: dict[str, Any]
    per_family: dict[str, Any]
    created_at: datetime


class DriftOut(Schema):
    id: int
    model_id: int
    window_start: datetime
    window_end: datetime
    sample_size: int
    threshold: float
    feature_psi: dict[str, float]
    max_psi: float
    drifted: bool
    alert_id: int | None
    created_at: datetime


class StatusChange(StrictInput):
    status: ModelStatus


class TrainRequest(StrictInput):
    dataset: str = Field(min_length=1, max_length=128)
    heldout_families: list[str] = Field(default_factory=list, max_length=len(ATTACK_FAMILIES))
    members: list[str] = Field(default_factory=lambda: ["isolation_forest", "autoencoder"], min_length=1, max_length=3)
    train_fraction: float = Field(0.6, ge=0.3, le=0.9)


class SyntheticDatasetRequest(StrictInput):
    seed: int = Field(7, ge=0, le=10**6)
    hours: float = Field(8.0, ge=1, le=48)
    episodes: int = Field(5, ge=1, le=20)
    intensity: float = Field(0.5, ge=0.1, le=2.0)


@router.get("", response_model=list[ModelOut])
def list_models(db: DbSession, _: Viewer) -> list[ModelOut]:
    rows = db.scalars(select(MLModel).order_by(MLModel.name, MLModel.version.desc())).all()
    return [ModelOut.model_validate(m) for m in rows]


@router.get("/features")
def features(_: Viewer) -> dict[str, Any]:
    """The documented feature registry the models consume."""
    return {
        "feature_version": FEATURE_VERSION,
        "features": [
            {
                "name": f.name,
                "label": f.label,
                "description": f.description,
                "transform": f.transform,
                "unit": f.unit,
                "group": f.group,
            }
            for f in FEATURES
        ],
        "members": sorted(MEMBER_REGISTRY),
        "attack_families": list(ATTACK_FAMILIES),
    }


@router.get("/status")
def pipeline_status(db: DbSession, _: Viewer) -> dict[str, Any]:
    active = model_cache.get(db)
    return {
        "active_model": active.tag if active else None,
        "anomaly_detection_available": active is not None,
        "reason": None if active else "No ACTIVE model in the registry — train and activate one.",
    }


@router.get("/datasets")
def datasets(_: Viewer) -> list[dict[str, Any]]:
    return ml_pipeline.list_datasets()


@router.post("/datasets/synthetic", status_code=201)
def create_synthetic_dataset(body: SyntheticDatasetRequest, db: DbSession, user: Manager, meta: Meta) -> dict[str, Any]:
    name, sha = ml_pipeline.generate_synthetic_dataset(
        seed=body.seed, hours=body.hours, episodes=body.episodes, intensity=body.intensity
    )
    audit_service.record(
        db,
        "DATASET_GENERATED",
        actor=user,
        resource_type="dataset",
        resource_id=name[:64],
        meta=meta,
        details={"sha256": sha, **body.model_dump()},
    )
    db.commit()
    return {"dataset": name, "sha256": sha, "synthetic": True}


@router.post("/train", status_code=202)
def train(body: TrainRequest, db: DbSession, user: Manager, meta: Meta) -> dict[str, Any]:
    ml_pipeline.dataset_path(body.dataset)  # validates name + existence
    unknown_members = set(body.members) - set(MEMBER_REGISTRY)
    if unknown_members:
        raise ValidationFailedError(f"Unknown anomaly members: {sorted(unknown_members)}")
    from app.workers.tasks.ml import train_model

    task = train_model.delay(body.dataset, body.heldout_families, body.members, user.id, body.train_fraction)
    audit_service.record(
        db,
        "MODEL_TRAINING_REQUESTED",
        actor=user,
        resource_type="dataset",
        resource_id=body.dataset[:64],
        meta=meta,
        details=body.model_dump(),
    )
    db.commit()
    return {"task_id": task.id, "status": "queued"}


@router.get("/compare")
def compare(
    db: DbSession, _: Viewer, ids: str = Query(..., max_length=200, pattern=r"^\d+(,\d+){0,9}$")
) -> list[dict[str, Any]]:
    """Latest evaluation of each requested model, side by side."""
    out = []
    for model_id in [int(i) for i in ids.split(",")]:
        model = db.get(MLModel, model_id)
        if model is None:
            continue
        ev = db.scalar(
            select(ModelEvaluation)
            .where(ModelEvaluation.model_id == model_id)
            .order_by(ModelEvaluation.created_at.desc())
            .limit(1)
        )
        out.append(
            {
                "model": ModelOut.model_validate(model).model_dump(mode="json"),
                "evaluation": EvaluationOut.model_validate(ev).model_dump(mode="json") if ev else None,
            }
        )
    return out


@router.get("/drift", response_model=list[DriftOut])
def drift_reports(db: DbSession, _: Viewer, limit: int = Query(50, ge=1, le=500)) -> list[DriftOut]:
    rows = db.scalars(select(DriftReport).order_by(DriftReport.created_at.desc()).limit(limit)).all()
    return [DriftOut.model_validate(r) for r in rows]


@router.post("/drift/check")
def drift_check(db: DbSession, user: Manager, meta: Meta, hours: int = Query(24, ge=1, le=168)) -> dict[str, Any]:
    outcome = run_drift_check(db, hours=hours)
    audit_service.record(
        db,
        "DRIFT_CHECK_RUN",
        actor=user,
        resource_type="ml_model",
        resource_id=outcome.report.model_id if outcome.report else None,
        meta=meta,
        details={"outcome": outcome.reason},
    )
    db.commit()
    if outcome.report is not None and outcome.report.drifted:
        publish(RealtimeEvent.MODEL_DRIFT_DETECTED, {"report_id": outcome.report.id, "max_psi": outcome.report.max_psi})
    return {
        "outcome": outcome.reason,
        "report": DriftOut.model_validate(outcome.report).model_dump(mode="json") if outcome.report else None,
        "alert_id": outcome.alert.id if outcome.alert else None,
    }


@router.get("/{model_id}")
def get_model(model_id: int, db: DbSession, _: Viewer) -> dict[str, Any]:
    model = model_service.get_model(db, model_id)
    evaluations = db.scalars(
        select(ModelEvaluation).where(ModelEvaluation.model_id == model_id).order_by(ModelEvaluation.created_at.desc())
    ).all()
    return {
        "model": ModelOut.model_validate(model).model_dump(mode="json"),
        "evaluations": [EvaluationOut.model_validate(e).model_dump(mode="json") for e in evaluations],
    }


@router.get("/evaluations/{evaluation_id}", response_model=EvaluationOut)
def get_evaluation(evaluation_id: int, db: DbSession, _: Viewer) -> EvaluationOut:
    ev = db.get(ModelEvaluation, evaluation_id)
    if ev is None:
        raise NotFoundError("Evaluation not found")
    return EvaluationOut.model_validate(ev)


@router.post("/{model_id}/activate", response_model=ModelOut)
def activate(model_id: int, db: DbSession, user: Manager, meta: Meta) -> ModelOut:
    model = model_service.activate(db, model_id, user, meta)
    db.commit()
    model_cache.clear()
    return ModelOut.model_validate(model)


@router.post("/{model_id}/status", response_model=ModelOut)
def set_status(model_id: int, body: StatusChange, db: DbSession, user: Manager, meta: Meta) -> ModelOut:
    model = model_service.set_status(db, model_id, body.status, user, meta)
    db.commit()
    model_cache.clear()
    return ModelOut.model_validate(model)
