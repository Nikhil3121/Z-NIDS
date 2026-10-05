"""Train / evaluate / register — shared by the CLI scripts and the API task."""

from __future__ import annotations

import json
import logging
import re
from dataclasses import dataclass
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

from sqlalchemy.orm import Session

from app.core.config import get_settings
from app.core.exceptions import ValidationFailedError
from app.ml.datasets import load_dataset, write_dataset
from app.ml.evaluation.experiment import evaluate_bundle, run_heldout_experiment
from app.ml.features.extractor import extract_features
from app.ml.inference.service import model_cache
from app.ml.registry.store import load_bundle, sha256_file
from app.ml.synthetic.generator import ATTACK_FAMILIES, SyntheticTrafficGenerator
from app.ml.training.train import TrainingConfig
from app.models.ml import MLModel
from app.models.user import User
from app.services import model_service

logger = logging.getLogger(__name__)

_DATASET_NAME = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._\-]{0,120}$")


def dataset_path(name: str) -> Path:
    """Resolve a dataset file name inside ML_DATASETS_DIR (no path traversal)."""
    if not _DATASET_NAME.match(name) or ".." in name:
        raise ValidationFailedError("Invalid dataset name")
    base = get_settings().ml_datasets_dir.resolve()
    path = (base / name).resolve()
    if path.parent != base or not path.is_file():
        raise ValidationFailedError(f"Dataset '{name}' not found in the datasets directory")
    return path


def list_datasets() -> list[dict[str, Any]]:
    base = get_settings().ml_datasets_dir
    out = []
    for manifest in sorted(base.glob("*.manifest.json")):
        try:
            out.append(json.loads(manifest.read_text()))
        except (OSError, json.JSONDecodeError):
            logger.warning("unreadable dataset manifest", extra={"file": manifest.name})
    return out


def generate_synthetic_dataset(
    seed: int = 7,
    hours: float = 8.0,
    episodes: int = 5,
    intensity: float = 0.5,
    families: tuple[str, ...] = ATTACK_FAMILIES,
) -> tuple[str, str]:
    """Create a versioned synthetic dataset file; return (file name, sha256)."""
    # Anchor at a fixed UTC midnight so the same parameters reproduce identical data.
    start = 1_779_926_400.0
    name = f"synthetic-s{seed}-h{hours:g}-e{episodes}-i{intensity:g}.csv.gz"
    path = get_settings().ml_datasets_dir / name
    if path.exists():
        return name, sha256_file(path)
    df = SyntheticTrafficGenerator(seed=seed).generate(
        start=start, hours=hours, families=families, episodes_per_family=episodes, intensity=intensity
    )
    params = {
        "generator": "SyntheticTrafficGenerator",
        "seed": seed,
        "hours": hours,
        "episodes_per_family": episodes,
        "intensity": intensity,
        "families": list(families),
        "start_epoch": start,
        "synthetic": True,
    }
    sha, _ = write_dataset(df, path, params)
    return name, sha


def _is_synthetic(name: str) -> bool:
    return name.startswith("synthetic-")


@dataclass
class TrainOutcome:
    model: MLModel
    evaluation_id: int | None
    summary: dict[str, Any]
    report_path: str


def train_and_register(
    db: Session,
    *,
    dataset: str,
    fmt: str = "normalized",
    heldout: list[str],
    config: TrainingConfig,
    train_fraction: float = 0.6,
    user: User | None = None,
    notes: str | None = None,
) -> TrainOutcome:
    """Run the held-out experiment, register the resulting bundle and its evaluation.

    The registered model is TRAINED, never ACTIVE — promotion is a separate,
    audited decision (POST /models/{id}/activate).
    """
    settings = get_settings()
    frame, sha = load_dataset([dataset_path(dataset)], fmt)
    result = run_heldout_experiment(frame, heldout, config, train_fraction=train_fraction)
    summary = {**result.summary, "dataset": dataset, "dataset_sha256": sha, "synthetic": _is_synthetic(dataset)}
    model = model_service.register_model(
        db,
        result.bundle,
        name=settings.anomaly_model_name,
        dataset_name=dataset,
        dataset_sha256=sha,
        training_config={**config.as_dict(), "heldout_families": heldout, "train_fraction": train_fraction},
        metrics=_headline(summary),
        notes=notes,
        created_by=user,
    )
    stamp = datetime.now(UTC).strftime("%Y%m%dT%H%M%S")
    report = model_service.write_report(
        settings.ml_reports_dir / model.tag,
        f"evaluation-{stamp}",
        {
            "model": model.tag,
            "summary": summary,
            "confusion_matrix": result.confusion_matrix,
            "per_family": result.per_family,
            "latency": result.latency,
        },
    )
    _write_markdown(report.with_suffix(".md"), model.tag, summary, result.confusion_matrix, result.per_family)
    evaluation = model_service.record_evaluation(
        db,
        model,
        dataset=dataset,
        dataset_sha256=sha,
        heldout=heldout,
        is_synthetic=_is_synthetic(dataset),
        config={"train_fraction": train_fraction, **config.as_dict()},
        summary=summary,
        confusion_matrix=result.confusion_matrix,
        per_family=result.per_family,
        report_path=str(report),
    )
    db.flush()
    return TrainOutcome(model, evaluation.id, summary, str(report))


def evaluate_registered(
    db: Session, model_id: int, *, dataset: str, fmt: str = "normalized", heldout: list[str] | None = None
) -> dict[str, Any]:
    """Score an already-registered model on a (different) dataset.

    Families absent from the model's training set are treated as unknown.
    """
    settings = get_settings()
    model = model_service.get_model(db, model_id)
    bundle = load_bundle(settings.model_artifact_dir / model.artifact_path, model.checksum_sha256)
    frame, sha = load_dataset([dataset_path(dataset)], fmt)
    frame = frame.sort_values("ts", kind="stable").reset_index(drop=True)
    features, raw = extract_features(frame)
    labels = frame["label"].astype(str).to_numpy()
    unknown = heldout if heldout is not None else sorted(set(labels) - set(bundle.known_families) - {"normal"})
    summary, cm, per_family, latency = evaluate_bundle(
        bundle,
        features,
        raw,
        labels,
        frame["ts"].to_numpy(dtype=float),
        frame["episode"].fillna("").astype(str).to_numpy(),
        unknown,
    )
    summary.update(
        {
            "dataset": dataset,
            "dataset_sha256": sha,
            "synthetic": _is_synthetic(dataset),
            "heldout_families": unknown,
            "known_families": bundle.known_families,
        }
    )
    stamp = datetime.now(UTC).strftime("%Y%m%dT%H%M%S")
    report = model_service.write_report(
        settings.ml_reports_dir / model.tag,
        f"evaluation-{stamp}",
        {"model": model.tag, "summary": summary, "confusion_matrix": cm, "per_family": per_family, "latency": latency},
    )
    _write_markdown(report.with_suffix(".md"), model.tag, summary, cm, per_family)
    evaluation = model_service.record_evaluation(
        db,
        model,
        dataset=dataset,
        dataset_sha256=sha,
        heldout=unknown,
        is_synthetic=_is_synthetic(dataset),
        config={"mode": "evaluate_registered"},
        summary=summary,
        confusion_matrix=cm,
        per_family=per_family,
        report_path=str(report),
    )
    db.flush()
    return {"evaluation_id": evaluation.id, "summary": summary, "report": str(report)}


def _headline(summary: dict[str, Any]) -> dict[str, Any]:
    unk = summary.get("unknown_attacks") or {}
    overall = summary.get("overall") or {}
    return {
        "precision": overall.get("precision"),
        "recall": overall.get("recall"),
        "f1": overall.get("f1"),
        "roc_auc": overall.get("roc_auc"),
        "pr_auc": overall.get("pr_auc"),
        "false_positive_rate": summary.get("false_positive_rate"),
        "unknown_attack_detection_rate": unk.get("unknown_attack_detection_rate"),
        "unknown_macro_detection_rate": unk.get("macro_detection_rate"),
        "known_macro_detection_rate": summary.get("known_macro_detection_rate"),
        "supervised_baseline_unknown_recall": (summary.get("supervised_baseline") or {}).get("unknown_recall"),
        "synthetic_dataset": summary.get("synthetic"),
    }


def _pct(v: Any) -> str:
    return "n/a" if v is None else f"{100 * float(v):.1f}%"


def _write_markdown(
    path: Path, tag: str, s: dict[str, Any], cm: dict[str, dict[str, int]], per_family: dict[str, dict[str, Any]]
) -> None:
    lines = [f"# Evaluation report — {tag}", ""]
    if s.get("synthetic"):
        lines += [
            "> **Synthetic laboratory data.** These numbers demonstrate the methodology on generated",
            "> flows; they are not a measurement of performance on real network traffic.",
            "",
        ]
    lines += [
        f"> {s.get('disclaimer', 'Laboratory evaluation of previously unseen attack behaviour.')}",
        "",
        f"* Dataset: `{s.get('dataset')}` (sha256 `{str(s.get('dataset_sha256'))[:16]}…`)",
        f"* Known families (trained): {', '.join(s.get('known_families') or []) or '—'}",
        f"* Held-out families (unseen): {', '.join(s.get('heldout_families') or []) or '—'}",
        "",
        "## Headline",
        "",
        "| Metric | Value |",
        "|---|---|",
    ]
    o, u = s.get("overall") or {}, s.get("unknown_attacks") or {}
    base = s.get("supervised_baseline") or {}
    rows = [
        ("Precision", _pct(o.get("precision"))),
        ("Recall", _pct(o.get("recall"))),
        ("F1", _pct(o.get("f1"))),
        ("ROC-AUC", o.get("roc_auc")),
        ("PR-AUC", o.get("pr_auc")),
        ("False-positive rate", _pct(s.get("false_positive_rate"))),
        ("Unknown-attack detection rate (flows)", _pct(u.get("unknown_attack_detection_rate"))),
        ("Unknown-attack detection rate (macro, per family)", _pct(u.get("macro_detection_rate"))),
        ("Unknown flows misattributed to a known family", _pct(u.get("misattributed_to_known_family_rate"))),
        ("Supervised baseline recall on unknown families", _pct(base.get("unknown_recall"))),
        (
            "Median seconds to first detection (unknown episodes)",
            (s.get("detection_latency") or {}).get("median_seconds_unknown"),
        ),
    ]
    lines += [f"| {k} | {v} |" for k, v in rows]
    lines += [
        "",
        "## Per family",
        "",
        "| Family | Group | Flows | Detected | As known | As anomalous | As potential unknown | Supervised baseline |",
        "|---|---|---|---|---|---|---|---|",
    ]
    for fam, v in per_family.items():
        lines.append(
            f"| {fam} | {v['group']} | {v['rows']} | {_pct(v['detection_rate'])} | {_pct(v['as_known_attack'])} | "
            f"{_pct(v['as_anomalous'])} | {_pct(v['as_potential_unknown'])} | {_pct(v.get('supervised_baseline_recall'))} |"
        )
    lines += [
        "",
        "## Confusion matrix (rows = ground truth, columns = verdict)",
        "",
        "| Label | NORMAL | KNOWN_ATTACK | ANOMALOUS | POTENTIAL_UNKNOWN |",
        "|---|---|---|---|---|",
    ]
    for label, cols in cm.items():
        lines.append(
            f"| {label} | {cols['NORMAL']} | {cols['KNOWN_ATTACK']} | {cols['ANOMALOUS']} | {cols['POTENTIAL_UNKNOWN']} |"
        )
    path.write_text("\n".join(lines) + "\n", encoding="utf-8")


def activate_and_reload(db: Session, model_id: int, user: User | None) -> MLModel:
    model = model_service.activate(db, model_id, user)
    model_cache.clear()
    return model


__all__ = [
    "TrainOutcome",
    "activate_and_reload",
    "dataset_path",
    "evaluate_registered",
    "generate_synthetic_dataset",
    "list_datasets",
    "train_and_register",
]
