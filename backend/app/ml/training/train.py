"""Fit a ModelBundle from labelled feature matrices."""

from __future__ import annotations

import logging
import time
from dataclasses import dataclass, field
from typing import Any

import numpy as np
import pandas as pd
from sklearn.ensemble import RandomForestClassifier
from sklearn.preprocessing import RobustScaler

from app.ml.features.registry import FEATURE_NAMES, FEATURE_VERSION
from app.ml.models.bundle import NORMAL_LABEL, Calibrator, ModelBundle
from app.ml.models.members import MEMBER_REGISTRY

logger = logging.getLogger(__name__)


@dataclass
class TrainingConfig:
    members: list[str] = field(default_factory=lambda: ["isolation_forest", "autoencoder"])
    use_classifier: bool = True
    target_fpr_anomalous: float = 0.005
    target_fpr_unknown: float = 0.001
    known_confidence: float = 0.8
    validation_fraction: float = 0.2
    max_normal_train_rows: int = 120_000
    max_rows_per_class: int = 25_000
    seed: int = 7
    member_params: dict[str, dict[str, Any]] = field(default_factory=dict)

    def as_dict(self) -> dict[str, Any]:
        return {
            "members": self.members,
            "use_classifier": self.use_classifier,
            "target_fpr_anomalous": self.target_fpr_anomalous,
            "target_fpr_unknown": self.target_fpr_unknown,
            "known_confidence": self.known_confidence,
            "validation_fraction": self.validation_fraction,
            "max_normal_train_rows": self.max_normal_train_rows,
            "max_rows_per_class": self.max_rows_per_class,
            "seed": self.seed,
            "member_params": self.member_params,
        }


def _drift_reference(
    x: np.ndarray, names: list[str], bins: int = 10
) -> tuple[dict[str, list[float]], dict[str, list[float]]]:
    edges: dict[str, list[float]] = {}
    expected: dict[str, list[float]] = {}
    for j, name in enumerate(names):
        col = x[:, j]
        e = np.unique(np.quantile(col, np.linspace(0, 1, bins + 1)[1:-1]))
        counts = np.bincount(np.searchsorted(e, col, side="right"), minlength=len(e) + 1)
        edges[name] = e.tolist()
        expected[name] = (counts / max(len(col), 1)).tolist()
    return edges, expected


def train_bundle(
    features: pd.DataFrame,
    raw: pd.DataFrame,
    labels: pd.Series,
    ts: pd.Series,
    config: TrainingConfig,
) -> tuple[ModelBundle, dict[str, Any]]:
    """Train on the given (already held-out-filtered) training period.

    Normal rows are split by *time*: the latest `validation_fraction` becomes
    the calibration/threshold set, so thresholds are never fitted on the rows
    the members were trained on.
    """
    if list(features.columns) != FEATURE_NAMES:
        raise ValueError("feature columns do not match the registry")
    rng = np.random.default_rng(config.seed)
    started = time.perf_counter()
    labels = labels.astype(str).to_numpy()
    ts_arr = ts.to_numpy(dtype=float)
    x_all = features.to_numpy(dtype=float)

    normal_idx = np.flatnonzero(labels == NORMAL_LABEL)
    if len(normal_idx) < 1000:
        raise ValueError(f"need at least 1000 normal flows to train, got {len(normal_idx)}")
    normal_idx = normal_idx[np.argsort(ts_arr[normal_idx], kind="stable")]
    cut = int(len(normal_idx) * (1 - config.validation_fraction))
    train_idx, val_idx = normal_idx[:cut], normal_idx[cut:]
    if len(train_idx) > config.max_normal_train_rows:
        train_idx = rng.choice(train_idx, config.max_normal_train_rows, replace=False)

    bundle = ModelBundle(feature_version=FEATURE_VERSION, feature_names=list(FEATURE_NAMES))
    bundle.scaler = RobustScaler(quantile_range=(5.0, 95.0)).fit(x_all[train_idx])
    z_train = bundle.transform(x_all[train_idx])
    z_val = bundle.transform(x_all[val_idx])

    member_timings: dict[str, float] = {}
    for name in config.members:
        cls = MEMBER_REGISTRY.get(name)
        if cls is None:
            raise ValueError(f"unknown anomaly member '{name}'")
        t0 = time.perf_counter()
        member = cls(seed=config.seed, **config.member_params.get(name, {}))  # type: ignore[call-arg]
        member.fit(z_train)
        bundle.members.append(member)
        bundle.calibrators[name] = Calibrator(member.score(z_val))
        member_timings[name] = round(time.perf_counter() - t0, 2)
        logger.info("trained member", extra={"member": name, "seconds": member_timings[name]})

    val_pct = np.mean([bundle.calibrators[m.name](m.score(z_val)) for m in bundle.members], axis=0)
    bundle.ensemble_calibrator = Calibrator(val_pct)
    bundle.threshold_anomalous = 1.0 - config.target_fpr_anomalous
    bundle.threshold_unknown = 1.0 - config.target_fpr_unknown
    bundle.known_confidence = config.known_confidence

    families = sorted({lbl for lbl in labels if lbl != NORMAL_LABEL})
    if config.use_classifier and families:
        cls_idx: list[np.ndarray] = []
        for lbl in [NORMAL_LABEL, *families]:
            idx = np.flatnonzero(labels == lbl)
            if lbl == NORMAL_LABEL:
                idx = train_idx  # never train the classifier on the calibration rows
            if len(idx) > config.max_rows_per_class:
                idx = rng.choice(idx, config.max_rows_per_class, replace=False)
            cls_idx.append(idx)
        idx = np.concatenate(cls_idx)
        clf = RandomForestClassifier(
            n_estimators=150,
            max_depth=24,
            min_samples_leaf=2,
            class_weight="balanced_subsample",
            n_jobs=-1,
            random_state=config.seed,
        )
        clf.fit(bundle.transform(x_all[idx]), labels[idx])
        bundle.classifier = clf
        bundle.known_families = families

    raw_train = raw.to_numpy(dtype=float)[train_idx]
    bundle.raw_median = {n: float(v) for n, v in zip(FEATURE_NAMES, np.median(raw_train, axis=0), strict=True)}
    bundle.raw_p99 = {n: float(v) for n, v in zip(FEATURE_NAMES, np.quantile(raw_train, 0.99, axis=0), strict=True)}
    bundle.drift_edges, bundle.drift_expected = _drift_reference(x_all[train_idx], FEATURE_NAMES)

    report = {
        "normal_train_rows": len(train_idx),
        "normal_validation_rows": len(val_idx),
        "known_families": families,
        "member_training_seconds": member_timings,
        "member_params": {m.name: m.params() for m in bundle.members},
        "training_seconds": round(time.perf_counter() - started, 2),
        "thresholds": {
            "anomalous": bundle.threshold_anomalous,
            "unknown": bundle.threshold_unknown,
            "known_confidence": bundle.known_confidence,
        },
    }
    bundle.metadata.update({"training_report": report, "config": config.as_dict()})
    return bundle, report
