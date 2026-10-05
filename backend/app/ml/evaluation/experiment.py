"""Held-out attack family ("unknown attack") experiment.

Protocol
--------
1. Features are extracted over the whole, time-sorted dataset using past-only
   windows (no look-ahead).
2. The timeline is split at `train_fraction`: earlier flows form the training
   period, later flows the test period. Attack episodes are spread across the
   timeline, so each family appears in both periods.
3. Every flow of a *held-out* family is removed from the training period. The
   anomaly members only ever see normal flows; the known-family classifier sees
   normal flows plus the non-held-out ("known") families.
4. Thresholds are set on normal validation flows from the training period.
5. The test period — normal, known families AND held-out families — is scored
   once. Held-out families are, to every model, previously unseen behaviour.

This is a laboratory evaluation of previously unseen attack *behaviour*. It is
not, and cannot be, evidence of discovering a real zero-day vulnerability.
"""

from __future__ import annotations

import logging
import time
from dataclasses import dataclass
from typing import Any

import numpy as np
import pandas as pd

from app.ml.evaluation.metrics import binary_metrics, confusion, detection_latency
from app.ml.features.extractor import extract_features
from app.ml.models.bundle import NORMAL_LABEL, ModelBundle
from app.ml.training.train import TrainingConfig, train_bundle

logger = logging.getLogger(__name__)


@dataclass
class ExperimentResult:
    bundle: ModelBundle
    summary: dict[str, Any]
    confusion_matrix: dict[str, dict[str, int]]
    per_family: dict[str, dict[str, Any]]
    latency: dict[str, Any]


def split_by_time(ts: np.ndarray, train_fraction: float) -> float:
    lo, hi = float(np.min(ts)), float(np.max(ts))
    return lo + (hi - lo) * train_fraction


def evaluate_bundle(
    bundle: ModelBundle,
    features: pd.DataFrame,
    raw: pd.DataFrame,
    labels: np.ndarray,
    ts: np.ndarray,
    episodes: np.ndarray,
    heldout: list[str],
) -> tuple[dict[str, Any], dict[str, dict[str, int]], dict[str, dict[str, Any]], dict[str, Any]]:
    """Score a test set and compute the open-set metric suite."""
    x = features.to_numpy(dtype=float)
    t0 = time.perf_counter()
    pred = bundle.predict(x, raw.to_numpy(dtype=float))
    elapsed = time.perf_counter() - t0
    cls = pred.classification
    flagged = cls != "NORMAL"
    is_attack = labels != NORMAL_LABEL
    is_unknown = np.isin(labels, heldout)
    is_known = is_attack & ~is_unknown
    is_normal = ~is_attack

    # Threshold-free ranking score: anomaly percentile, lifted by a confident known-family match.
    ranking = np.maximum(pred.anomaly_score, pred.family_confidence)
    summary: dict[str, Any] = {
        "rows": len(labels),
        "overall": binary_metrics(is_attack, flagged, ranking),
        "anomaly_detector_only": binary_metrics(
            is_attack, pred.anomaly_score >= bundle.threshold_anomalous, pred.anomaly_score
        ),
        "false_positive_rate": round(float(flagged[is_normal].mean()), 6) if is_normal.any() else None,
    }
    known_mask = is_normal | is_known
    summary["known_attacks"] = binary_metrics(is_attack[known_mask], flagged[known_mask], ranking[known_mask])
    if is_unknown.any():
        unk_mask = is_normal | is_unknown
        unk_cls = cls[is_unknown]
        summary["unknown_attacks"] = {
            **binary_metrics(is_attack[unk_mask], flagged[unk_mask], pred.anomaly_score[unk_mask]),
            "rows": int(is_unknown.sum()),
            "unknown_attack_detection_rate": round(float(np.mean(unk_cls != "NORMAL")), 6),
            "flagged_as_anomalous_or_unknown_rate": round(
                float(np.mean(np.isin(unk_cls, ["ANOMALOUS", "POTENTIAL_UNKNOWN"]))), 6
            ),
            "potential_unknown_rate": round(float(np.mean(unk_cls == "POTENTIAL_UNKNOWN")), 6),
            "misattributed_to_known_family_rate": round(float(np.mean(unk_cls == "KNOWN_ATTACK")), 6),
        }
    else:
        summary["unknown_attacks"] = None

    # Closed-world supervised baseline: the same classifier, argmax, no anomaly model.
    if bundle.classifier is not None:
        z = bundle.transform(x)
        closed = bundle.classifier.predict(z) != NORMAL_LABEL
        summary["supervised_baseline"] = {
            "description": "RandomForest trained on normal + known families; attack if argmax != normal",
            "known_recall": round(float(closed[is_known].mean()), 6) if is_known.any() else None,
            "unknown_recall": round(float(closed[is_unknown].mean()), 6) if is_unknown.any() else None,
            "false_positive_rate": round(float(closed[is_normal].mean()), 6) if is_normal.any() else None,
        }

    per_family: dict[str, dict[str, Any]] = {}
    for fam in sorted(set(labels.tolist()) - {NORMAL_LABEL}):
        m = labels == fam
        c = cls[m]
        per_family[fam] = {
            "group": "unknown" if fam in heldout else "known",
            "rows": int(m.sum()),
            "detection_rate": round(float(np.mean(c != "NORMAL")), 6),
            "as_known_attack": round(float(np.mean(c == "KNOWN_ATTACK")), 6),
            "as_anomalous": round(float(np.mean(c == "ANOMALOUS")), 6),
            "as_potential_unknown": round(float(np.mean(c == "POTENTIAL_UNKNOWN")), 6),
            "mean_anomaly_score": round(float(np.mean(pred.anomaly_score[m])), 6),
        }
        if bundle.classifier is not None:
            per_family[fam]["supervised_baseline_recall"] = round(float(closed[m].mean()), 6)

    if summary["unknown_attacks"] is not None:
        # Row-weighted rates are dominated by high-volume families; the macro
        # average weights every held-out family equally.
        rates = [per_family[f]["detection_rate"] for f in heldout if f in per_family]
        summary["unknown_attacks"]["macro_detection_rate"] = round(float(np.mean(rates)), 6) if rates else None
    known_rates = [v["detection_rate"] for v in per_family.values() if v["group"] == "known"]
    summary["known_macro_detection_rate"] = round(float(np.mean(known_rates)), 6) if known_rates else None

    lat = detection_latency(ts, episodes, flagged)
    known_lat = [
        v["seconds_to_first_detection"]
        for k, v in lat.items()
        if v["seconds_to_first_detection"] is not None and k.rsplit("-", 1)[0] not in heldout
    ]
    unk_lat = [
        v["seconds_to_first_detection"]
        for k, v in lat.items()
        if v["seconds_to_first_detection"] is not None and k.rsplit("-", 1)[0] in heldout
    ]
    latency = {
        "per_episode": lat,
        "episodes_detected": sum(1 for v in lat.values() if v["detected"]),
        "episodes_total": len(lat),
        "median_seconds_known": float(np.median(known_lat)) if known_lat else None,
        "median_seconds_unknown": float(np.median(unk_lat)) if unk_lat else None,
        "inference_ms_per_1000_flows": round(elapsed / max(len(labels), 1) * 1000 * 1000, 3),
    }
    summary["detection_latency"] = {k: v for k, v in latency.items() if k != "per_episode"}
    return summary, confusion(labels, cls), per_family, latency


def run_heldout_experiment(
    frame: pd.DataFrame,
    heldout: list[str],
    config: TrainingConfig | None = None,
    train_fraction: float = 0.6,
) -> ExperimentResult:
    config = config or TrainingConfig()
    frame = frame.sort_values("ts", kind="stable").reset_index(drop=True)
    labels = frame["label"].astype(str).to_numpy()
    unknown_labels = sorted(set(heldout) - set(labels.tolist()))
    if unknown_labels:
        raise ValueError(f"held-out families not present in dataset: {unknown_labels}")

    t0 = time.perf_counter()
    features, raw = extract_features(frame)
    extraction_s = time.perf_counter() - t0
    ts = frame["ts"].to_numpy(dtype=float)
    episodes = frame.get("episode", pd.Series([""] * len(frame))).fillna("").astype(str).to_numpy()

    cut = split_by_time(ts, train_fraction)
    in_train = (ts < cut) & ~np.isin(labels, heldout)
    in_test = ts >= cut

    bundle, train_report = train_bundle(
        features[in_train].reset_index(drop=True),
        raw[in_train].reset_index(drop=True),
        pd.Series(labels[in_train]),
        pd.Series(ts[in_train]),
        config,
    )
    test_idx = np.flatnonzero(in_test)
    summary, cm, per_family, latency = evaluate_bundle(
        bundle, features.iloc[test_idx], raw.iloc[test_idx], labels[test_idx], ts[test_idx], episodes[test_idx], heldout
    )
    summary.update(
        {
            "heldout_families": sorted(heldout),
            "known_families": bundle.known_families,
            "split": {
                "method": "time",
                "train_fraction": train_fraction,
                "cut_ts": cut,
                "train_rows": int(in_train.sum()),
                "test_rows": int(in_test.sum()),
                "heldout_rows_removed_from_train": int(((ts < cut) & np.isin(labels, heldout)).sum()),
            },
            "feature_extraction_seconds": round(extraction_s, 2),
            "training": train_report,
            "disclaimer": (
                "Laboratory evaluation of previously unseen attack behaviour (held-out families). "
                "Not evidence of detecting real zero-day vulnerabilities."
            ),
        }
    )
    bundle.metadata["heldout_families"] = sorted(heldout)
    return ExperimentResult(bundle, summary, cm, per_family, latency)
