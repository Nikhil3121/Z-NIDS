"""The deployable model bundle and its open-set decision rule.

A bundle contains:
  * a RobustScaler fitted on normal training traffic,
  * one or more anomaly members (trained on normal traffic only),
  * per-member calibrators that turn raw scores into "percentile of normal
    validation traffic" (so members are comparable and thresholds have a
    fixed false-positive meaning),
  * an optional known-family classifier (RandomForest) trained on normal +
    the attack families that were available for training,
  * thresholds chosen on normal *validation* data (never on test data),
  * reference statistics for explanations and drift (PSI) monitoring.

Decision (per flow):
  KNOWN_ATTACK        classifier assigns a known family with p >= known_confidence
  POTENTIAL_UNKNOWN   otherwise, anomaly score >= unknown threshold
  ANOMALOUS           otherwise, anomaly score >= anomalous threshold
  NORMAL              otherwise
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any

import numpy as np
from sklearn.ensemble import RandomForestClassifier
from sklearn.preprocessing import RobustScaler

from app.ml.features.registry import FEATURE_NAMES, FEATURE_VERSION, FEATURES_BY_NAME
from app.ml.models.members import AnomalyMember

CLIP = 50.0
NORMAL_LABEL = "normal"


def _unusual(unit: str, value: float, median: float, p99: float) -> bool:
    if unit == "bool":
        return round(value) != round(median)
    if value > p99 + 1e-9:
        return True
    return median > 0 and (value / median >= 3.0 or value / median <= 1 / 3)


class Calibrator:
    """Maps a raw score to its percentile among normal validation scores."""

    def __init__(self, reference: np.ndarray) -> None:
        self.sorted = np.sort(np.asarray(reference, dtype=float))

    def __call__(self, raw: np.ndarray) -> np.ndarray:
        return np.searchsorted(self.sorted, raw, side="right") / max(len(self.sorted), 1)


@dataclass
class Prediction:
    classification: np.ndarray  # str per row
    anomaly_score: np.ndarray  # [0, 1]
    member_scores: dict[str, np.ndarray]
    family: np.ndarray  # predicted known family or ""
    family_confidence: np.ndarray
    contributions: np.ndarray  # (n, n_features) attribution shares, rows sum to 1
    attribution_method: str


@dataclass
class ModelBundle:
    feature_version: str = FEATURE_VERSION
    feature_names: list[str] = field(default_factory=lambda: list(FEATURE_NAMES))
    scaler: RobustScaler | None = None
    members: list[AnomalyMember] = field(default_factory=list)
    calibrators: dict[str, Calibrator] = field(default_factory=dict)
    ensemble_calibrator: Calibrator | None = None
    classifier: RandomForestClassifier | None = None
    known_families: list[str] = field(default_factory=list)
    threshold_anomalous: float = 0.995
    threshold_unknown: float = 0.999
    known_confidence: float = 0.8
    # Explanation references (raw units, normal training traffic).
    raw_median: dict[str, float] = field(default_factory=dict)
    raw_p99: dict[str, float] = field(default_factory=dict)
    # Drift reference: per-feature quantile bin edges and expected proportions.
    drift_edges: dict[str, list[float]] = field(default_factory=dict)
    drift_expected: dict[str, list[float]] = field(default_factory=dict)
    metadata: dict[str, Any] = field(default_factory=dict)

    # -- helpers ------------------------------------------------------------

    def transform(self, x: np.ndarray) -> np.ndarray:
        if self.scaler is None:
            raise RuntimeError("bundle is not fitted")
        return np.clip(self.scaler.transform(x), -CLIP, CLIP)

    def check_features(self, names: list[str], version: str) -> None:
        if version != self.feature_version or names != self.feature_names:
            raise ValueError(f"feature mismatch: model expects {self.feature_version}, got {version}")

    # -- inference ----------------------------------------------------------

    def predict(self, features: np.ndarray, raw: np.ndarray | None = None) -> Prediction:
        z = self.transform(features)
        n = len(z)
        member_scores: dict[str, np.ndarray] = {}
        for member in self.members:
            member_scores[member.name] = self.calibrators[member.name](member.score(z))
        mean_pct = np.mean(np.vstack(list(member_scores.values())), axis=0) if member_scores else np.zeros(n)
        score = self.ensemble_calibrator(mean_pct) if self.ensemble_calibrator else mean_pct

        family = np.full(n, "", dtype=object)
        fam_conf = np.zeros(n)
        if self.classifier is not None and len(self.known_families):
            proba = self.classifier.predict_proba(z)
            classes = list(self.classifier.classes_)
            attack_idx = [i for i, c in enumerate(classes) if c != NORMAL_LABEL]
            if attack_idx:
                sub = proba[:, attack_idx]
                best = sub.argmax(axis=1)
                fam_conf = sub[np.arange(n), best]
                family = np.array([classes[attack_idx[b]] for b in best], dtype=object)

        cls = np.full(n, "NORMAL", dtype=object)
        cls[score >= self.threshold_anomalous] = "ANOMALOUS"
        cls[score >= self.threshold_unknown] = "POTENTIAL_UNKNOWN"
        known = fam_conf >= self.known_confidence
        cls[known] = "KNOWN_ATTACK"
        family = np.where(known, family, "")

        contributions, method = self._contributions(z)
        return Prediction(cls, score, member_scores, family, fam_conf, contributions, method)

    def _contributions(self, z: np.ndarray) -> tuple[np.ndarray, str]:
        for member in self.members:
            if member.provides_attribution:
                contrib = member.feature_contributions(z)
                if contrib is not None:
                    return contrib, f"{member.name}_reconstruction_error"
        # Model-agnostic fallback: share of |robust z| — deviation from the
        # normal training distribution, not an attribution of any one model.
        dev = np.abs(z)
        total = dev.sum(axis=1, keepdims=True)
        return np.divide(dev, total, out=np.zeros_like(dev), where=total > 0), "robust_z_deviation"

    def explain_row(self, contributions: np.ndarray, raw_row: np.ndarray, top_k: int = 5) -> list[dict[str, Any]]:
        """Top contributing features for one flow, in human units."""
        order = np.argsort(contributions)[::-1][:top_k]
        factors: list[dict[str, Any]] = []
        for idx in order:
            share = float(contributions[idx])
            if share < 0.02:
                break
            name = self.feature_names[idx]
            spec = FEATURES_BY_NAME[name]
            value = float(raw_row[idx])
            typical = float(self.raw_median.get(name, 0.0))
            p99 = float(self.raw_p99.get(name, 0.0))
            ratio = value / typical if typical > 0 else None
            if not _unusual(spec.unit, value, typical, p99):
                continue  # a contribution share alone is not a reason; show only out-of-range values
            if spec.unit == "bool":
                detail = f"{spec.label}: {'present' if value >= 0.5 else 'absent'} (normal traffic median: {typical:g})"
            elif ratio is not None and ratio >= 1.5:
                detail = f"{spec.label}: {value:,.3g} {spec.unit} — {ratio:.1f}× the normal median ({typical:,.3g})"
            else:
                detail = f"{spec.label}: {value:,.3g} {spec.unit} (normal median {typical:,.3g}, 99th pct {p99:,.3g})"
            factors.append(
                {
                    "feature": name,
                    "label": spec.label,
                    "value": value,
                    "normal_median": typical,
                    "normal_p99": p99,
                    "ratio_to_median": ratio,
                    "exceeds_normal_p99": value > p99 if spec.unit != "bool" else None,
                    "contribution": round(share, 4),
                    "detail": detail.strip(),
                }
            )
        if not factors:
            factors.append({
                "feature": "feature_combination",
                "label": "Combination of features",
                "value": None,
                "contribution": None,
                "detail": "No single feature is outside its normal range; the flow is unusual only as a "
                "combination of features, so treat this detection with extra caution.",
            })
        return factors
