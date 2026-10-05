"""ML anomaly detector: wraps the active ModelBundle for the live pipeline."""

from __future__ import annotations

from typing import Any

import numpy as np

from app.detection.base import Detector, EventContext, Signal
from app.ml.inference.service import ActiveModel
from app.models.enums import DetectorType, Severity


def anomaly_component(score: float, threshold: float) -> float:
    """Map a calibrated percentile to a 0-100 risk component.

    Below the anomalous threshold the model contributes nothing (a percentile
    is not an attack probability); above it the component rises linearly from
    50 at the threshold to 100 at the most extreme score seen in validation.
    """
    if score < threshold:
        return 0.0
    span = max(1.0 - threshold, 1e-9)
    return float(min(100.0, 50.0 + 50.0 * (score - threshold) / span))


class AnomalyDetector(Detector):
    name = "ml_anomaly_ensemble"
    detector_type = DetectorType.ANOMALY

    def __init__(self, active: ActiveModel | None, features: np.ndarray | None, raw: np.ndarray | None) -> None:
        self.active = active
        self.features = features
        self.raw = raw
        self.scores: np.ndarray | None = None

    def detect_batch(self, contexts: list[EventContext]) -> dict[int, list[Signal]]:
        if self.active is None or self.features is None or self.raw is None or not contexts:
            return {}
        bundle = self.active.bundle
        rows = np.array([c.index for c in contexts])
        pred = bundle.predict(self.features[rows], self.raw[rows])
        self.scores = np.zeros(len(self.features))
        self.scores[rows] = pred.anomaly_score
        out: dict[int, list[Signal]] = {}
        for k, ctx in enumerate(contexts):
            verdict = str(pred.classification[k])
            if verdict == "NORMAL":
                continue
            score = float(pred.anomaly_score[k])
            factors = bundle.explain_row(pred.contributions[k], self.raw[ctx.index])
            for f in factors:
                f["source"] = pred.attribution_method
            if verdict == "KNOWN_ATTACK":
                family = str(pred.family[k])
                conf = float(pred.family_confidence[k])
                out[ctx.index] = [
                    Signal(
                        detector=self.detector_type,
                        category=family,
                        component=max(anomaly_component(score, bundle.threshold_anomalous), 100.0 * conf),
                        confidence=conf,
                        severity=Severity.HIGH,
                        summary=f"Behaviour matches the known '{family}' attack family learned in training "
                        f"(classifier confidence {conf:.0%}).",
                        factors=factors,
                        verdict=verdict,
                        extra={"anomaly_score": score, "family": family, "model": self.active.tag},
                    )
                ]
                continue
            component = anomaly_component(score, bundle.threshold_anomalous)
            unknown = verdict == "POTENTIAL_UNKNOWN"
            out[ctx.index] = [
                Signal(
                    detector=self.detector_type,
                    category="unknown_anomaly",
                    component=component,
                    confidence=score,
                    severity=Severity.HIGH if unknown else Severity.MEDIUM,
                    summary=(
                        "Previously unseen behaviour: this flow is more anomalous than "
                        f"{score:.2%} of normal validation traffic and matches no known attack family."
                    ),
                    factors=factors,
                    verdict=verdict,
                    extra={
                        "anomaly_score": score,
                        "member_scores": {m: float(v[k]) for m, v in pred.member_scores.items()},
                        "attribution_method": pred.attribution_method,
                        "model": self.active.tag,
                    },
                )
            ]
        return out

    def status(self) -> dict[str, Any]:
        if self.active is None:
            return {"name": self.name, "available": False, "reason": "no ACTIVE model in the registry"}
        return {"name": self.name, "available": True, "model": self.active.tag}
