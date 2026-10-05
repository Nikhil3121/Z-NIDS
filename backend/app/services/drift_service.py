"""Data-drift monitoring for the active model.

Compares the feature distribution of recent traffic the pipeline classified
NORMAL against the model's training reference (normal traffic). Using only
NORMAL flows measures whether *normal behaviour* has moved away from what the
model learnt — the thing that inflates false positives — rather than flagging
every attack as "drift". Drift raises a MODEL_DRIFT alert; it never retrains
or swaps the production model.
"""

from __future__ import annotations

import logging
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta

from sqlalchemy import select
from sqlalchemy.orm import Session

from app.core.config import get_settings
from app.ml.drift.psi import feature_psi
from app.ml.features.extractor import extract_features
from app.ml.features.registry import FEATURE_NAMES, MAX_LOOKBACK_SECONDS
from app.ml.inference.service import model_cache
from app.models.alert import Alert
from app.models.enums import AlertStatus, AlertType, Classification, Severity
from app.models.ml import DriftReport
from app.models.network_event import NetworkEvent
from app.services.pipeline import _EVENT_COLUMNS, _frame

logger = logging.getLogger(__name__)


@dataclass
class DriftOutcome:
    report: DriftReport | None
    alert: Alert | None
    reason: str


def run_drift_check(db: Session, hours: int = 24, sample: int = 20_000) -> DriftOutcome:
    settings = get_settings()
    active = model_cache.get(db)
    if active is None:
        return DriftOutcome(None, None, "no active model")
    bundle = active.bundle
    if not bundle.drift_edges:
        return DriftOutcome(None, None, "model has no drift reference")
    end = datetime.now(UTC)
    start = end - timedelta(hours=hours)
    rows = db.execute(
        select(*_EVENT_COLUMNS)
        .where(NetworkEvent.ts >= start - timedelta(seconds=MAX_LOOKBACK_SECONDS), NetworkEvent.ts < end)
        .order_by(NetworkEvent.ts.desc())
        .limit(sample * 3)
    ).all()
    frame = _frame(rows)
    if frame.empty:
        return DriftOutcome(None, None, "no recent events")
    normal_ids = set(
        db.scalars(
            select(NetworkEvent.id).where(
                NetworkEvent.id.in_(frame["id"].tolist()),
                NetworkEvent.classification == Classification.NORMAL,
                NetworkEvent.ts >= start,
            )
        ).all()
    )
    features, _ = extract_features(frame)
    mask = frame["id"].isin(normal_ids).to_numpy()
    x = features[FEATURE_NAMES].to_numpy(dtype=float)[mask][:sample]
    if len(x) < settings.drift_min_samples:
        return DriftOutcome(None, None, f"only {len(x)} normal samples (< {settings.drift_min_samples})")
    per_feature = feature_psi(bundle.drift_edges, bundle.drift_expected, FEATURE_NAMES, x)
    max_psi = max(per_feature.values()) if per_feature else 0.0
    drifted = max_psi > settings.drift_psi_threshold
    report = DriftReport(
        model_id=active.model_id,
        window_start=start,
        window_end=end,
        sample_size=len(x),
        threshold=settings.drift_psi_threshold,
        feature_psi=per_feature,
        max_psi=round(max_psi, 6),
        drifted=drifted,
    )
    db.add(report)
    db.flush()
    alert = None
    if drifted:
        top = sorted(per_feature.items(), key=lambda kv: kv[1], reverse=True)[:5]
        key = f"model_drift|{active.model_id}"
        alert = db.scalar(
            select(Alert).where(Alert.dedup_key == key, Alert.status.in_([AlertStatus.OPEN, AlertStatus.ACKNOWLEDGED]))
        )
        description = (
            "Significant feature distribution drift detected for "
            + active.tag
            + ". Top features by PSI: "
            + ", ".join(f"{n}={v:.2f}" for n, v in top)
            + f" (threshold {settings.drift_psi_threshold}). Review before trusting anomaly scores; "
            "retraining requires an explicit training + activation step."
        )
        if alert is None:
            alert = Alert(
                alert_type=AlertType.MODEL_DRIFT,
                title=f"Model drift detected: {active.tag}",
                description=description,
                status=AlertStatus.OPEN,
                severity=Severity.HIGH if max_psi > 2 * settings.drift_psi_threshold else Severity.MEDIUM,
                category="model_drift",
                dedup_key=key,
                risk_score=0.0,
                first_seen=end,
                last_seen=end,
            )
            db.add(alert)
        else:
            alert.last_seen = end
            alert.occurrence_count += 1
            alert.description = description
        db.flush()
        report.alert_id = alert.id
    logger.info(
        "drift check", extra={"model": active.tag, "max_psi": round(max_psi, 4), "drifted": drifted, "samples": len(x)}
    )
    return DriftOutcome(report, alert, "drifted" if drifted else "stable")


def top_features(report: DriftReport, n: int = 10) -> list[tuple[str, float]]:
    return sorted(report.feature_psi.items(), key=lambda kv: kv[1], reverse=True)[:n]


__all__ = ["DriftOutcome", "run_drift_check", "top_features"]
