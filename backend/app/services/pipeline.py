"""The detection pipeline — one batch of PENDING events end to end.

    load batch + look-back context  →  feature extraction (same code as training)
    →  detectors (signature | ML anomaly | behavioural | threat intel)
    →  verdict + transparent risk  →  detections + MITRE hypotheses
    →  alerts (deduplicated)  →  correlation / incidents
    →  rollups, asset risk  →  commit  →  real-time events, notifications, response proposals

Processing is idempotent per event: only PENDING rows are claimed (SKIP LOCKED),
so concurrent workers never double-process an event.
"""

from __future__ import annotations

import logging
import time
from collections import defaultdict
from dataclasses import dataclass, field
from datetime import UTC, datetime, timedelta
from typing import Any

import numpy as np
import pandas as pd
from sqlalchemy import bindparam, or_, select, update
from sqlalchemy.dialects.postgresql import insert as pg_insert
from sqlalchemy.orm import Session

from app.core.config import get_settings
from app.core.metrics import DETECTION_LATENCY, EVENTS_PROCESSED, PIPELINE_LATENCY
from app.detection.anomaly.detector import AnomalyDetector
from app.detection.base import EventContext, Signal
from app.detection.behavioral.baseline import BaselineStore, BehavioralDetector, BehaviorConfig
from app.detection.signatures.engine import SignatureDetector
from app.integrations.mitre.catalog import map_detection
from app.ml.features.extractor import extract_features
from app.ml.features.registry import FEATURE_NAMES, MAX_LOOKBACK_SECONDS
from app.ml.inference.service import model_cache
from app.models.alert import Alert
from app.models.detection import Detection, MitreMapping
from app.models.enums import (
    AlertStatus,
    Classification,
    Criticality,
    DetectorType,
    ProcessingStatus,
    Severity,
)
from app.models.network_event import EventRollup, NetworkEvent
from app.services import asset_service
from app.services.alert_service import AlertBatcher
from app.services.incident_service import CorrelationEngine
from app.services.risk_service import compute_risk, get_weights
from app.services.threat_intel_service import ThreatIntelDetector
from app.websocket.events import RealtimeEvent, publish_many

logger = logging.getLogger(__name__)

_signature_detector: SignatureDetector | None = None


def signature_detector() -> SignatureDetector:
    global _signature_detector
    if _signature_detector is None:
        _signature_detector = SignatureDetector.from_file(get_settings().signature_rules_path)
    return _signature_detector


def reload_signatures() -> SignatureDetector:
    global _signature_detector
    _signature_detector = SignatureDetector.from_file(get_settings().signature_rules_path)
    return _signature_detector


_EVENT_COLUMNS = [
    NetworkEvent.id,
    NetworkEvent.ts,
    NetworkEvent.src_ip,
    NetworkEvent.dst_ip,
    NetworkEvent.src_port,
    NetworkEvent.dst_port,
    NetworkEvent.protocol,
    NetworkEvent.app_protocol,
    NetworkEvent.duration_ms,
    NetworkEvent.packets_out,
    NetworkEvent.packets_in,
    NetworkEvent.bytes_out,
    NetworkEvent.bytes_in,
    NetworkEvent.tcp_flags,
    NetworkEvent.conn_state,
    NetworkEvent.direction,
    NetworkEvent.is_demo,
    NetworkEvent.external_alert,
]


def _frame(rows: list[Any]) -> pd.DataFrame:
    df = pd.DataFrame([r._asdict() for r in rows])
    if df.empty:
        return df
    df["ts_dt"] = df["ts"]
    df["ts"] = df["ts"].map(lambda t: t.timestamp())
    for col in ("src_ip", "dst_ip"):
        df[col] = df[col].astype(str)
    for col in ("protocol", "direction"):
        df[col] = df[col].map(lambda v: v.value if hasattr(v, "value") else str(v))
    df["dst_port"] = df["dst_port"].fillna(-1)
    return df


@dataclass
class BatchResult:
    processed: int = 0
    detections: int = 0
    alerts_created: int = 0
    incidents_created: int = 0
    by_classification: dict[str, int] = field(default_factory=dict)
    realtime: list[tuple[RealtimeEvent, dict[str, Any]]] = field(default_factory=list)
    new_alert_ids: list[int] = field(default_factory=list)
    new_incident_ids: list[int] = field(default_factory=list)
    escalated_incident_ids: list[int] = field(default_factory=list)


def _claim(db: Session, event_ids: list[int]) -> list[Any]:
    """Lock the still-PENDING events of the batch (others are skipped)."""
    return list(
        db.execute(
            select(*_EVENT_COLUMNS)
            .where(NetworkEvent.id.in_(event_ids), NetworkEvent.processing_status == ProcessingStatus.PENDING)
            .order_by(NetworkEvent.ts, NetworkEvent.id)
            .with_for_update(skip_locked=True)
        ).all()
    )


def _context(db: Session, batch: pd.DataFrame) -> pd.DataFrame:
    """Earlier flows from the same sources/destinations within the look-back window."""
    start = batch["ts_dt"].min() - timedelta(seconds=MAX_LOOKBACK_SECONDS)
    end = batch["ts_dt"].max()
    batch_ids = batch["id"].tolist()
    srcs = sorted(set(batch["src_ip"]))
    dsts = sorted(set(batch["dst_ip"]))
    rows = db.execute(
        select(*_EVENT_COLUMNS).where(
            NetworkEvent.ts >= start,
            NetworkEvent.ts <= end,
            or_(NetworkEvent.src_ip.in_(srcs), NetworkEvent.dst_ip.in_(dsts)),
            NetworkEvent.id.notin_(batch_ids),
        )
    ).all()
    return _frame(rows)


def _values_row(batch_row: pd.Series, raw_row: pd.Series) -> dict[str, Any]:
    values = raw_row.to_dict()
    values.update(
        {
            "dst_port": None if batch_row["dst_port"] < 0 else int(batch_row["dst_port"]),
            "protocol": batch_row["protocol"],
            "direction": batch_row["direction"],
            "app_protocol": batch_row["app_protocol"],
            "conn_state": batch_row["conn_state"],
        }
    )
    return values


def _verdict(signals: list[Signal], strong_behavior: float) -> tuple[Classification, Signal | None]:
    """Combine detector verdicts into the platform classification.

    Known evidence (signature, known-family model, malicious indicator) wins;
    otherwise ML POTENTIAL_UNKNOWN — or an ML anomaly corroborated by a strong
    behavioural deviation — becomes Potential Unknown Attack.
    """
    if not signals:
        return Classification.NORMAL, None
    known = [s for s in signals if s.verdict == "KNOWN_ATTACK"]
    if known:
        return Classification.KNOWN_ATTACK, max(known, key=lambda s: (s.component, s.confidence))
    ml = [s for s in signals if s.detector == DetectorType.ANOMALY]
    behavioral = [s for s in signals if s.detector == DetectorType.BEHAVIORAL]
    strong = any(s.component >= strong_behavior for s in behavioral)
    if any(s.verdict == "POTENTIAL_UNKNOWN" for s in ml) or (ml and strong):
        return Classification.POTENTIAL_UNKNOWN, ml[0]
    primary = max(signals, key=lambda s: s.component)
    return Classification.ANOMALOUS, primary


def _correlation_components(db: Session, ips: list[str], now: datetime) -> dict[str, float]:
    """Prior-activity context per IP: alerts in the last 24h, capped at 100."""
    if not ips:
        return {}
    rows = db.execute(
        select(Alert.src_ip, Alert.dst_ip).where(
            Alert.last_seen >= now - timedelta(hours=24),
            Alert.status.in_([AlertStatus.OPEN, AlertStatus.ACKNOWLEDGED]),
            or_(Alert.src_ip.in_(ips), Alert.dst_ip.in_(ips)),
        )
    ).all()
    counts: dict[str, int] = defaultdict(int)
    for src, dst in rows:
        if src is not None:
            counts[str(src)] += 1
        if dst is not None and str(dst) != str(src):
            counts[str(dst)] += 1
    return {ip: min(100.0, 25.0 * n) for ip, n in counts.items()}


def process_events(db: Session, event_ids: list[int]) -> BatchResult:
    """Process one batch; commits on success. Safe to call concurrently."""
    started = time.perf_counter()
    settings = get_settings()
    result = BatchResult()
    rows = _claim(db, event_ids)
    if not rows:
        db.rollback()
        return result
    batch = _frame(rows)
    try:
        return _process(db, batch, result, started, settings)
    except Exception:
        db.rollback()
        logger.exception("pipeline batch failed", extra={"events": len(batch)})
        # Mark the batch FAILED in a clean transaction so it is visible, not silently retried forever.
        db.execute(
            update(NetworkEvent)
            .where(
                NetworkEvent.id.in_(batch["id"].tolist()), NetworkEvent.processing_status == ProcessingStatus.PENDING
            )
            .values(processing_status=ProcessingStatus.FAILED, processed_at=datetime.now(UTC))
        )
        db.commit()
        raise


def _process(db: Session, batch: pd.DataFrame, result: BatchResult, started: float, settings: Any) -> BatchResult:
    now = datetime.now(UTC)
    weights = get_weights()
    context = _context(db, batch)
    combined = (
        pd.concat([batch.assign(_in_batch=True), context.assign(_in_batch=False)], ignore_index=True)
        if not context.empty
        else batch.assign(_in_batch=True)
    )
    features, raw = extract_features(combined)
    in_batch = combined["_in_batch"].to_numpy(dtype=bool)
    idx = np.flatnonzero(in_batch)

    # Assets for every endpoint in the batch.
    seen: dict[str, tuple[datetime, bool]] = {}
    for r in batch.itertuples():
        for ip in (r.src_ip, r.dst_ip):
            prev = seen.get(ip)
            if prev is None or r.ts_dt > prev[0]:
                seen[ip] = (r.ts_dt, bool(r.is_demo))
    assets = asset_service.touch_internal_assets(db, seen)

    contexts: list[EventContext] = []
    for k in idx:
        row = combined.iloc[k]
        contexts.append(
            EventContext(
                index=int(k),
                event_id=int(row["id"]),
                ts=float(row["ts"]),
                src_ip=row["src_ip"],
                dst_ip=row["dst_ip"],
                src_port=None if pd.isna(row["src_port"]) else int(row["src_port"]),
                dst_port=None if row["dst_port"] < 0 else int(row["dst_port"]),
                protocol=row["protocol"],
                app_protocol=row["app_protocol"],
                direction=row["direction"],
                external_alert=row["external_alert"] if isinstance(row["external_alert"], dict) else None,
                values=_values_row(row, raw.iloc[k]),
            )
        )

    active = model_cache.get(db)
    anomaly = AnomalyDetector(
        active, features[FEATURE_NAMES].to_numpy(dtype=float), raw[FEATURE_NAMES].to_numpy(dtype=float)
    )
    bcfg = weights.behavioral
    behavioral = BehavioralDetector(
        BaselineStore.load(db, sorted({c.src_ip for c in contexts})),
        BehaviorConfig(
            min_observations=settings.baseline_min_observations,
            z_threshold=bcfg.get("z_threshold", 3.0),
            min_ratio=bcfg.get("min_ratio", 2.0),
            scale=bcfg.get("scale", 5.0),
            strong_component=bcfg.get("strong_component", 60.0),
        ),
    )
    detectors = [signature_detector(), anomaly, behavioral, ThreatIntelDetector(db)]
    signals: dict[int, list[Signal]] = defaultdict(list)
    for detector in detectors:
        for i, sigs in detector.detect_batch(contexts).items():
            signals[i].extend(sigs)
    scores = anomaly.scores

    corr = _correlation_components(db, sorted(seen), now)
    event_updates: list[dict[str, Any]] = []
    detections: list[tuple[Detection, EventContext]] = []
    asset_risk: dict[int, float] = {}
    rollups: dict[tuple[datetime, bool], dict[str, int]] = {}
    strong = bcfg.get("strong_component", 60.0)

    for ctx in contexts:
        sigs = signals.get(ctx.index, [])
        classification, primary = _verdict(sigs, strong)
        anomaly_score = float(scores[ctx.index]) if scores is not None else None
        risk_value: float | None = None
        is_demo = bool(combined.iloc[ctx.index]["is_demo"])
        if primary is not None:
            comp = {"signature": 0.0, "anomaly": 0.0, "behavioral": 0.0, "threat_intel": 0.0}
            for s in sigs:
                key = s.detector.value
                comp[key] = max(comp[key], s.component)
            involved = [a for a in (assets.get(ctx.src_ip), assets.get(ctx.dst_ip)) if a is not None]
            criticality = max((Criticality(a.criticality).score for a in involved), default=None)
            correlation = max(corr.get(ctx.src_ip, 0.0), corr.get(ctx.dst_ip, 0.0))
            risk = compute_risk(comp, criticality, correlation, weights)
            risk_value = risk.score
            fired = sorted({s.detector.value for s in sigs})
            factors: list[dict[str, Any]] = []
            for s in sorted(sigs, key=lambda s: s.component, reverse=True):
                factors.extend(s.factors)
            model_sig = next((s for s in sigs if s.detector == DetectorType.ANOMALY), None)
            category = primary.category
            if classification == Classification.POTENTIAL_UNKNOWN:
                category = "unknown_anomaly"
            severity = Severity.from_risk(risk.score)
            # A matched signature carries the severity its author assigned; risk can raise it, never lower it.
            for s in sigs:
                if s.detector == DetectorType.SIGNATURE and Severity(s.severity).rank > severity.rank:
                    severity = Severity(s.severity)
            if classification == Classification.POTENTIAL_UNKNOWN and severity.rank < Severity.MEDIUM.rank:
                severity = Severity.MEDIUM
            summary = primary.summary
            if classification == Classification.POTENTIAL_UNKNOWN:
                summary = "Potential Unknown Attack — " + summary
            det = Detection(
                event_id=ctx.event_id,
                ts=datetime.fromtimestamp(ctx.ts, UTC),
                classification=classification,
                category=category,
                detector=primary.detector,
                detectors_fired=fired,
                src_ip=ctx.src_ip,
                src_port=ctx.src_port,
                dst_ip=ctx.dst_ip,
                dst_port=ctx.dst_port,
                protocol=ctx.protocol,
                anomaly_score=anomaly_score,
                confidence=round(float(primary.confidence), 4),
                severity=severity,
                risk_score=risk.score,
                risk_components={**risk.components, "reason": risk.reason},
                explanation=factors[:12],
                summary=summary[:2000],
                rule_id=next((s.rule_id for s in sigs if s.rule_id), None),
                model_version=active.tag if active else None,
                predicted_family=(model_sig.extra.get("family") if model_sig else None),
                is_demo=is_demo,
            )
            detections.append((det, ctx))
            for a in involved:
                asset_risk[a.id] = max(asset_risk.get(a.id, 0.0), risk.score)
        event_updates.append(
            {"b_id": ctx.event_id, "b_cls": classification, "b_anom": anomaly_score, "b_risk": risk_value}
        )
        result.by_classification[classification.value] = result.by_classification.get(classification.value, 0) + 1
        bucket = datetime.fromtimestamp(ctx.ts - ctx.ts % 60, UTC)
        r = rollups.setdefault((bucket, is_demo), defaultdict(int))
        row = combined.iloc[ctx.index]
        r["events"] += 1
        r["bytes"] += int(row["bytes_in"] + row["bytes_out"])
        r["packets"] += int(row["packets_in"] + row["packets_out"])
        r[
            {
                "NORMAL": "normal",
                "ANOMALOUS": "anomalous",
                "KNOWN_ATTACK": "known_attack",
                "POTENTIAL_UNKNOWN": "potential_unknown",
            }[classification.value]
        ] += 1

    # Persist event verdicts in one executemany.
    db.execute(
        update(NetworkEvent.__table__)
        .where(NetworkEvent.__table__.c.id == bindparam("b_id"))
        .values(
            classification=bindparam("b_cls"),
            anomaly_score=bindparam("b_anom"),
            risk_score=bindparam("b_risk"),
            processing_status=ProcessingStatus.PROCESSED,
            processed_at=now,
        ),
        event_updates,
    )

    # Detections + MITRE hypotheses.
    if detections:
        db.add_all([d for d, _ in detections])
        db.flush()
        for det, ctx in detections:
            for hyp in map_detection(det.category, det.confidence, ctx.values, ctx.direction):
                db.add(
                    MitreMapping(
                        detection_id=det.id,
                        technique_id=hyp.technique_id,
                        confidence=round(min(hyp.confidence, 0.95), 3),
                        evidence=hyp.evidence,
                    )
                )
    result.detections = len(detections)

    # Alerts (dedup) and correlation.
    batcher = AlertBatcher(db)
    min_risk = settings.alert_min_risk
    for det, _ in detections:
        if det.risk_score >= min_risk or det.classification in (
            Classification.KNOWN_ATTACK,
            Classification.POTENTIAL_UNKNOWN,
        ):
            batcher.add(det)
    db.flush()
    batcher.flush_links()
    changed_alerts = [c.alert for c in batcher.changes.values()]
    incident_changes = CorrelationEngine(db).process(changed_alerts) if changed_alerts else {}

    asset_service.bump_risk(db, asset_risk)
    _upsert_rollups(db, rollups)
    db.commit()

    # --- after commit: real-time + follow-ups -------------------------------
    for change in batcher.changes.values():
        a = change.alert
        payload = {
            "id": a.id,
            "title": a.title,
            "severity": a.severity.value,
            "status": a.status.value,
            "classification": a.classification.value if a.classification else None,
            "category": a.category,
            "src_ip": str(a.src_ip) if a.src_ip else None,
            "dst_ip": str(a.dst_ip) if a.dst_ip else None,
            "risk_score": a.risk_score,
            "occurrence_count": a.occurrence_count,
            "incident_id": a.incident_id,
            "is_demo": a.is_demo,
        }
        result.realtime.append(
            (RealtimeEvent.ALERT_CREATED if change.created else RealtimeEvent.ALERT_UPDATED, payload)
        )
        if change.created:
            result.new_alert_ids.append(a.id)
            result.alerts_created += 1
    for inc_change in incident_changes.values():
        inc = inc_change.incident
        payload = {
            "id": inc.id,
            "reference": inc.reference,
            "title": inc.title,
            "severity": inc.severity.value,
            "status": inc.status.value,
            "risk_score": inc.risk_score,
            "classification": inc.classification.value if inc.classification else None,
            "is_demo": inc.is_demo,
        }
        result.realtime.append(
            (RealtimeEvent.INCIDENT_CREATED if inc_change.created else RealtimeEvent.INCIDENT_UPDATED, payload)
        )
        if inc_change.created:
            result.new_incident_ids.append(inc.id)
            result.incidents_created += 1
        elif inc_change.escalated_from is not None:
            result.escalated_incident_ids.append(inc.id)
    result.realtime.append(
        (
            RealtimeEvent.NETWORK_EVENTS_PROCESSED,
            {
                "count": len(contexts),
                "by_classification": result.by_classification,
                "detections": result.detections,
                "demo": bool(batch["is_demo"].any()),
            },
        )
    )
    publish_many(result.realtime)

    result.processed = len(contexts)
    for cls_name, n in result.by_classification.items():
        EVENTS_PROCESSED.labels(classification=cls_name).inc(n)
    elapsed = time.perf_counter() - started
    PIPELINE_LATENCY.observe(elapsed)
    newest = batch["ts"].max()
    DETECTION_LATENCY.observe(max(0.0, time.time() - float(newest)))
    logger.info(
        "pipeline batch processed",
        extra={
            "events": result.processed,
            "detections": result.detections,
            "alerts_created": result.alerts_created,
            "incidents_created": result.incidents_created,
            "seconds": round(elapsed, 3),
            "model": active.tag if active else None,
        },
    )
    _follow_up(result)
    return result


def _upsert_rollups(db: Session, rollups: dict[tuple[datetime, bool], dict[str, int]]) -> None:
    if not rollups:
        return
    rows = [{"bucket": b, "is_demo": d, **{k: int(v) for k, v in c.items()}} for (b, d), c in rollups.items()]
    cols = ("events", "bytes", "packets", "normal", "anomalous", "known_attack", "potential_unknown")
    for row in rows:
        for c in cols:
            row.setdefault(c, 0)
    stmt = pg_insert(EventRollup).values(rows)
    stmt = stmt.on_conflict_do_update(
        index_elements=[EventRollup.bucket, EventRollup.is_demo],
        set_={c: getattr(EventRollup, c) + getattr(stmt.excluded, c) for c in cols},
    )
    db.execute(stmt)


def _follow_up(result: BatchResult) -> None:
    """Queue notifications, TI enrichment and response proposals (never inline)."""
    if not (result.new_alert_ids or result.new_incident_ids or result.escalated_incident_ids):
        return
    from app.workers.tasks.followup import handle_new_alerts, handle_new_incidents

    try:
        if result.new_alert_ids:
            handle_new_alerts.delay(result.new_alert_ids)
        if result.new_incident_ids or result.escalated_incident_ids:
            handle_new_incidents.delay(result.new_incident_ids, result.escalated_incident_ids)
    except Exception:
        # The alerts/incidents are committed; a broker outage only delays follow-up work.
        logger.exception("failed to enqueue follow-up tasks")


def pending_event_ids(db: Session, limit: int = 5000, older_than_seconds: int = 0) -> list[int]:
    stmt = select(NetworkEvent.id).where(NetworkEvent.processing_status == ProcessingStatus.PENDING)
    if older_than_seconds:
        stmt = stmt.where(NetworkEvent.ingested_at < datetime.now(UTC) - timedelta(seconds=older_than_seconds))
    return list(db.scalars(stmt.order_by(NetworkEvent.id).limit(limit)).all())


__all__ = ["BatchResult", "pending_event_ids", "process_events", "reload_signatures", "signature_detector"]
