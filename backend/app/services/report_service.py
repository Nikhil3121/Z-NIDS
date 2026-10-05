"""Security reports generated from stored platform data (JSON + Markdown)."""

from __future__ import annotations

from datetime import datetime
from typing import Any

from sqlalchemy import func, select
from sqlalchemy.orm import Session

from app.models.alert import Alert
from app.models.detection import Detection, MitreMapping, MitreTechnique
from app.models.enums import Classification, ModelStatus
from app.models.incident import Incident
from app.models.ml import MLModel, ModelEvaluation
from app.models.network_event import EventRollup
from app.models.response import ResponseAction


def build_report(db: Session, start: datetime, end: datetime, include_demo: bool) -> dict[str, Any]:
    demo_ok = (lambda col: col.is_(False)) if not include_demo else (lambda col: col.isnot(None))
    events = db.execute(
        select(
            func.coalesce(func.sum(EventRollup.events), 0),
            func.coalesce(func.sum(EventRollup.normal), 0),
            func.coalesce(func.sum(EventRollup.anomalous), 0),
            func.coalesce(func.sum(EventRollup.known_attack), 0),
            func.coalesce(func.sum(EventRollup.potential_unknown), 0),
        ).where(EventRollup.bucket >= start, EventRollup.bucket < end, demo_ok(EventRollup.is_demo))
    ).one()
    incidents = db.scalars(
        select(Incident)
        .where(Incident.created_at >= start, Incident.created_at < end, demo_ok(Incident.is_demo))
        .order_by(Incident.risk_score.desc())
    ).all()
    alert_sev = dict(
        db.execute(
            select(Alert.severity, func.count())
            .where(Alert.first_seen >= start, Alert.first_seen < end, demo_ok(Alert.is_demo))
            .group_by(Alert.severity)
        ).all()
    )
    alert_cat = db.execute(
        select(Alert.category, func.count())
        .where(Alert.first_seen >= start, Alert.first_seen < end, demo_ok(Alert.is_demo))
        .group_by(Alert.category)
        .order_by(func.count().desc())
    ).all()
    attackers = db.execute(
        select(Detection.src_ip, func.count(), func.max(Detection.risk_score))
        .where(Detection.ts >= start, Detection.ts < end, demo_ok(Detection.is_demo))
        .group_by(Detection.src_ip)
        .order_by(func.max(Detection.risk_score).desc())
        .limit(10)
    ).all()
    techniques = db.execute(
        select(MitreTechnique.technique_id, MitreTechnique.name, func.count(), func.max(MitreMapping.confidence))
        .join(MitreMapping, MitreMapping.technique_id == MitreTechnique.technique_id)
        .join(Detection, Detection.id == MitreMapping.detection_id)
        .where(Detection.ts >= start, Detection.ts < end, demo_ok(Detection.is_demo))
        .group_by(MitreTechnique.technique_id, MitreTechnique.name)
        .order_by(func.count().desc())
    ).all()
    responses = db.execute(
        select(ResponseAction.action_type, ResponseAction.status, func.count())
        .where(ResponseAction.created_at >= start, ResponseAction.created_at < end)
        .group_by(ResponseAction.action_type, ResponseAction.status)
    ).all()
    active = db.scalar(select(MLModel).where(MLModel.status == ModelStatus.ACTIVE))
    evaluation = (
        db.scalar(
            select(ModelEvaluation)
            .where(ModelEvaluation.model_id == active.id)
            .order_by(ModelEvaluation.created_at.desc())
            .limit(1)
        )
        if active
        else None
    )
    unknown_incidents = [i for i in incidents if i.classification == Classification.POTENTIAL_UNKNOWN]
    return {
        "period": {"start": start, "end": end},
        "includes_demo_data": include_demo,
        "events": {
            "total": int(events[0]),
            "normal": int(events[1]),
            "anomalous": int(events[2]),
            "known_attack": int(events[3]),
            "potential_unknown": int(events[4]),
        },
        "alerts": {
            "by_severity": {getattr(k, "value", k): int(v) for k, v in alert_sev.items()},
            "by_category": [{"category": c, "count": int(n)} for c, n in alert_cat],
        },
        "incidents": {
            "total": len(incidents),
            "resolved": sum(1 for i in incidents if i.resolved_at is not None),
            "potential_unknown": len(unknown_incidents),
            "items": [
                {
                    "reference": i.reference,
                    "title": i.title,
                    "severity": i.severity.value,
                    "status": i.status.value,
                    "risk_score": i.risk_score,
                    "classification": i.classification.value if i.classification else None,
                    "resolution": i.resolution.value if i.resolution else None,
                }
                for i in incidents[:50]
            ],
        },
        "top_sources": [{"ip": str(ip), "detections": int(n), "max_risk": float(r)} for ip, n, r in attackers],
        "mitre_techniques": [
            {"technique_id": t, "name": n, "detections": int(c), "max_confidence": float(mc)}
            for t, n, c, mc in techniques
        ],
        "response_actions": [{"action": a.value, "status": s.value, "count": int(c)} for a, s, c in responses],
        "model": (
            None
            if active is None
            else {
                "tag": active.tag,
                "trained_at": active.trained_at,
                "dataset": active.training_dataset,
                "headline_metrics": active.metrics,
                "latest_evaluation_synthetic": evaluation.is_synthetic if evaluation else None,
            }
        ),
    }


def to_markdown(report: dict[str, Any]) -> str:
    p = report["period"]
    lines = ["# Z-NIDS security report", "", f"Period: {p['start']:%Y-%m-%d %H:%M} → {p['end']:%Y-%m-%d %H:%M} UTC", ""]
    if report["includes_demo_data"]:
        lines += ["> **Includes LAB / DEMO data** (synthetic telemetry).", ""]
    e = report["events"]
    lines += [
        "## Traffic",
        "",
        f"* Flows analysed: {e['total']:,}",
        f"* Known attack: {e['known_attack']:,} · Anomalous: {e['anomalous']:,} · "
        f"Potential unknown: {e['potential_unknown']:,}",
        "",
    ]
    lines += ["## Alerts by severity", ""] + [f"* {k}: {v}" for k, v in report["alerts"]["by_severity"].items()] + [""]
    inc = report["incidents"]
    lines += [
        "## Incidents",
        "",
        f"{inc['total']} opened, {inc['resolved']} resolved, "
        f"{inc['potential_unknown']} classified as potential unknown attacks.",
        "",
        "| Ref | Title | Severity | Status | Risk |",
        "|---|---|---|---|---|",
    ]
    lines += [
        f"| {i['reference']} | {i['title']} | {i['severity']} | {i['status']} | {i['risk_score']:.0f} |"
        for i in inc["items"]
    ]
    lines += [
        "",
        "## MITRE ATT&CK hypotheses",
        "",
        "| Technique | Name | Detections | Max confidence |",
        "|---|---|---|---|",
    ]
    lines += [
        f"| {t['technique_id']} | {t['name']} | {t['detections']} | {t['max_confidence']:.2f} |"
        for t in report["mitre_techniques"]
    ]
    m = report["model"]
    lines += ["", "## Detection model", ""]
    lines += [
        (
            "No active anomaly model."
            if m is None
            else f"Active: `{m['tag']}` trained on `{m['dataset']}`"
            + (" (synthetic lab data)" if m.get("latest_evaluation_synthetic") else "")
        )
    ]
    return "\n".join(lines) + "\n"
