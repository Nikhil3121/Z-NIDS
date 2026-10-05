"""/api/v1/dashboard — SOC overview computed from stored data (rollups + indexed queries)."""

from __future__ import annotations

from datetime import UTC, datetime, timedelta
from typing import Annotated, Any

from fastapi import APIRouter, Depends, Query
from sqlalchemy import func, select, true

from app.api.deps import DbSession, require
from app.models.alert import Alert
from app.models.asset import Asset
from app.models.detection import Detection
from app.models.enums import AlertStatus, AssetStatus, Classification, IncidentStatus, Permission, ResponseStatus
from app.models.incident import Incident
from app.models.network_event import EventRollup, NetworkEvent
from app.models.response import LabBlocklistEntry, ResponseAction
from app.models.user import User

router = APIRouter(prefix="/dashboard", tags=["dashboard"])
Viewer = Annotated[User, Depends(require(Permission.VIEW_EVENTS, Permission.VIEW_ALERTS))]


def _demo_filter(col: Any, demo: bool | None) -> Any:
    return true() if demo is None else col.is_(demo)


@router.get("/overview")
def overview(
    db: DbSession,
    _: Viewer,
    hours: int = Query(24, ge=1, le=24 * 30),
    demo: bool | None = None,
) -> dict[str, Any]:
    now = datetime.now(UTC)
    since = now - timedelta(hours=hours)

    roll = db.execute(
        select(
            func.coalesce(func.sum(EventRollup.events), 0),
            func.coalesce(func.sum(EventRollup.bytes), 0),
            func.coalesce(func.sum(EventRollup.normal), 0),
            func.coalesce(func.sum(EventRollup.anomalous), 0),
            func.coalesce(func.sum(EventRollup.known_attack), 0),
            func.coalesce(func.sum(EventRollup.potential_unknown), 0),
        ).where(EventRollup.bucket >= since, _demo_filter(EventRollup.is_demo, demo))
    ).one()
    events, volume, normal, anomalous, known, unknown = (int(v) for v in roll)

    active_incidents = (
        db.scalar(
            select(func.count())
            .select_from(Incident)
            .where(Incident.status != IncidentStatus.RESOLVED, _demo_filter(Incident.is_demo, demo))
        )
        or 0
    )
    open_alerts = dict(
        db.execute(
            select(Alert.severity, func.count())
            .where(Alert.status.in_([AlertStatus.OPEN, AlertStatus.ACKNOWLEDGED]), _demo_filter(Alert.is_demo, demo))
            .group_by(Alert.severity)
        ).all()
    )
    assets = (
        db.scalar(
            select(func.count())
            .select_from(Asset)
            .where(Asset.status != AssetStatus.INACTIVE, _demo_filter(Asset.is_demo, demo))
        )
        or 0
    )
    blocked = (
        db.scalar(select(func.count()).select_from(LabBlocklistEntry).where(LabBlocklistEntry.active.is_(True))) or 0
    )
    executed = (
        db.scalar(
            select(func.count())
            .select_from(ResponseAction)
            .where(ResponseAction.status == ResponseStatus.EXECUTED, ResponseAction.executed_at >= since)
        )
        or 0
    )
    pending_approval = (
        db.scalar(
            select(func.count()).select_from(ResponseAction).where(ResponseAction.status == ResponseStatus.PROPOSED)
        )
        or 0
    )

    # Live activity over the last 60s of *arrivals* (ingestion time).
    live_since = now - timedelta(seconds=60)
    live = db.execute(
        select(func.count(), func.coalesce(func.sum(NetworkEvent.bytes_in + NetworkEvent.bytes_out), 0)).where(
            NetworkEvent.ingested_at >= live_since, _demo_filter(NetworkEvent.is_demo, demo)
        )
    ).one()

    # Timeline from rollups, re-bucketed so the browser never receives more than ~120 points.
    bucket_minutes = max(1, (hours * 60) // 120)
    bucket = func.to_timestamp(
        func.floor(func.extract("epoch", EventRollup.bucket) / (bucket_minutes * 60)) * (bucket_minutes * 60)
    )
    timeline = [
        {
            "ts": r.b,
            "events": int(r.e),
            "bytes": int(r.by),
            "normal": int(r.n),
            "anomalous": int(r.a),
            "known_attack": int(r.k),
            "potential_unknown": int(r.u),
        }
        for r in db.execute(
            select(
                bucket.label("b"),
                func.sum(EventRollup.events).label("e"),
                func.sum(EventRollup.bytes).label("by"),
                func.sum(EventRollup.normal).label("n"),
                func.sum(EventRollup.anomalous).label("a"),
                func.sum(EventRollup.known_attack).label("k"),
                func.sum(EventRollup.potential_unknown).label("u"),
            )
            .where(EventRollup.bucket >= since, _demo_filter(EventRollup.is_demo, demo))
            .group_by("b")
            .order_by("b")
        ).all()
    ]

    # Top talkers / protocols — bounded to the window via the ts index.
    ev_window = [NetworkEvent.ts >= since, _demo_filter(NetworkEvent.is_demo, demo)]
    suspicious = func.count().filter(NetworkEvent.classification != Classification.NORMAL)
    top_src = db.execute(
        select(NetworkEvent.src_ip, func.count().label("flows"), suspicious.label("suspicious"))
        .where(*ev_window)
        .group_by(NetworkEvent.src_ip)
        .order_by(suspicious.desc(), func.count().desc())
        .limit(10)
    ).all()
    top_dst = db.execute(
        select(NetworkEvent.dst_ip, func.count().label("flows"), suspicious.label("suspicious"))
        .where(*ev_window)
        .group_by(NetworkEvent.dst_ip)
        .order_by(suspicious.desc(), func.count().desc())
        .limit(10)
    ).all()
    protocols = db.execute(
        select(NetworkEvent.protocol, func.count()).where(*ev_window).group_by(NetworkEvent.protocol)
    ).all()

    trend_bucket = func.date_trunc("hour", Detection.ts)
    trends = db.execute(
        select(trend_bucket.label("h"), Detection.category, func.count())
        .where(Detection.ts >= since, _demo_filter(Detection.is_demo, demo))
        .group_by("h", Detection.category)
        .order_by("h")
    ).all()
    risky_assets = db.scalars(
        select(Asset)
        .where(Asset.risk_score > 0, _demo_filter(Asset.is_demo, demo))
        .order_by(Asset.risk_score.desc())
        .limit(10)
    ).all()
    demo_present = bool(
        db.scalar(
            select(func.count())
            .select_from(EventRollup)
            .where(EventRollup.bucket >= since, EventRollup.is_demo.is_(True))
        )
    )

    return {
        "generated_at": now,
        "window_hours": hours,
        "demo_data_present": demo_present,
        "overview": {
            "total_events": events,
            "traffic_bytes": volume,
            "active_incidents": int(active_incidents),
            "critical_alerts": int(open_alerts.get("critical", 0)),
            "open_alerts": int(sum(open_alerts.values())),
            "unknown_anomalies": unknown,
            "blocked_ips_lab": int(blocked),
            "response_actions_executed": int(executed),
            "response_actions_pending": int(pending_approval),
            "assets_monitored": int(assets),
        },
        "live": {
            "window_seconds": 60,
            "events_per_sec": round(live[0] / 60, 2),
            "connections_per_sec": round(live[0] / 60, 2),
            "bytes_per_sec": round(int(live[1]) / 60, 1),
        },
        "detection_distribution": {
            "normal": normal,
            "anomalous": anomalous,
            "known_attack": known,
            "potential_unknown": unknown,
        },
        "severity": {s: int(open_alerts.get(s, 0)) for s in ("critical", "high", "medium", "low", "info")},
        "timeline": {"bucket_minutes": bucket_minutes, "points": timeline},
        "top_sources": [{"ip": str(r[0]), "flows": int(r[1]), "suspicious": int(r[2])} for r in top_src],
        "top_destinations": [{"ip": str(r[0]), "flows": int(r[1]), "suspicious": int(r[2])} for r in top_dst],
        "protocols": [{"protocol": getattr(p, "value", str(p)), "flows": int(c)} for p, c in protocols],
        "attack_trends": [{"hour": h, "category": c, "count": int(n)} for h, c, n in trends],
        "asset_risk": [
            {
                "id": a.id,
                "ip": str(a.ip_address),
                "hostname": a.hostname,
                "criticality": a.criticality.value,
                "risk_score": a.risk_score,
                "asset_type": a.asset_type.value,
            }
            for a in risky_assets
        ],
    }
