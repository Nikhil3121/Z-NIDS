"""/api/v1/assets — inventory, asset risk, and the observed network topology."""

from __future__ import annotations

import ipaddress
from datetime import UTC, datetime, timedelta
from typing import Annotated, Any

from fastapi import APIRouter, Depends, Query
from sqlalchemy import case, func, or_, select

from app.api.deps import DbSession, Meta, require
from app.api.query import apply_sort, page_params, paginate
from app.core.exceptions import ConflictError, NotFoundError, PermissionDeniedError, ValidationFailedError
from app.models.alert import Alert
from app.models.asset import Asset, Sensor
from app.models.enums import AssetStatus, AssetType, Classification, Criticality, Permission
from app.models.network_event import NetworkEvent
from app.models.user import User
from app.schemas.common import Page, PageParams
from app.schemas.soc import AlertOut, AssetIn, AssetOut, AssetPatch
from app.services import audit_service
from app.services.ingest_service import is_internal
from app.websocket.events import RealtimeEvent, publish

router = APIRouter(prefix="/assets", tags=["assets"])
Viewer = Annotated[User, Depends(require(Permission.VIEW_ASSETS))]
Manager = Annotated[User, Depends(require(Permission.MANAGE_ASSETS))]

_SORT = {
    "risk_score": Asset.risk_score,
    "last_seen": Asset.last_seen,
    "hostname": Asset.hostname,
    "criticality": case({"critical": 4, "high": 3, "medium": 2, "low": 1}, value=Asset.criticality),
}


@router.get("", response_model=Page[AssetOut])
def list_assets(
    db: DbSession,
    _: Viewer,
    params: Annotated[PageParams, Depends(page_params)],
    asset_type: AssetType | None = None,
    criticality: Criticality | None = None,
    status: AssetStatus | None = None,
    q: str | None = Query(None, max_length=100),
    min_risk: float | None = Query(None, ge=0, le=100),
    demo: bool | None = None,
    sort: str | None = Query(None, max_length=32),
) -> Page[AssetOut]:
    stmt = select(Asset)
    if asset_type:
        stmt = stmt.where(Asset.asset_type == asset_type)
    if criticality:
        stmt = stmt.where(Asset.criticality == criticality)
    if status:
        stmt = stmt.where(Asset.status == status)
    if min_risk is not None:
        stmt = stmt.where(Asset.risk_score >= min_risk)
    if demo is not None:
        stmt = stmt.where(Asset.is_demo.is_(demo))
    if q:
        needle = q.replace("\\", "\\\\").replace("%", "\\%").replace("_", "\\_")
        try:
            ip = str(ipaddress.ip_address(q.strip()))
            stmt = stmt.where(Asset.ip_address == ip)
        except ValueError:
            stmt = stmt.where(
                or_(Asset.hostname.ilike(f"%{needle}%", escape="\\"), Asset.owner.ilike(f"%{needle}%", escape="\\"))
            )
    stmt = apply_sort(stmt, sort, _SORT, Asset.risk_score.desc())
    return paginate(db, stmt, params, AssetOut.model_validate)


@router.post("", response_model=AssetOut, status_code=201)
def create_asset(body: AssetIn, db: DbSession, user: Manager, meta: Meta) -> AssetOut:
    try:
        ip = str(ipaddress.ip_address(body.ip_address))
    except ValueError as exc:
        raise ValidationFailedError("Invalid IP address") from exc
    if db.scalar(select(Asset).where(Asset.ip_address == ip)) is not None:
        raise ConflictError("An asset with this IP already exists")
    now = datetime.now(UTC)
    asset = Asset(
        **body.model_dump(exclude={"ip_address"}), ip_address=ip, auto_discovered=False, first_seen=now, last_seen=now
    )
    db.add(asset)
    db.flush()
    audit_service.record(
        db, "ASSET_CREATED", actor=user, resource_type="asset", resource_id=asset.id, meta=meta, details={"ip": ip}
    )
    db.commit()
    return AssetOut.model_validate(asset)


@router.get("/topology")
def topology(
    db: DbSession,
    user: Viewer,
    minutes: int = Query(60, ge=5, le=24 * 60),
    collapse_external: bool = True,
    incident_id: int | None = Query(None, ge=1),
    max_edges: int = Query(150, ge=10, le=500),
) -> dict[str, Any]:
    """Nodes and edges derived from observed flows in the window — nothing is drawn that was not seen."""
    if not user.has_permission(Permission.VIEW_EVENTS.value):
        raise PermissionDeniedError("Topology requires permission to view events")
    since = datetime.now(UTC) - timedelta(minutes=minutes)
    suspicious = func.sum(case((NetworkEvent.classification != Classification.NORMAL, 1), else_=0))
    rows = db.execute(
        select(
            NetworkEvent.src_ip,
            NetworkEvent.dst_ip,
            func.count().label("flows"),
            func.sum(NetworkEvent.bytes_in + NetworkEvent.bytes_out).label("bytes"),
            suspicious.label("suspicious"),
            func.max(NetworkEvent.risk_score).label("max_risk"),
            func.max(NetworkEvent.ts).label("last_seen"),
        )
        .where(NetworkEvent.ts >= since)
        .group_by(NetworkEvent.src_ip, NetworkEvent.dst_ip)
        .order_by(suspicious.desc(), func.count().desc())
        .limit(max_edges)
    ).all()
    highlight: set[tuple[str, str]] = set()
    if incident_id is not None:
        for src, dst in db.execute(select(Alert.src_ip, Alert.dst_ip).where(Alert.incident_id == incident_id)).all():
            if src is not None and dst is not None:
                highlight.add((str(src), str(dst)))

    ips = {str(r.src_ip) for r in rows} | {str(r.dst_ip) for r in rows}
    assets = (
        {str(a.ip_address): a for a in db.scalars(select(Asset).where(Asset.ip_address.in_(list(ips)))).all()}
        if ips
        else {}
    )

    def node_id(ip: str) -> str:
        return "internet" if collapse_external and not is_internal(ip) else ip

    nodes: dict[str, dict[str, Any]] = {}
    external_seen: set[str] = set()
    edges: dict[tuple[str, str], dict[str, Any]] = {}
    for r in rows:
        src, dst = str(r.src_ip), str(r.dst_ip)
        for ip in (src, dst):
            nid = node_id(ip)
            if nid not in nodes:
                if nid == "internet":
                    nodes[nid] = {
                        "id": nid,
                        "label": "Internet (external hosts)",
                        "kind": "internet",
                        "external_hosts": 0,
                        "risk": 0.0,
                    }
                else:
                    a = assets.get(ip)
                    nodes[nid] = {
                        "id": nid,
                        "label": (a.hostname if a and a.hostname else ip),
                        "ip": ip,
                        "kind": a.asset_type.value if a else ("external" if not is_internal(ip) else "unknown"),
                        "criticality": a.criticality.value if a else None,
                        "status": a.status.value if a else None,
                        "risk": a.risk_score if a else 0.0,
                        "asset_id": a.id if a else None,
                    }
            if nid == "internet" and ip not in external_seen:
                external_seen.add(ip)
                nodes[nid]["external_hosts"] += 1
        key = (node_id(src), node_id(dst))
        e = edges.setdefault(
            key,
            {
                "source": key[0],
                "target": key[1],
                "flows": 0,
                "bytes": 0,
                "suspicious": 0,
                "max_risk": 0.0,
                "highlight": False,
            },
        )
        e["flows"] += int(r.flows)
        e["bytes"] += int(r.bytes or 0)
        e["suspicious"] += int(r.suspicious or 0)
        e["max_risk"] = max(e["max_risk"], float(r.max_risk or 0.0))
        if (src, dst) in highlight:
            e["highlight"] = True
    sensors = db.scalars(select(Sensor).where(Sensor.is_active.is_(True))).all()
    return {
        "window_minutes": minutes,
        "generated_at": datetime.now(UTC),
        "nodes": list(nodes.values()),
        "edges": list(edges.values()),
        "sensors": [
            {"id": s.id, "name": s.name, "type": s.sensor_type.value, "last_seen": s.last_seen} for s in sensors
        ],
        "truncated": len(rows) >= max_edges,
    }


@router.get("/{asset_id}")
def get_asset(asset_id: int, db: DbSession, _: Viewer) -> dict[str, Any]:
    asset = db.get(Asset, asset_id)
    if asset is None:
        raise NotFoundError("Asset not found")
    alerts = db.scalars(
        select(Alert)
        .where(or_(Alert.src_ip == asset.ip_address, Alert.dst_ip == asset.ip_address))
        .order_by(Alert.last_seen.desc())
        .limit(25)
    ).all()
    return {
        "asset": AssetOut.model_validate(asset).model_dump(mode="json"),
        "recent_alerts": [AlertOut.model_validate(a).model_dump(mode="json") for a in alerts],
    }


@router.patch("/{asset_id}", response_model=AssetOut)
def update_asset(asset_id: int, body: AssetPatch, db: DbSession, user: Manager, meta: Meta) -> AssetOut:
    asset = db.get(Asset, asset_id)
    if asset is None:
        raise NotFoundError("Asset not found")
    changes = body.model_dump(exclude_unset=True)
    before = {k: getattr(asset, k) for k in changes}
    for key, value in changes.items():
        setattr(asset, key, value)
    asset.auto_discovered = False
    audit_service.record(
        db,
        "ASSET_UPDATED",
        actor=user,
        resource_type="asset",
        resource_id=asset.id,
        meta=meta,
        details={"before": {k: str(v) for k, v in before.items()}, "after": {k: str(v) for k, v in changes.items()}},
    )
    db.commit()
    out = AssetOut.model_validate(asset)
    publish(RealtimeEvent.ASSET_UPDATED, out.model_dump(mode="json"))
    return out
