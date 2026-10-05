"""Asset inventory: discovery from observed traffic, lookups and risk roll-up."""

from __future__ import annotations

from collections.abc import Iterable
from datetime import datetime

from sqlalchemy import func, select, update
from sqlalchemy.dialects.postgresql import insert
from sqlalchemy.orm import Session

from app.models.asset import Asset
from app.models.enums import AssetStatus, AssetType, Criticality
from app.services.ingest_service import is_internal


def touch_internal_assets(db: Session, seen: dict[str, tuple[datetime, bool]]) -> dict[str, Asset]:
    """Upsert assets for internal IPs observed in a batch; return ip -> Asset.

    `seen` maps ip -> (latest timestamp, is_demo). Newly discovered assets get
    type UNKNOWN / criticality MEDIUM until an analyst classifies them.
    """
    internal = {ip: v for ip, v in seen.items() if is_internal(ip)}
    if internal:
        rows = [
            {
                "ip_address": ip,
                "asset_type": AssetType.UNKNOWN,
                "criticality": Criticality.MEDIUM,
                "status": AssetStatus.ACTIVE,
                "auto_discovered": True,
                "is_demo": demo,
                "is_lab": demo,
                "first_seen": ts,
                "last_seen": ts,
            }
            for ip, (ts, demo) in internal.items()
        ]
        for i in range(0, len(rows), 1000):
            stmt = insert(Asset).values(rows[i : i + 1000])
            stmt = stmt.on_conflict_do_update(
                index_elements=[Asset.ip_address],
                set_={"last_seen": func.greatest(Asset.last_seen, stmt.excluded.last_seen), "updated_at": func.now()},
            )
            db.execute(stmt)
    return assets_by_ip(db, seen.keys())


def assets_by_ip(db: Session, ips: Iterable[str]) -> dict[str, Asset]:
    ips = list(ips)
    out: dict[str, Asset] = {}
    for i in range(0, len(ips), 1000):
        for asset in db.scalars(select(Asset).where(Asset.ip_address.in_(ips[i : i + 1000]))).all():
            out[str(asset.ip_address)] = asset
    return out


def bump_risk(db: Session, asset_ids_to_risk: dict[int, float]) -> None:
    """Asset risk = the highest recent detection risk touching it (monotone within a batch)."""
    for asset_id, risk in asset_ids_to_risk.items():
        db.execute(update(Asset).where(Asset.id == asset_id, Asset.risk_score < risk).values(risk_score=risk))
