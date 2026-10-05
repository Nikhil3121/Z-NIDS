"""/api/v1/mitre — technique catalogue and observed technique coverage."""

from __future__ import annotations

from datetime import UTC, datetime, timedelta
from typing import Annotated, Any

from fastapi import APIRouter, Depends, Query
from sqlalchemy import func, select

from app.api.deps import DbSession, require
from app.integrations.mitre.catalog import ATTACK_URL
from app.models.detection import Detection, MitreMapping, MitreTechnique
from app.models.enums import Permission
from app.models.user import User

router = APIRouter(prefix="/mitre", tags=["mitre"])
Viewer = Annotated[User, Depends(require(Permission.VIEW_DETECTIONS))]


@router.get("/techniques")
def techniques(db: DbSession, _: Viewer, days: int = Query(7, ge=1, le=90)) -> list[dict[str, Any]]:
    """Every catalogued technique with how often it was hypothesised in the window."""
    since = datetime.now(UTC) - timedelta(days=days)
    counts = dict(
        db.execute(
            select(MitreMapping.technique_id, func.count())
            .join(Detection, Detection.id == MitreMapping.detection_id)
            .where(Detection.ts >= since)
            .group_by(MitreMapping.technique_id)
        ).all()
    )
    max_conf = dict(
        db.execute(
            select(MitreMapping.technique_id, func.max(MitreMapping.confidence))
            .join(Detection, Detection.id == MitreMapping.detection_id)
            .where(Detection.ts >= since)
            .group_by(MitreMapping.technique_id)
        ).all()
    )
    out = []
    for t in db.scalars(select(MitreTechnique).order_by(MitreTechnique.tactic, MitreTechnique.technique_id)).all():
        out.append(
            {
                "technique_id": t.technique_id,
                "name": t.name,
                "tactic": t.tactic,
                "description": t.description,
                "url": ATTACK_URL.format(t.technique_id.replace(".", "/")),
                "observed": int(counts.get(t.technique_id, 0)),
                "max_confidence": float(max_conf[t.technique_id]) if t.technique_id in max_conf else None,
            }
        )
    return out


@router.get("/techniques/{technique_id}/detections")
def technique_detections(
    technique_id: str, db: DbSession, _: Viewer, limit: int = Query(50, ge=1, le=200)
) -> list[dict[str, Any]]:
    rows = db.execute(
        select(MitreMapping, Detection)
        .join(Detection, Detection.id == MitreMapping.detection_id)
        .where(MitreMapping.technique_id == technique_id)
        .order_by(Detection.ts.desc())
        .limit(limit)
    ).all()
    return [
        {
            "detection_id": d.id,
            "ts": d.ts,
            "src_ip": str(d.src_ip),
            "dst_ip": str(d.dst_ip),
            "classification": d.classification.value,
            "confidence": m.confidence,
            "evidence": m.evidence,
            "risk_score": d.risk_score,
        }
        for m, d in rows
    ]
