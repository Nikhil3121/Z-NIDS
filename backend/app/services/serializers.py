"""ORM -> API schema mapping for objects that need joined/derived fields."""

from __future__ import annotations

from app.integrations.mitre.catalog import ATTACK_URL
from app.models.detection import Detection
from app.models.incident import Incident
from app.schemas.soc import DetectionOut, IncidentOut, MitreMappingOut


def detection_out(det: Detection) -> DetectionOut:
    out = DetectionOut.model_validate(det)
    out.mitre = [
        MitreMappingOut(
            technique_id=m.technique_id,
            name=m.technique.name if m.technique else m.technique_id,
            tactic=m.technique.tactic if m.technique else "",
            url=ATTACK_URL.format(m.technique_id.replace(".", "/")),
            confidence=m.confidence,
            evidence=m.evidence,
        )
        for m in det.mitre_mappings
    ]
    return out


def incident_out(inc: Incident) -> IncidentOut:
    return IncidentOut.model_validate(
        {
            **{c: getattr(inc, c) for c in IncidentOut.model_fields if c not in ("reference", "assigned_to")},
            "reference": inc.reference,
            "assigned_to": inc.assigned_to,
        }
    )
