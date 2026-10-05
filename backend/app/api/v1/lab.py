"""/api/v1/lab — LAB / DEMO synthetic telemetry (DEMO_MODE only)."""

from __future__ import annotations

from typing import Annotated, Any

from fastapi import APIRouter, Depends
from pydantic import Field

from app.api.deps import CurrentUser, DbSession, Meta, require
from app.core.config import Environment, get_settings
from app.models.enums import Permission
from app.models.user import User
from app.schemas.common import StrictInput
from app.services import audit_service, lab_service

router = APIRouter(prefix="/lab", tags=["lab"])
Admin = Annotated[User, Depends(require(Permission.MANAGE_SETTINGS))]


class ScenarioRequest(StrictInput):
    scenario: str = Field(pattern=r"^[a-z_]{3,32}$")
    minutes: float = Field(10, ge=1, le=120)
    intensity: float = Field(0.3, ge=0.05, le=2.0)
    seed: int | None = Field(default=None, ge=0, le=10**6)


@router.get("/status")
def status(_: CurrentUser) -> dict[str, Any]:
    s = get_settings()
    enabled = s.demo_mode and s.environment != Environment.PRODUCTION
    return {
        "demo_mode": enabled,
        "scenarios": list(lab_service.SCENARIOS) if enabled else [],
        "aliases": lab_service.ALIASES if enabled else {},
        "banner": "LAB / DEMO DATA" if enabled else None,
    }


@router.post("/scenarios", status_code=202)
def run(body: ScenarioRequest, db: DbSession, user: Admin, meta: Meta) -> dict[str, Any]:
    lab_service.ensure_enabled()
    audit_service.record(
        db, "LAB_SCENARIO_STARTED", actor=user, resource_type="lab", meta=meta, details=body.model_dump()
    )
    db.commit()
    return lab_service.run_scenario(db, body.scenario, body.minutes, body.intensity, body.seed)
