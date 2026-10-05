"""Aggregates every /api/v1 router."""

from __future__ import annotations

from fastapi import APIRouter

from app.api.v1 import (
    alerts,
    assets,
    assistant,
    audit,
    auth,
    dashboard,
    detections,
    events,
    incidents,
    lab,
    mitre,
    models,
    notifications,
    reports,
    response,
    sensors,
    system,
    threat_intelligence,
    users,
    ws,
)

api_router = APIRouter()
for module in (
    auth,
    dashboard,
    events,
    detections,
    alerts,
    incidents,
    assets,
    sensors,
    threat_intelligence,
    mitre,
    models,
    reports,
    users,
    audit,
    notifications,
    response,
    lab,
    assistant,
    system,
    ws,
):
    api_router.include_router(module.router)
