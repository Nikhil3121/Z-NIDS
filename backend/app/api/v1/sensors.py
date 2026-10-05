"""/api/v1/sensors — sensor registration and API-key lifecycle."""

from __future__ import annotations

from typing import Annotated

from fastapi import APIRouter, Depends
from sqlalchemy import select

from app.api.deps import DbSession, Meta, require
from app.core.config import Environment, get_settings
from app.core.exceptions import ConflictError, NotFoundError, PermissionDeniedError
from app.core.security import generate_opaque_token, hash_token
from app.models.asset import Sensor
from app.models.enums import Permission
from app.models.user import User
from app.schemas.soc import SensorCreate, SensorCreated, SensorOut
from app.services import audit_service

router = APIRouter(prefix="/sensors", tags=["sensors"])
Admin = Annotated[User, Depends(require(Permission.MANAGE_SENSORS))]
Viewer = Annotated[User, Depends(require(Permission.VIEW_EVENTS))]


def _new_key() -> tuple[str, str, str]:
    raw = "zns_" + generate_opaque_token(32)
    return raw, hash_token(raw), raw[:12]


@router.get("", response_model=list[SensorOut])
def list_sensors(db: DbSession, _: Viewer) -> list[SensorOut]:
    return [SensorOut.model_validate(s) for s in db.scalars(select(Sensor).order_by(Sensor.name)).all()]


@router.post("", response_model=SensorCreated, status_code=201)
def create_sensor(body: SensorCreate, db: DbSession, user: Admin, meta: Meta) -> SensorCreated:
    if body.is_demo and get_settings().environment == Environment.PRODUCTION:
        raise PermissionDeniedError("Lab/demo sensors cannot be created in production")
    if db.scalar(select(Sensor).where(Sensor.name == body.name)) is not None:
        raise ConflictError("A sensor with this name already exists")
    raw, digest, prefix = _new_key()
    sensor = Sensor(
        name=body.name,
        sensor_type=body.sensor_type,
        location=body.location,
        is_demo=body.is_demo,
        api_key_hash=digest,
        key_prefix=prefix,
    )
    db.add(sensor)
    db.flush()
    audit_service.record(
        db,
        "SENSOR_CREATED",
        actor=user,
        resource_type="sensor",
        resource_id=sensor.id,
        meta=meta,
        details={"name": sensor.name, "type": sensor.sensor_type.value, "key_prefix": prefix},
    )
    db.commit()
    return SensorCreated(**SensorOut.model_validate(sensor).model_dump(), api_key=raw)


@router.post("/{sensor_id}/rotate-key", response_model=SensorCreated)
def rotate_key(sensor_id: int, db: DbSession, user: Admin, meta: Meta) -> SensorCreated:
    sensor = db.get(Sensor, sensor_id)
    if sensor is None:
        raise NotFoundError("Sensor not found")
    raw, digest, prefix = _new_key()
    old_prefix = sensor.key_prefix
    sensor.api_key_hash, sensor.key_prefix = digest, prefix
    audit_service.record(
        db,
        "SENSOR_KEY_ROTATED",
        actor=user,
        resource_type="sensor",
        resource_id=sensor.id,
        meta=meta,
        details={"old_prefix": old_prefix, "new_prefix": prefix},
    )
    db.commit()
    return SensorCreated(**SensorOut.model_validate(sensor).model_dump(), api_key=raw)


@router.patch("/{sensor_id}", response_model=SensorOut)
def set_active(sensor_id: int, is_active: bool, db: DbSession, user: Admin, meta: Meta) -> SensorOut:
    sensor = db.get(Sensor, sensor_id)
    if sensor is None:
        raise NotFoundError("Sensor not found")
    sensor.is_active = is_active
    audit_service.record(
        db,
        "SENSOR_UPDATED",
        actor=user,
        resource_type="sensor",
        resource_id=sensor.id,
        meta=meta,
        details={"is_active": is_active},
    )
    db.commit()
    return SensorOut.model_validate(sensor)
