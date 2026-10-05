"""LAB / DEMO mode: synthetic telemetry through the *real* ingestion + detection path.

Only available when DEMO_MODE=true (never in production). Every record comes
from a dedicated lab sensor flagged is_demo, so the resulting events, alerts
and incidents are marked demo and the UI shows "LAB / DEMO DATA". Nothing is
sent on any network; the generator only produces flow metadata.
"""

from __future__ import annotations

import time
from datetime import UTC, datetime
from typing import Any

import pandas as pd
from sqlalchemy import select
from sqlalchemy.orm import Session

from app.core.config import Environment, get_settings
from app.core.exceptions import PermissionDeniedError, ValidationFailedError
from app.core.security import generate_opaque_token, hash_token
from app.ml.synthetic.generator import ATTACK_FAMILIES, LabNetwork, SyntheticTrafficGenerator, finalize
from app.models.asset import Asset, Sensor
from app.models.enums import AssetStatus, AssetType, Criticality, EventSource
from app.services import ingest_service

LAB_SENSOR_NAME = "lab-synthetic-generator"
SCENARIOS = ("normal", *ATTACK_FAMILIES)
ALIASES = {"connection_spike": "ddos", "unusual_traffic": "exfiltration"}


def ensure_enabled() -> None:
    s = get_settings()
    if not s.demo_mode or s.environment == Environment.PRODUCTION:
        raise PermissionDeniedError("LAB / DEMO mode is disabled (DEMO_MODE=false)", code="DEMO_DISABLED")


def lab_sensor(db: Session) -> Sensor:
    sensor = db.scalar(select(Sensor).where(Sensor.name == LAB_SENSOR_NAME))
    if sensor is None:
        # The lab sensor never authenticates over HTTP; its key is random and discarded.
        raw = generate_opaque_token(32)
        sensor = Sensor(
            name=LAB_SENSOR_NAME,
            sensor_type=EventSource.SYNTHETIC,
            api_key_hash=hash_token(raw),
            key_prefix="lab-internal",
            is_demo=True,
            location="lab",
        )
        db.add(sensor)
        db.flush()
    return sensor


def seed_lab_assets(db: Session) -> int:
    """Register the lab network's hosts as demo assets (hostname, type, criticality)."""
    created = 0
    now = datetime.now(UTC)
    for item in LabNetwork().asset_inventory():
        asset = db.scalar(select(Asset).where(Asset.ip_address == item["ip"]))
        if asset is None:
            db.add(
                Asset(
                    ip_address=item["ip"],
                    hostname=item["hostname"],
                    asset_type=AssetType(item["asset_type"]),
                    criticality=Criticality(item["criticality"]),
                    status=AssetStatus.ACTIVE,
                    environment="lab",
                    owner="lab",
                    auto_discovered=False,
                    is_lab=True,
                    is_demo=True,
                    first_seen=now,
                    last_seen=now,
                )
            )
            created += 1
        elif asset.is_demo:
            asset.hostname = item["hostname"]
            asset.asset_type = AssetType(item["asset_type"])
            asset.criticality = Criticality(item["criticality"])
    return created


def generate_frame(
    scenario: str, minutes: float, seed: int | None, intensity: float, background: bool = True
) -> pd.DataFrame:
    scenario = ALIASES.get(scenario, scenario)
    if scenario not in SCENARIOS:
        raise ValidationFailedError(f"Unknown scenario '{scenario}'", details={"allowed": [*SCENARIOS, *ALIASES]})
    end = time.time() - 1.0
    start = end - minutes * 60
    gen = SyntheticTrafficGenerator(seed=seed if seed is not None else int(end) % 1_000_000)
    parts = [gen.normal(start, end, intensity)] if background or scenario == "normal" else []
    if scenario != "normal":
        # Start the episode in the second half of the window so baselines/context precede it.
        t0 = start + (end - start) * float(gen.rng.uniform(0.45, 0.6))
        parts.append(getattr(gen, scenario)(t0, f"lab-{scenario}"))
    df = finalize(pd.concat([p for p in parts if len(p)], ignore_index=True))
    return df[(df["ts"] >= start) & (df["ts"] <= end)].reset_index(drop=True)


def frame_to_records(df: pd.DataFrame) -> list[dict[str, Any]]:
    records = []
    for r in df.itertuples(index=False):
        records.append(
            {
                "ts": datetime.fromtimestamp(float(r.ts), UTC).isoformat(),
                "src_ip": r.src_ip,
                "dst_ip": r.dst_ip,
                "src_port": int(r.src_port),
                "dst_port": int(r.dst_port),
                "protocol": r.protocol,
                "app_protocol": None if r.app_protocol in ("", "unknown") else r.app_protocol,
                "duration_ms": float(r.duration_ms),
                "packets_out": int(r.packets_out),
                "packets_in": int(r.packets_in),
                "bytes_out": int(r.bytes_out),
                "bytes_in": int(r.bytes_in),
                "tcp_flags": int(r.tcp_flags),
                "conn_state": r.conn_state or None,
                "dataset_label": r.label,
                "raw_ref": f"lab:{r.episode}" if r.episode else "lab:normal",
            }
        )
    return records


def run_scenario(
    db: Session, scenario: str, minutes: float, intensity: float, seed: int | None, background: bool = True
) -> dict[str, Any]:
    ensure_enabled()
    if not 1 <= minutes <= 120:
        raise ValidationFailedError("minutes must be between 1 and 120")
    sensor = lab_sensor(db)
    seed_lab_assets(db)
    db.commit()
    df = generate_frame(scenario, minutes, seed, intensity, background)
    records = frame_to_records(df)
    accepted, rejected = 0, 0
    for i in range(0, len(records), 2000):
        result = ingest_service.ingest(db, records[i : i + 2000], source_type=EventSource.SYNTHETIC, sensor=sensor)
        accepted += len(result.accepted_ids)
        rejected += len(result.rejected)
    labels = df["label"].value_counts().to_dict()
    return {
        "scenario": scenario,
        "minutes": minutes,
        "flows_generated": len(df),
        "accepted": accepted,
        "rejected": rejected,
        "ground_truth_labels": {str(k): int(v) for k, v in labels.items()},
        "demo": True,
        "note": "Synthetic lab telemetry only — no traffic was sent on any network.",
    }


__all__ = ["SCENARIOS", "generate_frame", "lab_sensor", "run_scenario", "seed_lab_assets"]
