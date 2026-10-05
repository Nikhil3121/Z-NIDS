"""Behavioural baselines: learning (Welford) and deviation scoring.

Metrics are per *active minute* of a source: how many flows it starts, how many
distinct ports/hosts it touches, how much it sends and how often it fails.
Baselines are learnt only from flows the pipeline classified NORMAL, so an
ongoing attack cannot teach the baseline that it is normal (poisoning guard).

Levels: `asset` (per source IP), `hour` (all sources, per UTC hour-of-day) and
`global`. An asset with fewer than BASELINE_MIN_OBSERVATIONS active minutes is
scored against the hour-of-day baseline (or, failing that, the global one) at
reduced trust, and the explanation says so — new assets are not judged against
an empty history of their own.
"""

from __future__ import annotations

import math
from dataclasses import dataclass
from datetime import datetime
from typing import Any

from sqlalchemy import select, text
from sqlalchemy.dialects.postgresql import insert
from sqlalchemy.orm import Session

from app.detection.base import Detector, EventContext, Signal
from app.models.enums import DetectorType, Severity
from app.models.network_event import Baseline

# metric name -> (window feature used live, human label, unit)
METRICS: dict[str, tuple[str, str, str]] = {
    "conn_per_min": ("conn_count_60", "Connection rate", "flows/min"),
    "dst_ports_per_min": ("uniq_dst_ports_60", "Distinct destination ports", "ports/min"),
    "dst_ips_per_min": ("uniq_dst_ips_60", "Distinct destination hosts", "hosts/min"),
    "bytes_out_per_min": ("bytes_out_sum_60", "Outbound volume", "bytes/min"),
    "failed_ratio": ("failed_ratio_60", "Failed-connection ratio", "ratio"),
}


@dataclass
class Stat:
    count: int
    mean: float
    m2: float

    @property
    def std(self) -> float:
        return math.sqrt(self.m2 / (self.count - 1)) if self.count > 1 else 0.0


def merge(a: Stat, count: int, mean: float, m2: float) -> Stat:
    """Chan et al. parallel merge of two (count, mean, M2) summaries."""
    if count == 0:
        return a
    if a.count == 0:
        return Stat(count, mean, m2)
    n = a.count + count
    delta = mean - a.mean
    return Stat(n, a.mean + delta * count / n, a.m2 + m2 + delta * delta * a.count * count / n)


class BaselineStore:
    def __init__(self, stats: dict[tuple[str, str, str], Stat]) -> None:
        self.stats = stats

    @classmethod
    def load(cls, db: Session, sources: list[str]) -> BaselineStore:
        keys = [("asset", s) for s in sources] + [("global", "all")] + [("hour", f"h{h:02d}") for h in range(24)]
        stats: dict[tuple[str, str, str], Stat] = {}
        if not keys:
            return cls(stats)
        # Chunk to keep the IN-list bounded.
        for i in range(0, len(keys), 500):
            chunk = keys[i : i + 500]
            rows = db.scalars(
                select(Baseline).where(
                    Baseline.entity_type.in_({k[0] for k in chunk}),
                    Baseline.entity_key.in_({k[1] for k in chunk}),
                )
            ).all()
            for r in rows:
                stats[(r.entity_type, r.entity_key, r.metric)] = Stat(r.count, r.mean, r.m2)
        return cls(stats)

    def get(self, entity_type: str, key: str, metric: str) -> Stat | None:
        return self.stats.get((entity_type, key, metric))


@dataclass
class BehaviorConfig:
    min_observations: int
    z_threshold: float = 3.0
    min_ratio: float = 2.0
    scale: float = 5.0
    strong_component: float = 60.0


class BehavioralDetector(Detector):
    name = "behavioral_baseline"
    detector_type = DetectorType.BEHAVIORAL

    def __init__(self, store: BaselineStore, config: BehaviorConfig) -> None:
        self.store = store
        self.config = config

    def _deviation(self, value: float, stat: Stat) -> tuple[float, float]:
        # Floor the std so a near-constant history does not turn noise into 100-sigma events.
        std = max(stat.std, 0.1 * abs(stat.mean), 1.0 if stat.mean >= 1 else 0.05)
        z = (value - stat.mean) / std
        ratio = value / stat.mean if stat.mean > 0 else float("inf") if value > 0 else 1.0
        return z, ratio

    def detect_batch(self, contexts: list[EventContext]) -> dict[int, list[Signal]]:
        cfg = self.config
        out: dict[int, list[Signal]] = {}
        for ctx in contexts:
            factors: list[dict[str, Any]] = []
            best = 0.0
            for metric, (feature, label, unit) in METRICS.items():
                value = ctx.values.get(feature)
                if value is None:
                    continue
                stat = self.store.get("asset", ctx.src_ip, metric)
                level, trust = "asset", 1.0
                if stat is None or stat.count < cfg.min_observations:
                    history = stat.count if stat else 0
                    hour = int((ctx.ts % 86400) // 3600)
                    fallback = self.store.get("hour", f"h{hour:02d}", metric)
                    if fallback is not None and fallback.count >= cfg.min_observations:
                        stat, scope = fallback, f"hour-of-day {hour:02d}:00 UTC"
                    else:
                        stat, scope = self.store.get("global", "all", metric), "global"
                    level = f"{scope} (asset has {history} < {cfg.min_observations} minutes of history)"
                    trust = 0.5
                if stat is None or stat.count < cfg.min_observations:
                    continue
                z, ratio = self._deviation(float(value), stat)
                if z < cfg.z_threshold or ratio < cfg.min_ratio:
                    continue
                component = trust * 100.0 * (1.0 - math.exp(-(z - cfg.z_threshold) / cfg.scale))
                best = max(best, component)
                ratio_txt = "∞" if math.isinf(ratio) else f"{ratio:.1f}×"
                factors.append(
                    {
                        "feature": metric,
                        "label": label,
                        "value": float(value),
                        "baseline_mean": round(stat.mean, 4),
                        "baseline_std": round(stat.std, 4),
                        "z_score": round(z, 2),
                        "ratio_to_baseline": None if math.isinf(ratio) else round(ratio, 2),
                        "baseline_level": level,
                        "source": "behavioral_baseline",
                        "detail": f"{label} {float(value):,.3g} {unit} vs {level} baseline "
                        f"{stat.mean:,.3g} ({ratio_txt}, z={z:.1f})",
                    }
                )
            if best > 0:
                factors.sort(key=lambda f: f["z_score"], reverse=True)
                out[ctx.index] = [
                    Signal(
                        detector=self.detector_type,
                        category="behavioral_anomaly",
                        component=round(best, 2),
                        confidence=min(0.95, best / 100.0 + 0.3),
                        severity=Severity.MEDIUM if best < cfg.strong_component else Severity.HIGH,
                        summary="Source behaviour deviates from its learned baseline: "
                        + "; ".join(f["detail"] for f in factors[:3]),
                        factors=factors,
                        verdict="ANOMALOUS",
                    )
                ]
        return out


_FAILED_SQL = (
    "(conn_state IN ('S0','REJ','RSTO','RSTOS0','RSTR','RSTRH','SH','SHR','OTH') "
    "OR (conn_state IS NULL AND protocol = 'tcp' AND ((tcp_flags & 2) > 0 AND (tcp_flags & 16) = 0 OR (tcp_flags & 4) > 0)))"
)


def update_baselines(db: Session, processed_from: datetime, processed_to: datetime) -> int:
    """Fold NORMAL flows processed in [from, to) into the baselines. Returns minutes observed."""
    rows = db.execute(
        text(f"""
            SELECT host(src_ip) AS src, date_trunc('minute', ts) AS minute,
                   extract(hour from ts)::int AS hour,
                   count(*) AS conns, count(DISTINCT dst_port) AS ports, count(DISTINCT dst_ip) AS ips,
                   sum(bytes_out) AS bytes_out,
                   avg(CASE WHEN {_FAILED_SQL} THEN 1.0 ELSE 0.0 END) AS failed_ratio
            FROM network_events
            WHERE processed_at >= :f AND processed_at < :t AND classification = 'NORMAL'
            GROUP BY 1, 2, 3
            """),  # noqa: S608 - static SQL, parameters bound
        {"f": processed_from, "t": processed_to},
    ).all()
    if not rows:
        return 0
    batches: dict[tuple[str, str, str], list[float]] = {}
    for r in rows:
        values = {
            "conn_per_min": float(r.conns),
            "dst_ports_per_min": float(r.ports),
            "dst_ips_per_min": float(r.ips),
            "bytes_out_per_min": float(r.bytes_out or 0),
            "failed_ratio": float(r.failed_ratio or 0),
        }
        for metric, v in values.items():
            for key in (("asset", r.src), ("global", "all"), ("hour", f"h{int(r.hour):02d}")):
                batches.setdefault((key[0], key[1], metric), []).append(v)

    existing = BaselineStore.load(db, sorted({r.src for r in rows})).stats

    values_to_upsert = []
    for (etype, ekey, metric), vals in batches.items():
        n = len(vals)
        mean = sum(vals) / n
        m2 = sum((v - mean) ** 2 for v in vals)
        merged = merge(existing.get((etype, ekey, metric), Stat(0, 0.0, 0.0)), n, mean, m2)
        values_to_upsert.append(
            {
                "entity_type": etype,
                "entity_key": ekey[:64],
                "metric": metric,
                "count": merged.count,
                "mean": merged.mean,
                "m2": merged.m2,
            }
        )
    stmt = insert(Baseline).values(values_to_upsert)
    stmt = stmt.on_conflict_do_update(
        constraint="uq_baselines_entity_metric",
        set_={
            "count": stmt.excluded.count,
            "mean": stmt.excluded.mean,
            "m2": stmt.excluded.m2,
            "updated_at": text("now()"),
        },
    )
    db.execute(stmt)
    return len(rows)
