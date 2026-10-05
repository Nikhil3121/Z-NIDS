"""Transparent ensemble risk engine.

    detection_strength = 1 - Π_i (1 - trust_i · component_i / 100)      i ∈ {signature, anomaly,
                                                                          behavioral, threat_intel}
    context            = min(1, base + w_asset · asset/100 + w_corr · correlation/100)
    risk               = 100 · detection_strength · context

A noisy-OR lets independent evidence reinforce without any single weak signal
dominating; context (asset criticality, prior activity) scales it. Every
component, weight and intermediate is stored with the detection.
"""

from __future__ import annotations

import json
from dataclasses import dataclass, field
from functools import lru_cache
from pathlib import Path
from typing import Any

from app.core.config import get_settings

DETECTION_COMPONENTS = ("signature", "anomaly", "behavioral", "threat_intel")


@dataclass(frozen=True)
class RiskWeights:
    trust: dict[str, float]
    context_base: float
    context_asset: float
    context_correlation: float
    unknown_asset_criticality: float
    behavioral: dict[str, float] = field(default_factory=dict)
    version: str = ""

    @classmethod
    def from_file(cls, path: Path) -> RiskWeights:
        data = json.loads(path.read_text(encoding="utf-8"))
        trust = {k: float(data["trust"][k]) for k in DETECTION_COMPONENTS}
        for key, value in trust.items():
            if not 0.0 <= value <= 1.0:
                raise ValueError(f"trust weight {key} must be within [0, 1]")
        ctx = data["context"]
        return cls(
            trust=trust,
            context_base=float(ctx["base"]),
            context_asset=float(ctx["asset_criticality"]),
            context_correlation=float(ctx["correlation"]),
            unknown_asset_criticality=float(data.get("unknown_asset_criticality", 50)),
            behavioral={k: float(v) for k, v in data.get("behavioral", {}).items()},
            version=str(data.get("version", "")),
        )


@lru_cache
def get_weights() -> RiskWeights:
    return RiskWeights.from_file(get_settings().risk_weights_path)


@dataclass
class RiskResult:
    score: float
    components: dict[str, Any]
    reason: str


def compute_risk(
    components: dict[str, float], asset_criticality: float | None, correlation: float, weights: RiskWeights
) -> RiskResult:
    comp = {k: float(max(0.0, min(100.0, components.get(k, 0.0)))) for k in DETECTION_COMPONENTS}
    asset = weights.unknown_asset_criticality if asset_criticality is None else asset_criticality
    correlation = max(0.0, min(100.0, correlation))
    miss = 1.0
    for key in DETECTION_COMPONENTS:
        miss *= 1.0 - weights.trust[key] * comp[key] / 100.0
    strength = 1.0 - miss
    context = min(
        1.0,
        weights.context_base
        + weights.context_asset * asset / 100.0
        + weights.context_correlation * correlation / 100.0,
    )
    score = round(100.0 * strength * context, 1)
    stored = {
        **{k: round(v, 1) for k, v in comp.items()},
        "asset_criticality": round(asset, 1),
        "asset_criticality_known": asset_criticality is not None,
        "correlation": round(correlation, 1),
        "detection_strength": round(strength, 4),
        "context_multiplier": round(context, 4),
        "weights": {
            "trust": weights.trust,
            "context_base": weights.context_base,
            "context_asset": weights.context_asset,
            "context_correlation": weights.context_correlation,
        },
        "formula": "100 * (1 - prod(1 - trust_i*c_i/100)) * min(1, base + w_a*asset/100 + w_c*corr/100)",
        "weights_version": weights.version,
    }
    return RiskResult(score, stored, explain_components(comp, asset, correlation))


def explain_components(comp: dict[str, float], asset: float, correlation: float) -> str:
    parts: list[str] = []
    if comp["signature"] > 0:
        parts.append("a known attack signature matched")
    else:
        parts.append("no known signature matched")
    if comp["anomaly"] >= 50:
        parts.append("the ML models rate the flow as highly unusual compared with learned normal traffic")
    if comp["behavioral"] >= 40:
        parts.append("the source significantly deviates from its learned behavioural baseline")
    elif comp["behavioral"] > 0:
        parts.append("the source mildly deviates from its baseline")
    if comp["threat_intel"] > 0:
        parts.append("threat intelligence lists an endpoint as suspicious or malicious")
    if asset >= 75:
        parts.append("a high-criticality asset is involved")
    if correlation > 0:
        parts.append("the source was involved in other recent alerts")
    text = parts[0]
    if len(parts) > 1:
        text += (", but " if comp["signature"] == 0 else ", ") + "; ".join(parts[1:])
    return text[0].upper() + text[1:] + "."
