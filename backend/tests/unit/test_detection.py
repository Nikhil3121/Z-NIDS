"""Signature rules, risk scoring and explanation behaviour (no database needed)."""

from __future__ import annotations

from pathlib import Path

import numpy as np

from app.core.config import get_settings
from app.detection.signatures.engine import SignatureDetector, load_rules
from app.ml.models.bundle import ModelBundle
from app.services.risk_service import RiskWeights, compute_risk

RULES = SignatureDetector(load_rules(get_settings().signature_rules_path))
WEIGHTS = RiskWeights.from_file(Path(get_settings().risk_weights_path))

BRUTE = {"same_port_ratio_60": 1.0, "conn_count_60": 120, "uniq_dst_ips_60": 1}


def _ids(values: dict) -> set[str]:
    return {r.id for r in RULES.evaluate(values)}


def test_ssh_brute_force_matches_from_any_direction() -> None:
    for direction in ("inbound", "internal"):
        assert "SIG-BRUTE-001" in _ids({**BRUTE, "dst_port": 22, "direction": direction})


def test_internal_database_connection_pool_is_not_brute_force() -> None:
    # App server -> PostgreSQL at 3 connections/s: identical shape to password guessing.
    assert not ({"SIG-BRUTE-001", "SIG-BRUTE-002"} & _ids({**BRUTE, "dst_port": 5432, "direction": "internal"}))


def test_external_database_brute_force_matches() -> None:
    assert "SIG-BRUTE-002" in _ids({**BRUTE, "dst_port": 5432, "direction": "inbound"})


def test_port_scan_rule_and_thresholds_come_from_config() -> None:
    assert "SIG-SCAN-001" in _ids({"uniq_dst_ports_60": 45, "failed_ratio_60": 0.9})
    assert "SIG-SCAN-001" not in _ids({"uniq_dst_ports_60": 45, "failed_ratio_60": 0.1})


def test_missing_fields_never_match() -> None:
    assert _ids({}) == set()


def test_risk_formula_reproduces_the_specification_example() -> None:
    # Anomaly 94, behaviour 88, threat intel 80, asset criticality 95, no signature -> about 91.
    r = compute_risk({"signature": 0, "anomaly": 94, "behavioral": 88, "threat_intel": 80}, 95, 0, WEIGHTS)
    assert 90 <= r.score <= 92
    assert r.components["signature"] == 0 and r.components["asset_criticality"] == 95
    assert r.reason.startswith("No known signature matched, but")


def test_risk_is_monotonic_and_bounded() -> None:
    low = compute_risk({"anomaly": 60}, 50, 0, WEIGHTS).score
    high = compute_risk({"anomaly": 60, "behavioral": 70}, 50, 0, WEIGHTS).score
    assert 0 < low < high <= 100
    assert compute_risk({"signature": 100, "anomaly": 100, "behavioral": 100, "threat_intel": 100}, 100, 100,
                        WEIGHTS).score <= 100
    assert compute_risk({}, None, 0, WEIGHTS).score == 0


def test_explanations_only_list_out_of_range_features() -> None:
    bundle = ModelBundle()
    names = bundle.feature_names
    bundle.raw_median = dict.fromkeys(names, 1.0)
    bundle.raw_p99 = dict.fromkeys(names, 5.0)
    raw = np.ones(len(names))
    contrib = np.zeros(len(names))
    idx_normal, idx_high = names.index("conn_count_60"), names.index("uniq_dst_ports_60")
    raw[idx_high] = 40.0
    contrib[idx_normal], contrib[idx_high] = 0.6, 0.4  # the in-range feature has the larger share
    factors = bundle.explain_row(contrib, raw)
    assert [f["feature"] for f in factors] == ["uniq_dst_ports_60"]
    assert "40.0×" in factors[0]["detail"]
    # Nothing out of range -> an honest "combination" note instead of a made-up reason.
    raw[idx_high] = 1.0
    only = bundle.explain_row(contrib, raw)
    assert [f["feature"] for f in only] == ["feature_combination"]
