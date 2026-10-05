"""Configurable signature engine.

Rules are declarative JSON (config/signature_rules.json): every threshold is
data, validated at load time. Also turns alerts forwarded by an external IDS
(e.g. Suricata `alert` events) into known-attack signals.
"""

from __future__ import annotations

import json
import logging
import operator
import re
from collections.abc import Callable
from pathlib import Path
from typing import Any

from pydantic import BaseModel, Field, field_validator

from app.detection.base import Detector, EventContext, Signal
from app.models.enums import DetectorType, Severity

logger = logging.getLogger(__name__)

_OPS: dict[str, Callable[[Any, Any], bool]] = {
    ">=": operator.ge,
    ">": operator.gt,
    "<=": operator.le,
    "<": operator.lt,
    "==": operator.eq,
    "!=": operator.ne,
    "in": lambda a, b: a in b,
    "not_in": lambda a, b: a not in b,
}

_SEVERITY_COMPONENT = {"critical": 100.0, "high": 85.0, "medium": 60.0, "low": 35.0, "info": 10.0}
_SURICATA_SEVERITY = {1: Severity.HIGH, 2: Severity.MEDIUM, 3: Severity.LOW}


class Condition(BaseModel):
    field: str = Field(pattern=r"^[a-z0-9_]{1,48}$")
    op: str
    value: Any

    @field_validator("op")
    @classmethod
    def _known_op(cls, v: str) -> str:
        if v not in _OPS:
            raise ValueError(f"unsupported operator {v!r}")
        return v


class Rule(BaseModel):
    id: str = Field(pattern=r"^[A-Z0-9\-]{3,32}$")
    name: str
    category: str = Field(pattern=r"^[a-z0-9_]{2,48}$")
    severity: Severity
    enabled: bool = True
    description: str = ""
    all: list[Condition] = Field(default_factory=list)
    any: list[Condition] = Field(default_factory=list)


class RuleSet(BaseModel):
    version: str
    rules: list[Rule]


def load_rules(path: Path) -> RuleSet:
    data = json.loads(path.read_text(encoding="utf-8"))
    ruleset = RuleSet.model_validate(data)
    ids = [r.id for r in ruleset.rules]
    if len(ids) != len(set(ids)):
        raise ValueError("duplicate signature rule ids")
    return ruleset


def _holds(cond: Condition, values: dict[str, Any]) -> bool:
    if cond.field not in values or values[cond.field] is None:
        return False
    try:
        return bool(_OPS[cond.op](values[cond.field], cond.value))
    except TypeError:
        return False


def _describe(cond: Condition, values: dict[str, Any]) -> dict[str, Any]:
    actual = values.get(cond.field)
    shown = f"{actual:g}" if isinstance(actual, float) else str(actual)
    return {"feature": cond.field, "value": actual, "detail": f"{cond.field} = {shown} ({cond.op} {cond.value})"}


class SignatureDetector(Detector):
    name = "signature_engine"
    detector_type = DetectorType.SIGNATURE

    def __init__(self, ruleset: RuleSet) -> None:
        self.ruleset = ruleset
        self.rules = [r for r in ruleset.rules if r.enabled]

    @classmethod
    def from_file(cls, path: Path) -> SignatureDetector:
        return cls(load_rules(path))

    def evaluate(self, values: dict[str, Any]) -> list[Rule]:
        hits = []
        for rule in self.rules:
            if rule.all and not all(_holds(c, values) for c in rule.all):
                continue
            if rule.any and not any(_holds(c, values) for c in rule.any):
                continue
            if not rule.all and not rule.any:
                continue
            hits.append(rule)
        return hits

    def detect_batch(self, contexts: list[EventContext]) -> dict[int, list[Signal]]:
        out: dict[int, list[Signal]] = {}
        for ctx in contexts:
            signals: list[Signal] = []
            for rule in self.evaluate(ctx.values):
                signals.append(
                    Signal(
                        detector=self.detector_type,
                        category=rule.category,
                        component=_SEVERITY_COMPONENT[rule.severity.value],
                        confidence=0.9,
                        severity=rule.severity,
                        summary=f"{rule.name}: {rule.description}",
                        factors=[_describe(c, ctx.values) for c in (rule.all or rule.any)],
                        rule_id=rule.id,
                        verdict="KNOWN_ATTACK",
                    )
                )
            if ctx.external_alert:
                signals.append(self._external(ctx.external_alert))
            if signals:
                out[ctx.index] = signals
        return out

    @staticmethod
    def _external(alert: dict[str, Any]) -> Signal:
        signature = str(alert.get("signature", "external IDS alert"))[:200]
        sev_raw = alert.get("severity")
        severity = _SURICATA_SEVERITY.get(sev_raw if isinstance(sev_raw, int) else 2, Severity.MEDIUM)
        category_raw = str(alert.get("category") or "")
        category = re.sub(r"[^a-z0-9]+", "_", category_raw.lower()).strip("_")[:48] or "external_ids_alert"
        return Signal(
            detector=DetectorType.SIGNATURE,
            category="external_ids_alert",
            component=_SEVERITY_COMPONENT[severity.value],
            confidence=0.85,
            severity=severity,
            summary=f"External IDS signature matched: {signature}",
            factors=[
                {
                    "feature": "external_alert",
                    "value": signature,
                    "detail": f"Sensor signature '{signature}' (category: {category_raw or 'n/a'})",
                }
            ],
            rule_id=str(alert.get("signature_id") or "EXT"),
            verdict="KNOWN_ATTACK",
            extra={"external_category": category},
        )

    def status(self) -> dict[str, Any]:
        return {
            "name": self.name,
            "available": True,
            "ruleset_version": self.ruleset.version,
            "enabled_rules": len(self.rules),
        }
