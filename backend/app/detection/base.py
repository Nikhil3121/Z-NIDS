"""Common detector interface.

Detectors are batch-oriented: the pipeline builds one `EventContext` per flow
(flow fields + window features in raw units) and every registered detector
returns zero or more `Signal`s per event. Detectors never touch each other; the
risk engine combines their signals. Adding a detector means implementing
`Detector.detect_batch` and registering it — nothing else changes.
"""

from __future__ import annotations

from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from typing import Any

from app.models.enums import DetectorType, Severity


@dataclass
class EventContext:
    index: int
    event_id: int
    ts: float
    src_ip: str
    dst_ip: str
    src_port: int | None
    dst_port: int | None
    protocol: str
    app_protocol: str | None
    direction: str
    external_alert: dict[str, Any] | None
    #: flow fields + raw (human-unit) window features, keyed by feature name
    values: dict[str, Any]


@dataclass
class Signal:
    detector: DetectorType
    category: str
    #: 0-100 contribution to the risk engine for this detector's component
    component: float
    confidence: float
    severity: Severity
    summary: str
    factors: list[dict[str, Any]] = field(default_factory=list)
    rule_id: str | None = None
    #: detector-specific verdict hint, e.g. "KNOWN_ATTACK", "POTENTIAL_UNKNOWN"
    verdict: str | None = None
    extra: dict[str, Any] = field(default_factory=dict)


class Detector(ABC):
    name: str
    detector_type: DetectorType

    @abstractmethod
    def detect_batch(self, contexts: list[EventContext]) -> dict[int, list[Signal]]:
        """Return signals keyed by EventContext.index (omit events with none)."""

    def status(self) -> dict[str, Any]:
        return {"name": self.name, "available": True}
