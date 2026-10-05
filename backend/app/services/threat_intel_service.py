"""Threat-intelligence lookups (cached, rate-limited, audited) and local IOC management."""

from __future__ import annotations

import ipaddress
import logging
import re
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
from typing import Any

from sqlalchemy import or_, select
from sqlalchemy.dialects.postgresql import insert
from sqlalchemy.orm import Session

from app.core.config import get_settings
from app.core.exceptions import RateLimitedError, ValidationFailedError
from app.core.rate_limit import rate_limiter
from app.detection.base import Detector, EventContext, Signal
from app.integrations.threat_intel.providers import (
    IntelResult,
    ProviderUnavailableError,
    ThreatIntelProvider,
    all_providers,
    external_providers,
)
from app.models.enums import DetectorType, IocType, Reputation, Severity
from app.models.threat_intel import ThreatIntelIndicator
from app.models.user import User
from app.services import audit_service
from app.services.audit_service import RequestMeta

logger = logging.getLogger(__name__)

_DOMAIN = re.compile(r"^(?=.{1,253}$)([a-z0-9](-?[a-z0-9])*\.)+[a-z]{2,63}$")
_HASH = re.compile(r"^[a-f0-9]{32}$|^[a-f0-9]{40}$|^[a-f0-9]{64}$")


def normalize_ioc(ioc_type: IocType, value: str) -> str:
    value = value.strip()
    if ioc_type == IocType.IP:
        try:
            return str(ipaddress.ip_address(value))
        except ValueError as exc:
            raise ValidationFailedError("Invalid IP address") from exc
    if ioc_type == IocType.DOMAIN:
        value = value.lower().rstrip(".")
        if not _DOMAIN.match(value):
            raise ValidationFailedError("Invalid domain")
        return value
    if ioc_type == IocType.HASH:
        value = value.lower()
        if not _HASH.match(value):
            raise ValidationFailedError("Hash must be MD5, SHA-1 or SHA-256 hex")
        return value
    if ioc_type == IocType.URL:
        if not re.match(r"^https?://[^\s]{1,2000}$", value):
            raise ValidationFailedError("Invalid URL")
        return value
    raise ValidationFailedError("Unsupported IOC type")


def _upsert(db: Session, result: IntelResult, ttl_hours: int) -> ThreatIntelIndicator:
    now = datetime.now(UTC)
    values = {
        "ioc_type": result.ioc_type,
        "ioc_value": result.ioc_value,
        "provider": result.provider,
        "confidence": max(0.0, min(100.0, result.confidence)),
        "reputation": result.reputation,
        "source": result.source,
        "tags": result.tags,
        "raw_metadata": result.raw,
        "first_seen": result.first_seen,
        "last_seen": result.last_seen,
        "fetched_at": now,
        "expires_at": now + timedelta(hours=ttl_hours),
    }
    stmt = insert(ThreatIntelIndicator).values(**values)
    stmt = stmt.on_conflict_do_update(
        constraint="uq_ti_ioc_provider",
        set_={k: stmt.excluded[k] for k in values if k not in ("ioc_type", "ioc_value", "provider")},
    ).returning(ThreatIntelIndicator.id)
    ind_id = db.execute(stmt).scalar_one()
    indicator = db.get(ThreatIntelIndicator, ind_id)
    assert indicator is not None
    return indicator


@dataclass
class LookupOutcome:
    ioc_type: IocType
    ioc_value: str
    indicators: list[ThreatIntelIndicator]
    provider_status: list[dict[str, Any]]


def lookup(
    db: Session,
    ioc_type: IocType,
    raw_value: str,
    *,
    user: User | None,
    meta: RequestMeta | None,
    refresh: bool = False,
    providers: list[ThreatIntelProvider] | None = None,
) -> LookupOutcome:
    settings = get_settings()
    value = normalize_ioc(ioc_type, raw_value)
    now = datetime.now(UTC)
    statuses: list[dict[str, Any]] = []
    for provider in providers if providers is not None else external_providers():
        status: dict[str, Any] = {"provider": provider.name}
        if ioc_type not in provider.supported:
            status.update(status="not_applicable")
        elif not provider.configured():
            status.update(status="unavailable", reason="credentials not configured")
        else:
            cached = db.scalar(
                select(ThreatIntelIndicator).where(
                    ThreatIntelIndicator.ioc_type == ioc_type,
                    ThreatIntelIndicator.ioc_value == value,
                    ThreatIntelIndicator.provider == provider.name,
                )
            )
            if cached is not None and not refresh and cached.expires_at and cached.expires_at > now:
                status.update(status="cached", fetched_at=cached.fetched_at.isoformat())
            else:
                try:
                    rate_limiter.hit(
                        "ti-provider", provider.name, settings.threat_intel_requests_per_minute, fail_closed=True
                    )
                    _upsert(db, provider.lookup_ioc(ioc_type, value), settings.threat_intel_cache_ttl_hours)
                    status.update(status="fetched")
                except RateLimitedError:
                    status.update(status="rate_limited")
                except (ProviderUnavailableError, ValueError) as exc:
                    logger.warning("threat intel provider failed", extra={"provider": provider.name, "error": str(exc)})
                    status.update(status="error", reason=str(exc)[:200])
        statuses.append(status)

    indicators = list(
        db.scalars(
            select(ThreatIntelIndicator)
            .where(ThreatIntelIndicator.ioc_type == ioc_type, ThreatIntelIndicator.ioc_value == value)
            .order_by(ThreatIntelIndicator.provider)
        ).all()
    )
    audit_service.record(
        db,
        "THREAT_INTEL_LOOKUP",
        actor=user,
        resource_type="ioc",
        resource_id=f"{ioc_type.value}:{value}"[:64],
        meta=meta,
        details={"providers": statuses, "matches": len(indicators)},
    )
    return LookupOutcome(ioc_type, value, indicators, statuses)


def provider_statuses() -> list[dict[str, Any]]:
    return [p.status() for p in all_providers()]


def create_local_ioc(
    db: Session,
    *,
    ioc_type: IocType,
    value: str,
    reputation: Reputation,
    confidence: float,
    source: str | None,
    tags: list[str],
    user: User,
    meta: RequestMeta,
) -> ThreatIntelIndicator:
    normalized = normalize_ioc(ioc_type, value)
    existing = db.scalar(
        select(ThreatIntelIndicator).where(
            ThreatIntelIndicator.ioc_type == ioc_type,
            ThreatIntelIndicator.ioc_value == normalized,
            ThreatIntelIndicator.provider == "local",
        )
    )
    now = datetime.now(UTC)
    if existing is None:
        existing = ThreatIntelIndicator(ioc_type=ioc_type, ioc_value=normalized, provider="local", first_seen=now)
        db.add(existing)
    existing.reputation = reputation
    existing.confidence = confidence
    existing.source = source or f"analyst:{user.email}"
    existing.tags = tags
    existing.last_seen = now
    existing.fetched_at = now
    existing.expires_at = None
    existing.created_by_id = user.id
    db.flush()
    audit_service.record(
        db,
        "IOC_UPSERTED",
        actor=user,
        resource_type="ioc",
        resource_id=existing.id,
        meta=meta,
        details={"type": ioc_type.value, "value": normalized, "reputation": reputation.value},
    )
    return existing


class ThreatIntelDetector(Detector):
    """Matches flow endpoints against *already known* indicators in the database.

    The hot path never calls external providers (rate limits, latency); fresh
    provider lookups happen asynchronously for alerting IPs and on demand.
    """

    name = "threat_intel_matcher"
    detector_type = DetectorType.THREAT_INTEL

    def __init__(self, db: Session) -> None:
        self.db = db

    def detect_batch(self, contexts: list[EventContext]) -> dict[int, list[Signal]]:
        ips = sorted({c.src_ip for c in contexts} | {c.dst_ip for c in contexts})
        if not ips:
            return {}
        now = datetime.now(UTC)
        found: dict[str, list[ThreatIntelIndicator]] = {}
        for i in range(0, len(ips), 1000):
            rows = self.db.scalars(
                select(ThreatIntelIndicator).where(
                    ThreatIntelIndicator.ioc_type == IocType.IP,
                    ThreatIntelIndicator.ioc_value.in_(ips[i : i + 1000]),
                    ThreatIntelIndicator.reputation.in_([Reputation.MALICIOUS, Reputation.SUSPICIOUS]),
                    or_(ThreatIntelIndicator.expires_at.is_(None), ThreatIntelIndicator.expires_at > now),
                )
            ).all()
            for r in rows:
                found.setdefault(r.ioc_value, []).append(r)
        out: dict[int, list[Signal]] = {}
        for ctx in contexts:
            for role, ip in (("source", ctx.src_ip), ("destination", ctx.dst_ip)):
                for ind in found.get(ip, []):
                    malicious = ind.reputation == Reputation.MALICIOUS
                    component = ind.confidence * (1.0 if malicious else 0.5)
                    out.setdefault(ctx.index, []).append(
                        Signal(
                            detector=self.detector_type,
                            category="threat_intel_match",
                            component=component,
                            confidence=ind.confidence / 100.0,
                            severity=Severity.HIGH if malicious and ind.confidence >= 75 else Severity.MEDIUM,
                            summary=f"The {role} {ip} is listed as {ind.reputation.value} by {ind.provider} "
                            f"(confidence {ind.confidence:.0f}).",
                            factors=[
                                {
                                    "feature": "ioc",
                                    "value": ip,
                                    "provider": ind.provider,
                                    "indicator_id": ind.id,
                                    "reputation": ind.reputation.value,
                                    "detail": f"{role} {ip}: {ind.reputation.value} ({ind.provider}, "
                                    f"confidence {ind.confidence:.0f})",
                                }
                            ],
                            verdict="KNOWN_ATTACK" if malicious else "ANOMALOUS",
                            extra={"indicator_id": ind.id},
                        )
                    )
        return out
