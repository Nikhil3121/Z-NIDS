"""Threat-intelligence provider interface and adapters.

`ThreatIntelProvider.lookup_ioc()` returns a normalised result or raises
`ProviderUnavailableError`. A provider without credentials reports itself
unavailable; Z-NIDS never fabricates an intelligence verdict to fill the gap.
"""

from __future__ import annotations

import ipaddress
import logging
from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from datetime import UTC, datetime
from typing import Any

import httpx

from app.core.config import get_settings
from app.models.enums import IocType, Reputation

logger = logging.getLogger(__name__)


class ProviderUnavailableError(RuntimeError):
    pass


@dataclass
class IntelResult:
    provider: str
    ioc_type: IocType
    ioc_value: str
    reputation: Reputation
    confidence: float  # 0-100
    source: str
    tags: list[str] = field(default_factory=list)
    first_seen: datetime | None = None
    last_seen: datetime | None = None
    raw: dict[str, Any] = field(default_factory=dict)


class ThreatIntelProvider(ABC):
    name: str
    supported: tuple[IocType, ...]

    @abstractmethod
    def configured(self) -> bool: ...

    @abstractmethod
    def lookup_ioc(self, ioc_type: IocType, value: str) -> IntelResult: ...

    def status(self) -> dict[str, Any]:
        return {
            "provider": self.name,
            "status": "available" if self.configured() else "unavailable",
            "reason": None if self.configured() else "credentials not configured",
            "supported_ioc_types": [t.value for t in self.supported],
        }


class AbuseIPDBProvider(ThreatIntelProvider):
    """AbuseIPDB v2 `check` endpoint (https://docs.abuseipdb.com/#check-endpoint)."""

    name = "abuseipdb"
    supported = (IocType.IP,)
    URL = "https://api.abuseipdb.com/api/v2/check"

    def configured(self) -> bool:
        return bool(get_settings().abuseipdb_api_key)

    def lookup_ioc(self, ioc_type: IocType, value: str) -> IntelResult:
        if not self.configured():
            raise ProviderUnavailableError("AbuseIPDB API key not configured")
        if ioc_type != IocType.IP:
            raise ValueError("AbuseIPDB supports IP indicators only")
        addr = ipaddress.ip_address(value)
        if addr.is_private or addr.is_loopback or addr.is_reserved or addr.is_link_local:
            raise ValueError("refusing to send an internal/reserved address to an external provider")
        settings = get_settings()
        try:
            resp = httpx.get(
                self.URL,
                params={"ipAddress": str(addr), "maxAgeInDays": 90},
                headers={"Key": settings.abuseipdb_api_key, "Accept": "application/json"},
                timeout=settings.threat_intel_timeout_seconds,
                follow_redirects=False,
            )
        except httpx.HTTPError as exc:
            raise ProviderUnavailableError(f"AbuseIPDB request failed: {type(exc).__name__}") from exc
        if resp.status_code == 429:
            raise ProviderUnavailableError("AbuseIPDB rate limit reached")
        if resp.status_code != 200:
            raise ProviderUnavailableError(f"AbuseIPDB returned HTTP {resp.status_code}")
        data = resp.json().get("data", {})
        score = float(data.get("abuseConfidenceScore", 0))
        reputation = (
            Reputation.MALICIOUS
            if score >= 75
            else (
                Reputation.SUSPICIOUS
                if score >= 25
                else (
                    Reputation.BENIGN
                    if data.get("totalReports", 0) == 0 and data.get("isWhitelisted")
                    else Reputation.UNKNOWN
                )
            )
        )
        last = data.get("lastReportedAt")
        return IntelResult(
            provider=self.name,
            ioc_type=IocType.IP,
            ioc_value=str(addr),
            reputation=reputation,
            confidence=score,
            source="AbuseIPDB",
            tags=[f"reports:{data.get('totalReports', 0)}", f"country:{data.get('countryCode') or '?'}"],
            last_seen=datetime.fromisoformat(last.replace("Z", "+00:00")) if last else None,
            raw={
                k: data.get(k)
                for k in (
                    "abuseConfidenceScore",
                    "totalReports",
                    "numDistinctUsers",
                    "countryCode",
                    "usageType",
                    "isp",
                    "domain",
                    "isWhitelisted",
                    "lastReportedAt",
                )
            },
        )


class LocalIOCProvider(ThreatIntelProvider):
    """Analyst-managed indicators stored in Z-NIDS itself (always available).

    Lookups against it are served straight from the database by the service
    layer; this class exists so it appears alongside external providers.
    """

    name = "local"
    supported = (IocType.IP, IocType.DOMAIN, IocType.URL, IocType.HASH)

    def configured(self) -> bool:
        return True

    def lookup_ioc(self, ioc_type: IocType, value: str) -> IntelResult:
        raise ProviderUnavailableError("local indicators are resolved from the database")


def external_providers() -> list[ThreatIntelProvider]:
    return [AbuseIPDBProvider()]


def all_providers() -> list[ThreatIntelProvider]:
    return [LocalIOCProvider(), *external_providers()]


def now() -> datetime:
    return datetime.now(UTC)
