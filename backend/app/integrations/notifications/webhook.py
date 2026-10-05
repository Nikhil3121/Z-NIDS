"""Outbound webhooks (generic signed JSON and Slack-compatible) with SSRF protection."""

from __future__ import annotations

import ipaddress
import json
import logging
import socket
import time
from typing import Any
from urllib.parse import urlsplit

import httpx

from app.core.config import get_settings
from app.core.security import sign_payload

logger = logging.getLogger(__name__)


class UnsafeTargetError(ValueError):
    """The URL resolves to an address outbound integrations may not reach."""


def _address_allowed(addr: ipaddress.IPv4Address | ipaddress.IPv6Address, allow_private: bool) -> bool:
    if addr.is_loopback or addr.is_link_local or addr.is_multicast or addr.is_unspecified or addr.is_reserved:
        return False  # never: metadata services (169.254.169.254), localhost, etc.
    return not (addr.is_private and not allow_private)


def validate_target(url: str) -> str:
    """Validate scheme/host and every resolved address. Returns the normalised URL.

    Residual risk: DNS can change between this check and the connection (DNS
    rebinding). Production deployments should additionally route webhooks
    through an egress proxy that enforces the same policy (docs/security.md).
    """
    settings = get_settings()
    parts = urlsplit(url.strip())
    if parts.scheme not in ("https", "http"):
        raise UnsafeTargetError("webhook URL must use http(s)")
    if parts.scheme != "https" and settings.is_production_like:
        raise UnsafeTargetError("webhook URL must use https outside development")
    if not parts.hostname:
        raise UnsafeTargetError("webhook URL has no host")
    if parts.username or parts.password:
        raise UnsafeTargetError("credentials in webhook URLs are not allowed")
    port = parts.port or (443 if parts.scheme == "https" else 80)
    try:
        infos = socket.getaddrinfo(parts.hostname, port, proto=socket.IPPROTO_TCP)
    except socket.gaierror as exc:
        raise UnsafeTargetError(f"cannot resolve {parts.hostname}") from exc
    for info in infos:
        addr = ipaddress.ip_address(info[4][0])
        if not _address_allowed(addr, settings.webhook_allow_private_targets):
            raise UnsafeTargetError(f"{parts.hostname} resolves to a disallowed address")
    return url.strip()


def post_json(url: str, payload: dict[str, Any], *, sign: bool) -> int:
    """POST JSON to a validated URL. Raises on network failure or non-2xx."""
    settings = get_settings()
    target = validate_target(url)
    body = json.dumps(payload, default=str, separators=(",", ":")).encode()
    headers = {"Content-Type": "application/json", "User-Agent": "Z-NIDS-Notifier/1.0"}
    if sign:
        if not settings.webhook_signing_secret:
            raise RuntimeError("WEBHOOK_SIGNING_SECRET is not configured; refusing to send unsigned webhook")
        headers["X-ZNIDS-Signature"] = sign_payload(body, settings.webhook_signing_secret, int(time.time()))
    resp = httpx.post(
        target, content=body, headers=headers, timeout=settings.webhook_timeout_seconds, follow_redirects=False
    )
    if not 200 <= resp.status_code < 300:
        raise RuntimeError(f"webhook returned HTTP {resp.status_code}")
    return resp.status_code


def slack_payload(title: str, body: str, link: str | None) -> dict[str, Any]:
    text = f"*{title}*\n{body}"
    if link:
        text += f"\n<{link}|Open in Z-NIDS>"
    return {"text": text}
