"""Structured JSON logging with request correlation and secret redaction."""

from __future__ import annotations

import json
import logging
import re
import sys
from contextvars import ContextVar
from datetime import UTC, datetime
from typing import Any

request_id_var: ContextVar[str | None] = ContextVar("request_id", default=None)
correlation_id_var: ContextVar[str | None] = ContextVar("correlation_id", default=None)

_SENSITIVE_KEYS = re.compile(
    r"(password|passwd|secret|token|api[_-]?key|authorization|cookie|signature|smtp_password)",
    re.IGNORECASE,
)
# Bearer tokens / JWTs / long hex or base64 blobs that end up in free-text messages.
_SENSITIVE_VALUES = [
    (re.compile(r"(?i)bearer\s+[A-Za-z0-9\-_\.=]+"), "Bearer [REDACTED]"),
    (re.compile(r"eyJ[A-Za-z0-9_\-]+\.[A-Za-z0-9_\-]+\.[A-Za-z0-9_\-]+"), "[REDACTED]"),
    (re.compile(r"(?i)(password|secret|token|api_key)=([^&\s]+)"), r"\1=[REDACTED]"),
]
REDACTED = "[REDACTED]"

_RESERVED = set(vars(logging.LogRecord("", 0, "", 0, "", None, None))) | {"message", "asctime"}


def redact(value: Any, key: str | None = None) -> Any:
    """Recursively redact secrets from a log payload."""
    if key is not None and _SENSITIVE_KEYS.search(key):
        return REDACTED
    if isinstance(value, dict):
        return {k: redact(v, str(k)) for k, v in value.items()}
    if isinstance(value, list | tuple):
        return [redact(v) for v in value]
    if isinstance(value, str):
        return redact_text(value)
    return value


def redact_text(text: str) -> str:
    for pattern, replacement in _SENSITIVE_VALUES:
        text = pattern.sub(replacement, text)
    return text


class JsonFormatter(logging.Formatter):
    def format(self, record: logging.LogRecord) -> str:
        payload: dict[str, Any] = {
            "ts": datetime.fromtimestamp(record.created, UTC).isoformat(),
            "level": record.levelname,
            "logger": record.name,
            "message": redact_text(record.getMessage()),
        }
        if rid := request_id_var.get():
            payload["request_id"] = rid
        if cid := correlation_id_var.get():
            payload["correlation_id"] = cid
        extras = {k: v for k, v in record.__dict__.items() if k not in _RESERVED and not k.startswith("_")}
        if extras:
            payload.update(redact(extras))
        if record.exc_info:
            payload["exception"] = redact_text(self.formatException(record.exc_info))
        return json.dumps(payload, default=str)


class TextFormatter(logging.Formatter):
    """Human-readable dev format; structured extras are appended as key=value."""

    def format(self, record: logging.LogRecord) -> str:
        rid = request_id_var.get()
        prefix = f"[{rid[:8]}] " if rid else ""
        record.msg = redact_text(str(record.msg))
        line = prefix + super().format(record)
        extras = {k: v for k, v in record.__dict__.items() if k not in _RESERVED and not k.startswith("_")}
        if extras:
            line += " " + " ".join(f"{k}={v}" for k, v in redact(extras).items())
        return line


def configure_logging(level: str = "INFO", json_logs: bool = True) -> None:
    handler = logging.StreamHandler(sys.stdout)
    handler.setFormatter(
        JsonFormatter() if json_logs else TextFormatter("%(asctime)s %(levelname)s %(name)s: %(message)s")
    )
    root = logging.getLogger()
    root.handlers[:] = [handler]
    root.setLevel(level.upper())
    for noisy in ("uvicorn.access", "httpx", "httpcore"):
        logging.getLogger(noisy).setLevel(logging.WARNING)
