"""Shared helpers for command-line tools."""

from __future__ import annotations

import json
import logging
from typing import Any

from app.core.config import get_settings
from app.core.logging import configure_logging


def setup() -> None:
    settings = get_settings()
    configure_logging(settings.log_level, json_logs=False)
    logging.getLogger("app").setLevel(logging.INFO)


def dump(obj: Any) -> str:
    return json.dumps(obj, indent=2, default=str)
