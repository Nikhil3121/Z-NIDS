"""Outbound email: SMTP in staging/production, .eml files in development."""

from __future__ import annotations

import logging
import smtplib
import ssl
import uuid
from datetime import UTC, datetime
from email.message import EmailMessage

from app.core.config import get_settings

logger = logging.getLogger(__name__)


class EmailNotConfiguredError(RuntimeError):
    pass


def email_configured() -> bool:
    settings = get_settings()
    if settings.email_backend == "file":
        return True
    return bool(settings.smtp_host and settings.email_from)


def send_email(to: str, subject: str, body: str) -> None:
    """Send a plain-text email. Raises on failure — callers record delivery status."""
    settings = get_settings()
    message = EmailMessage()
    message["From"] = settings.email_from or "z-nids@localhost"
    message["To"] = to
    message["Subject"] = subject
    message["Message-ID"] = f"<{uuid.uuid4().hex}@z-nids>"
    message["Date"] = datetime.now(UTC).strftime("%a, %d %b %Y %H:%M:%S +0000")
    message.set_content(body)

    if settings.email_backend == "file":
        if settings.is_production_like:
            raise EmailNotConfiguredError("file email backend is not allowed outside development")
        settings.email_file_dir.mkdir(parents=True, exist_ok=True)
        path = settings.email_file_dir / f"{datetime.now(UTC):%Y%m%dT%H%M%S}-{uuid.uuid4().hex[:8]}.eml"
        path.write_bytes(bytes(message))
        logger.info("email written to file backend", extra={"to_domain": to.split("@")[-1], "file": path.name})
        return

    if not email_configured():
        raise EmailNotConfiguredError("SMTP is not configured (SMTP_HOST / EMAIL_FROM)")
    context = ssl.create_default_context()
    with smtplib.SMTP(settings.smtp_host, settings.smtp_port, timeout=10) as smtp:
        if settings.smtp_use_tls:
            smtp.starttls(context=context)
        if settings.smtp_username:
            smtp.login(settings.smtp_username, settings.smtp_password)
        smtp.send_message(message)
    logger.info("email sent", extra={"to_domain": to.split("@")[-1]})
