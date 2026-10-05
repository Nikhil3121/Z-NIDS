"""Shared schema building blocks: pagination, IP strings, ORM-safe base."""

from __future__ import annotations

from typing import Annotated, TypeVar

import email_validator
from email_validator import EmailNotValidError, validate_email
from pydantic import BaseModel, BeforeValidator, ConfigDict, Field


def _to_str(value: object) -> object:
    # psycopg returns INET columns as ipaddress objects.
    return None if value is None else str(value)


IPStr = Annotated[str, BeforeValidator(_to_str)]


# email-validator rejects every IANA special-use domain unconditionally. ".local"
# is a normal choice for internal SOC accounts, so allow it (the library's
# documented way to do this); .onion, .invalid, .localhost, .arpa stay rejected.
if "local" in email_validator.SPECIAL_USE_DOMAIN_NAMES:
    email_validator.SPECIAL_USE_DOMAIN_NAMES.remove("local")


def validate_email_address(value: object) -> str:
    """Syntax-only email check shared by the API and the CLI.

    Deliverability is never checked (no DNS lookups on login), so the same rule
    works for any account the CLI creates. Returns the address lower-cased.
    """
    if not isinstance(value, str):
        raise ValueError("email must be a string")
    try:
        result = validate_email(value.strip(), check_deliverability=False)
    except EmailNotValidError as exc:
        raise ValueError(f"not a valid email address: {exc}") from exc
    return result.normalized.lower()


Email = Annotated[str, BeforeValidator(validate_email_address)]


class Schema(BaseModel):
    """Base for response models: built from ORM objects, never returns them raw."""

    model_config = ConfigDict(from_attributes=True, populate_by_name=True)


class StrictInput(BaseModel):
    """Base for request bodies: unknown fields are rejected, strings stripped."""

    model_config = ConfigDict(extra="forbid", str_strip_whitespace=True)


T = TypeVar("T")


class Page[T](BaseModel):
    items: list[T]
    total: int
    page: int
    page_size: int
    pages: int


class PageParams(BaseModel):
    page: int = Field(1, ge=1, le=100_000)
    page_size: int = Field(25, ge=1, le=200)

    @property
    def offset(self) -> int:
        return (self.page - 1) * self.page_size


class Message(BaseModel):
    message: str
