"""Shared helpers for list endpoints: pagination, whitelisted sorting, demo filtering."""

from __future__ import annotations

import ipaddress
import math
from collections.abc import Callable, Sequence
from typing import Any, TypeVar

from fastapi import Query
from sqlalchemy import Select, func, select
from sqlalchemy.orm import Session

from app.core.exceptions import ValidationFailedError
from app.schemas.common import Page, PageParams

T = TypeVar("T")


def page_params(
    page: int = Query(1, ge=1, le=100_000),
    page_size: int = Query(25, ge=1, le=200),
) -> PageParams:
    return PageParams(page=page, page_size=page_size)


def apply_sort(stmt: Select[Any], sort: str | None, allowed: dict[str, Any], default: Any) -> Select[Any]:
    """`sort` is `field` or `-field`; only whitelisted fields are accepted (no raw SQL from clients)."""
    if not sort:
        return stmt.order_by(default)
    desc = sort.startswith("-")
    key = sort.lstrip("-")
    column = allowed.get(key)
    if column is None:
        raise ValidationFailedError(f"Cannot sort by '{key}'", details={"allowed": sorted(allowed)})
    return stmt.order_by(column.desc() if desc else column.asc())


def paginate[T](
    db: Session, stmt: Select[Any], params: PageParams, mapper: Callable[[Any], T], *, scalars: bool = True
) -> Page[T]:
    total = db.scalar(select(func.count()).select_from(stmt.order_by(None).subquery())) or 0
    result = db.execute(stmt.limit(params.page_size).offset(params.offset))
    rows: Sequence[Any] = result.scalars().all() if scalars else result.all()
    return Page[T](
        items=[mapper(r) for r in rows],
        total=int(total),
        page=params.page,
        page_size=params.page_size,
        pages=max(1, math.ceil(total / params.page_size)) if total else 0,
    )


def parse_ip(value: str | None, name: str = "ip") -> str | None:
    """Validate an IP query parameter before it reaches an INET comparison."""
    if value is None or value == "":
        return None
    try:
        return str(ipaddress.ip_address(value.strip()))
    except ValueError as exc:
        raise ValidationFailedError(f"'{name}' must be an IP address") from exc
