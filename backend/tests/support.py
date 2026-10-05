"""Helpers shared by integration and security tests."""

from __future__ import annotations

from datetime import UTC, datetime, timedelta
from typing import Any

from sqlalchemy import select
from sqlalchemy.orm import Session

from app.core.security import hash_password
from app.models.enums import RoleName
from app.models.user import Role, User

PASSWORD = "correct horse battery staple"


def make_user(db: Session, email: str, role: RoleName, *, active: bool = True, password: str = PASSWORD) -> User:
    role_row = db.scalar(select(Role).where(Role.name == role.value))
    assert role_row is not None
    user = User(email=email, name=email.split("@")[0].title(), role_id=role_row.id, is_active=active,
                password_hash=hash_password(password))
    db.add(user)
    db.commit()
    return user


def login(client: Any, email: str, password: str = PASSWORD) -> dict[str, str]:
    r = client.post("/api/v1/auth/login", json={"email": email, "password": password})
    assert r.status_code == 200, r.text
    return {"Authorization": f"Bearer {r.json()['access_token']}"}


def as_role(client: Any, db: Session, role: RoleName) -> dict[str, str]:
    email = f"{role.value.lower()}@example.com"
    make_user(db, email, role)
    return login(client, email)


def flow(ts: datetime, src: str, dst: str, dport: int, *, flags: str = "SA", state: str = "SF",
         bytes_out: int = 800, bytes_in: int = 4000, packets: int = 6, duration_ms: float = 40.0,
         protocol: str = "tcp", **extra: Any) -> dict[str, Any]:
    return {"ts": ts.isoformat(), "src_ip": src, "dst_ip": dst, "src_port": 50000 + dport % 10000,
            "dst_port": dport, "protocol": protocol, "tcp_flags": flags, "conn_state": state,
            "bytes_out": bytes_out, "bytes_in": bytes_in, "packets_out": packets, "packets_in": packets,
            "duration_ms": duration_ms, **extra}


def recent(seconds_ago: float = 0.0) -> datetime:
    return datetime.now(UTC) - timedelta(seconds=seconds_ago)
