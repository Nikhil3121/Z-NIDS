"""Authentication against a real PostgreSQL database."""

from __future__ import annotations

import email
import email.policy
import re
from pathlib import Path

from sqlalchemy import select

from app.core.config import get_settings
from app.models.audit import AuditLog
from app.models.enums import RoleName
from app.models.user import RefreshToken, User
from tests.support import PASSWORD, login, make_user

CSRF = {"X-ZNIDS-CSRF": "1"}


def test_login_success_sets_httponly_refresh_cookie(client, db) -> None:
    make_user(db, "ana@example.com", RoleName.SECURITY_ANALYST)
    r = client.post("/api/v1/auth/login", json={"email": "ANA@example.com", "password": PASSWORD})
    assert r.status_code == 200
    body = r.json()
    assert body["token_type"] == "bearer" and body["user"]["role"]["name"] == "SECURITY_ANALYST"
    assert "incidents:manage" in body["user"]["permissions"]
    cookie = r.headers["set-cookie"].lower()
    assert "znids_refresh=" in cookie and "httponly" in cookie and "samesite=strict" in cookie
    assert "path=/api/v1/auth" in cookie
    assert "password" not in r.text.lower()
    me = client.get("/api/v1/auth/me", headers={"Authorization": f"Bearer {body['access_token']}"})
    assert me.status_code == 200 and me.json()["email"] == "ana@example.com"
    assert db.scalar(select(AuditLog).where(AuditLog.action == "LOGIN")) is not None


def test_wrong_password_and_unknown_user_are_indistinguishable(client, db) -> None:
    make_user(db, "bob@example.com", RoleName.VIEWER)
    a = client.post("/api/v1/auth/login", json={"email": "bob@example.com", "password": "wrong password here"})
    b = client.post("/api/v1/auth/login", json={"email": "nobody@example.com", "password": "wrong password here"})
    assert a.status_code == b.status_code == 401
    assert a.json()["error"]["message"] == b.json()["error"]["message"]
    assert a.json()["error"]["code"] == b.json()["error"]["code"] == "INVALID_CREDENTIALS"


def test_account_locks_after_repeated_failures(client, db) -> None:
    user = make_user(db, "carl@example.com", RoleName.VIEWER)
    for _ in range(get_settings().max_failed_logins):
        client.post("/api/v1/auth/login", json={"email": "carl@example.com", "password": "not the password!"})
    r = client.post("/api/v1/auth/login", json={"email": "carl@example.com", "password": PASSWORD})
    assert r.status_code == 401 and r.json()["error"]["code"] == "ACCOUNT_LOCKED"
    db.refresh(user)
    assert user.locked_until is not None
    failures = db.scalars(select(AuditLog).where(AuditLog.action == "LOGIN_FAILED")).all()
    assert len(failures) >= get_settings().max_failed_logins


def test_inactive_user_cannot_log_in(client, db) -> None:
    make_user(db, "dora@example.com", RoleName.VIEWER, active=False)
    r = client.post("/api/v1/auth/login", json={"email": "dora@example.com", "password": PASSWORD})
    assert r.status_code == 401


def test_refresh_rotation_and_reuse_detection(client, db) -> None:
    make_user(db, "eve@example.com", RoleName.VIEWER)
    client.post("/api/v1/auth/login", json={"email": "eve@example.com", "password": PASSWORD})
    first = client.cookies.get("znids_refresh")
    assert client.post("/api/v1/auth/refresh").status_code == 403  # CSRF header required
    r = client.post("/api/v1/auth/refresh", headers=CSRF)
    assert r.status_code == 200
    second = client.cookies.get("znids_refresh")
    assert second and second != first
    # Replaying the rotated token revokes the whole family.
    client.cookies.set("znids_refresh", first, path="/api/v1/auth")
    replay = client.post("/api/v1/auth/refresh", headers=CSRF)
    assert replay.status_code == 401 and replay.json()["error"]["code"] == "REFRESH_REUSED"
    client.cookies.set("znids_refresh", second, path="/api/v1/auth")
    assert client.post("/api/v1/auth/refresh", headers=CSRF).status_code == 401
    assert all(t.revoked_at is not None for t in db.scalars(select(RefreshToken)).all())


def test_logout_all_revokes_access_tokens(client, db) -> None:
    make_user(db, "fay@example.com", RoleName.VIEWER)
    headers = login(client, "fay@example.com")
    assert client.post("/api/v1/auth/logout-all", headers=headers).status_code == 200
    r = client.get("/api/v1/auth/me", headers=headers)
    assert r.status_code == 401 and r.json()["error"]["code"] == "TOKEN_REVOKED"


def test_activation_and_password_reset_by_email(client, db) -> None:
    admin = make_user(db, "admin@example.com", RoleName.ADMIN)
    headers = login(client, admin.email)
    r = client.post("/api/v1/users", headers=headers,
                    json={"email": "new.analyst@example.com", "name": "New Analyst", "role": "SECURITY_ANALYST"})
    assert r.status_code == 201 and r.json()["is_active"] is False and r.json()["activation_email_sent"]
    mail_dir = Path(get_settings().email_file_dir)
    token = _token_from_mail(mail_dir, "activate")
    bad = client.post("/api/v1/auth/activate", json={"token": token, "password": "short"})
    assert bad.status_code == 422 and bad.json()["error"]["code"] == "WEAK_PASSWORD"
    ok = client.post("/api/v1/auth/activate", json={"token": token, "password": "a brand new passphrase"})
    assert ok.status_code == 200
    reused = client.post("/api/v1/auth/activate", json={"token": token, "password": "a brand new passphrase"})
    assert reused.status_code == 422 and reused.json()["error"]["code"] == "TOKEN_INVALID"
    login(client, "new.analyst@example.com", "a brand new passphrase")

    for f in mail_dir.glob("*.eml"):
        f.unlink()
    r = client.post("/api/v1/auth/password-reset/request", json={"email": "new.analyst@example.com"})
    unknown = client.post("/api/v1/auth/password-reset/request", json={"email": "ghost@example.com"})
    assert r.status_code == unknown.status_code == 202 and r.json() == unknown.json()
    reset = _token_from_mail(mail_dir, "reset-password")
    assert client.post("/api/v1/auth/password-reset/confirm",
                       json={"token": reset, "new_password": "another good passphrase"}).status_code == 200
    login(client, "new.analyst@example.com", "another good passphrase")
    user = db.scalar(select(User).where(User.email == "new.analyst@example.com"))
    assert user is not None and user.password_hash and "passphrase" not in user.password_hash


def _token_from_mail(mail_dir: Path, route: str) -> str:
    bodies = [email.message_from_bytes(f.read_bytes(), policy=email.policy.default).get_content()
              for f in sorted(mail_dir.glob("*.eml"))]
    for body in reversed(bodies):
        m = re.search(rf"/{route}\?token=([A-Za-z0-9_\-]+)", body)
        if m:
            return m.group(1)
    raise AssertionError(f"no {route} link in {len(bodies)} mails")
