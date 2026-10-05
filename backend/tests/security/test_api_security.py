"""Security behaviour of the HTTP API (needs PostgreSQL)."""

from __future__ import annotations

import re

import pytest
from sqlalchemy import select

from app.models.audit import AuditLog
from app.models.enums import AuditResult, RoleName
from tests.support import as_role, make_user

PATH_PARAM = re.compile(r"\{[^}]+\}")


def _protected_operations(client) -> list[tuple[str, str]]:
    spec = client.app.openapi()
    public = {"/health", "/ready", "/api/v1/auth/login", "/api/v1/auth/refresh", "/api/v1/auth/logout",
              "/api/v1/auth/activate", "/api/v1/auth/password-reset/request", "/api/v1/auth/password-reset/confirm"}
    ops = []
    for path, methods in spec["paths"].items():
        if path in public or path.startswith("/api/v1/events/ingest"):
            continue
        for method in methods:
            ops.append((method.upper(), PATH_PARAM.sub("1", path)))
    return ops


def test_every_protected_endpoint_requires_authentication(client, db) -> None:
    ops = _protected_operations(client)
    assert len(ops) > 70
    for method, path in ops:
        r = client.request(method, path)
        assert r.status_code == 401, f"{method} {path} -> {r.status_code}"
        assert r.json()["error"]["code"] in ("AUTHENTICATION_REQUIRED",), (method, path)


@pytest.mark.parametrize("token", ["garbage", "a.b.c", "eyJhbGciOiJub25lIn0.eyJzdWIiOiIxIn0."])
def test_invalid_jwt_rejected(client, db, token) -> None:
    r = client.get("/api/v1/alerts", headers={"Authorization": f"Bearer {token}"})
    assert r.status_code == 401 and r.json()["error"]["code"] == "TOKEN_INVALID"


def test_sensor_key_required_and_audited(client, db) -> None:
    assert client.post("/api/v1/events/ingest", json={"events": [{}]}).status_code == 401
    r = client.post("/api/v1/events/ingest", headers={"X-Sensor-Key": "zns_forged"}, json={"events": [{}]})
    assert r.status_code == 401
    assert db.scalar(select(AuditLog).where(AuditLog.action == "SENSOR_AUTH_FAILED")) is not None


@pytest.mark.parametrize(
    ("role", "method", "path", "body"),
    [
        (RoleName.VIEWER, "PATCH", "/api/v1/alerts/1", {"status": "ACKNOWLEDGED"}),
        (RoleName.VIEWER, "PATCH", "/api/v1/incidents/1001", {"status": "INVESTIGATING"}),
        (RoleName.VIEWER, "POST", "/api/v1/assistant/ask", {"question": "what happened?"}),
        (RoleName.SECURITY_ANALYST, "GET", "/api/v1/users", None),
        (RoleName.SECURITY_ANALYST, "POST", "/api/v1/users", {"email": "x@example.com", "name": "X", "role": "ADMIN"}),
        (RoleName.SECURITY_ANALYST, "GET", "/api/v1/audit", None),
        (RoleName.SECURITY_ANALYST, "POST", "/api/v1/models/1/activate", None),
        (RoleName.SECURITY_ANALYST, "POST", "/api/v1/response/actions/1/decision", {"approve": True}),
        (RoleName.SECURITY_MANAGER, "POST", "/api/v1/sensors", {"name": "s1", "sensor_type": "zeek"}),
        (RoleName.SECURITY_MANAGER, "PATCH", "/api/v1/users/1", {"role": "ADMIN"}),
    ],
)
def test_privilege_escalation_is_denied_and_audited(client, db, role, method, path, body) -> None:
    headers = as_role(client, db, role)
    r = client.request(method, path, headers=headers, json=body)
    assert r.status_code == 403, r.text
    assert r.json()["error"]["code"] == "PERMISSION_DENIED"
    denial = db.scalar(select(AuditLog).where(AuditLog.action == "AUTHORIZATION_DENIED"))
    assert denial is not None and denial.result == AuditResult.DENIED


def test_admin_cannot_demote_self(client, db) -> None:
    headers = as_role(client, db, RoleName.ADMIN)
    me = client.get("/api/v1/auth/me", headers=headers).json()
    r = client.patch(f"/api/v1/users/{me['id']}", headers=headers, json={"role": "VIEWER"})
    assert r.status_code == 403


def test_role_change_revokes_existing_tokens(client, db) -> None:
    admin = as_role(client, db, RoleName.ADMIN)
    user = make_user(db, "victim@example.com", RoleName.SECURITY_MANAGER)
    from tests.support import login

    victim = login(client, "victim@example.com")
    assert client.get("/api/v1/audit", headers=victim).status_code == 200
    assert client.patch(f"/api/v1/users/{user.id}", headers=admin, json={"role": "VIEWER"}).status_code == 200
    assert client.get("/api/v1/audit", headers=victim).status_code == 401


@pytest.mark.parametrize(
    "query",
    [
        "/api/v1/events?sort=id;DROP TABLE users",
        "/api/v1/events?sort=password_hash",
        "/api/v1/events?src_ip=1'%20OR%20'1'='1",
        "/api/v1/alerts?ip=10.0.0.1%27--",
        "/api/v1/detections?category=x%27%20OR%201=1",
        "/api/v1/audit?action=LOGIN%27;--",
        "/api/v1/models/compare?ids=1);DROP",
    ],
)
def test_injection_attempts_are_rejected_by_validation(client, db, query) -> None:
    headers = as_role(client, db, RoleName.ADMIN)
    r = client.get(query, headers=headers)
    assert r.status_code == 422, (query, r.status_code, r.text)
    assert "Traceback" not in r.text and "psycopg" not in r.text


def test_search_text_is_parameterised(client, db) -> None:
    headers = as_role(client, db, RoleName.ADMIN)
    r = client.get("/api/v1/alerts?q=%25'%20OR%201=1--", headers=headers)
    assert r.status_code == 200 and r.json()["total"] == 0


def test_malformed_json_and_unknown_fields(client, db) -> None:
    r = client.post("/api/v1/auth/login", content="{not json", headers={"Content-Type": "application/json"})
    assert r.status_code == 422 and r.json()["error"]["code"] == "VALIDATION_ERROR"
    r = client.post("/api/v1/auth/login", json={"email": "a@example.com", "password": "x", "is_admin": True})
    assert r.status_code == 422


def test_oversized_body_rejected(client, db) -> None:
    r = client.post("/api/v1/auth/login", content=b"x" * (6 * 1024 * 1024),
                    headers={"Content-Type": "application/json"})
    assert r.status_code == 413 and r.json()["error"]["code"] == "PAYLOAD_TOO_LARGE"


def test_login_rate_limit(client, db) -> None:
    make_user(db, "rl@example.com", RoleName.VIEWER)
    codes = [client.post("/api/v1/auth/login", json={"email": "rl@example.com", "password": "wrong password!!"}).status_code
             for _ in range(12)]
    assert codes[-1] == 429
    r = client.post("/api/v1/auth/login", json={"email": "rl@example.com", "password": "wrong password!!"})
    assert r.status_code == 429 and int(r.headers["Retry-After"]) >= 1


def test_security_headers_and_no_stack_traces(client, db) -> None:
    r = client.get("/health")
    for header in ("x-content-type-options", "x-frame-options", "content-security-policy", "referrer-policy",
                   "x-request-id"):
        assert header in r.headers
    assert r.headers["x-frame-options"] == "DENY"
    missing = client.get("/api/v1/does-not-exist")
    assert missing.status_code == 404 and missing.json()["error"]["request_id"]


def test_cors_allows_only_configured_origin(client, db) -> None:
    ok = client.options("/api/v1/auth/login", headers={"Origin": "http://testserver.local",
                                                       "Access-Control-Request-Method": "POST"})
    assert ok.headers.get("access-control-allow-origin") == "http://testserver.local"
    bad = client.options("/api/v1/auth/login", headers={"Origin": "https://evil.example",
                                                        "Access-Control-Request-Method": "POST"})
    assert "access-control-allow-origin" not in bad.headers


def test_health_endpoints_expose_nothing_sensitive(client, db) -> None:
    ready = client.get("/ready")
    assert ready.status_code == 200 and ready.json() == {"status": "ready",
                                                         "checks": {"database": "ok", "redis": "ok"}}
    assert "postgres" not in ready.text.lower()


def test_webhook_ssrf_targets_refused(client, db) -> None:
    headers = as_role(client, db, RoleName.ADMIN)
    for target in ("http://127.0.0.1:8010/api", "http://169.254.169.254/latest/meta-data", "http://10.0.0.5/hook",
                   "file:///etc/passwd", "http://user:pw@example.com/"):
        r = client.post("/api/v1/notifications/channels", headers=headers,
                        json={"name": f"c{abs(hash(target))}", "channel_type": "webhook", "target": target,
                              "events": ["critical_alert"]})
        assert r.status_code == 422, (target, r.text)
