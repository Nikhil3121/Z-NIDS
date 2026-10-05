"""Regression tests for bugs found while running the stack by hand, plus a GET-endpoint smoke sweep."""

from __future__ import annotations

import logging

import pytest

from app.cli import create_admin
from app.core.logging import TextFormatter
from app.models.enums import RoleName
from app.schemas.common import validate_email_address
from tests.support import PASSWORD, as_role, login, make_user


def test_internal_dot_local_account_can_log_in(client, db) -> None:
    # The dev admin is admin@znids.local; EmailStr rejected it with 422 before the password was checked.
    make_user(db, "admin@znids.local", RoleName.ADMIN)
    assert "Authorization" in login(client, "Admin@ZNIDS.local")


@pytest.mark.parametrize("bad", ["not-an-email", "a@b", "x@site.onion", "x@host.localhost", "x@y.invalid"])
def test_invalid_or_reserved_emails_still_rejected(client, bad) -> None:
    r = client.post("/api/v1/auth/login", json={"email": bad, "password": "x"})
    assert r.status_code == 422
    assert r.json()["error"]["details"][0]["loc"] == ["body", "email"]


def test_email_rule_is_shared_and_normalises() -> None:
    assert validate_email_address("  SOC.Lead@Corp.Local ") == "soc.lead@corp.local"
    with pytest.raises(ValueError):
        validate_email_address("nobody")


def test_create_admin_rejects_what_login_would_reject(db, monkeypatch, capsys) -> None:
    monkeypatch.setenv("ZNIDS_ADMIN_PASSWORD", PASSWORD)
    assert create_admin.main(["--email", "root@box.onion", "--name", "X"]) == 2
    assert "Invalid --email" in capsys.readouterr().err


def test_text_log_format_keeps_structured_fields() -> None:
    record = logging.LogRecord("znids.http", logging.INFO, __file__, 1, "request", None, None)
    record.method, record.path, record.status, record.token = "GET", "/api/v1/alerts", 200, "secret-value"
    line = TextFormatter("%(levelname)s %(name)s: %(message)s").format(record)
    assert "method=GET" in line and "path=/api/v1/alerts" in line and "status=200" in line
    assert "secret-value" not in line and "token=[REDACTED]" in line


# Paths that need a specific existing resource id; the sweep covers list endpoints.
_SKIP_PARAM = "{"


def test_every_get_endpoint_answers_admin_without_server_error(client, db) -> None:
    headers = as_role(client, db, RoleName.ADMIN)
    spec = client.get("/api/v1/openapi.json").json()
    prefix = spec.get("servers", [{}])[0].get("url", "") if spec.get("servers") else ""
    paths = sorted(prefix + p for p, ops in spec["paths"].items() if "get" in ops and _SKIP_PARAM not in p)
    paths = [p if p.startswith("/api/v1") else "/api/v1" + p for p in paths]
    assert len(paths) > 30
    failures, ok = {}, 0
    for path in paths:
        r = client.get(path, headers=headers)
        ok += r.status_code == 200
        if r.status_code >= 500:
            failures[path] = (r.status_code, r.text[:200])
    assert not failures, failures
    # Guard against a sweep that silently 404s everything (wrong prefix).
    assert ok >= len(paths) * 0.8, f"only {ok}/{len(paths)} returned 200"


def test_missing_resources_return_404_not_500(client, db) -> None:
    headers = as_role(client, db, RoleName.ADMIN)
    for path in ("/api/v1/incidents/999999", "/api/v1/alerts/999999", "/api/v1/detections/999999",
                 "/api/v1/assets/999999", "/api/v1/models/999999"):
        assert client.get(path, headers=headers).status_code == 404, path
