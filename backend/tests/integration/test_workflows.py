"""Incident workflow, response approvals (four-eyes), notifications, assistant and reports."""

from __future__ import annotations

from sqlalchemy import select

from app.models.audit import AuditLog
from app.models.enums import RoleName
from app.models.incident import Incident
from app.models.notification import Notification
from app.models.response import LabBlocklistEntry
from tests.support import as_role, flow, login, make_user, recent


def _make_incident(client, db) -> tuple[Incident, dict[str, str]]:
    admin = as_role(client, db, RoleName.ADMIN)
    key = client.post("/api/v1/sensors", headers=admin, json={"name": "lab-sensor", "sensor_type": "zeek"}).json()["api_key"]
    flood = [flow(recent(50 - i * 0.02), f"198.51.100.{1 + i % 60}", "10.1.0.80", 80, flags="S", state="S0",
                  bytes_out=60, bytes_in=0, packets=1, duration_ms=0.0) for i in range(1600)]
    for i in range(0, len(flood), 800):
        client.post("/api/v1/events/ingest", headers={"X-Sensor-Key": key}, json={"events": flood[i:i + 800]})
    incident = db.scalar(select(Incident))
    assert incident is not None
    return incident, admin


def test_incident_lifecycle_with_audit_and_notifications(client, db) -> None:
    incident, admin = _make_incident(client, db)
    analyst_user = make_user(db, "analyst@example.com", RoleName.SECURITY_ANALYST)
    analyst = login(client, "analyst@example.com")
    url = f"/api/v1/incidents/{incident.id}"

    r = client.patch(url, headers=admin, json={"assigned_to_id": analyst_user.id})
    assert r.status_code == 200 and r.json()["assigned_to"]["email"] == "analyst@example.com"
    note = db.scalar(select(Notification).where(Notification.user_id == analyst_user.id,
                                                Notification.event_type == "incident_assigned"))
    assert note is not None
    # Invalid jump straight to CONTAINED.
    r = client.patch(url, headers=analyst, json={"status": "CONTAINED"})
    assert r.status_code == 409 and r.json()["error"]["code"] == "INVALID_STATE_TRANSITION"
    for status in ("ACKNOWLEDGED", "INVESTIGATING", "CONFIRMED", "CONTAINED"):
        assert client.patch(url, headers=analyst, json={"status": status}).status_code == 200, status
    assert client.patch(url, headers=analyst, json={"severity": "high"}).status_code == 422  # reason required
    assert client.patch(url, headers=analyst,
                        json={"severity": "medium", "severity_reason": "Lab target only"}).status_code == 200
    assert client.post(f"{url}/notes", headers=analyst, json={"text": "Flood source list exported."}).status_code == 201
    assert client.patch(url, headers=analyst, json={"status": "RESOLVED"}).status_code == 422  # needs resolution
    r = client.patch(url, headers=analyst, json={"status": "RESOLVED", "resolution": "TRUE_POSITIVE",
                                                 "resolution_notes": "Upstream filtering applied."})
    assert r.status_code == 200 and r.json()["status"] == "RESOLVED"

    inv = client.get(f"{url}/investigation", headers=analyst).json()
    kinds = {t["kind"] for t in inv["timeline"]}
    assert {"detection", "alert", "activity"} <= kinds
    assert inv["notes"][0]["content"] == "Flood source list exported."
    assert inv["audit_visible"] is False  # analysts cannot read the audit log
    audit = client.get(f"/api/v1/audit?resource_type=incident&resource_id={incident.id}", headers=admin).json()
    actions = [a["action"] for a in audit["items"]]
    assert actions.count("INCIDENT_UPDATED") >= 6 and "INCIDENT_ASSIGNED" in actions


def test_response_requires_second_approver(client, db) -> None:
    incident, _admin = _make_incident(client, db)
    make_user(db, "req@example.com", RoleName.SECURITY_ANALYST)
    make_user(db, "boss@example.com", RoleName.SECURITY_MANAGER)
    requester, manager = login(client, "req@example.com"), login(client, "boss@example.com")

    internal = client.post("/api/v1/response/actions", headers=requester, json={
        "action_type": "BLOCK_IP", "target": "10.1.0.80", "reason": "should be refused", "incident_id": incident.id})
    assert internal.status_code == 422  # never block internal addresses
    r = client.post("/api/v1/response/actions", headers=requester, json={
        "action_type": "BLOCK_IP", "target": "198.51.100.7", "reason": "Flood source", "incident_id": incident.id})
    assert r.status_code == 201 and r.json()["status"] == "PROPOSED"
    action_id = r.json()["id"]
    dup = client.post("/api/v1/response/actions", headers=requester, json={
        "action_type": "BLOCK_IP", "target": "198.51.100.7", "reason": "again", "incident_id": incident.id})
    assert dup.status_code == 409
    # The requester (even if they held approval rights) cannot approve their own request.
    self_approve = client.post(f"/api/v1/response/actions/{action_id}/decision", headers=requester, json={"approve": True})
    assert self_approve.status_code == 403
    ok = client.post(f"/api/v1/response/actions/{action_id}/decision", headers=manager,
                     json={"approve": True, "comment": "Approved for lab"})
    assert ok.status_code == 200 and ok.json()["status"] == "EXECUTED"
    assert db.scalar(select(LabBlocklistEntry).where(LabBlocklistEntry.active.is_(True))) is not None
    revert = client.post(f"/api/v1/response/actions/{action_id}/revert", headers=manager)
    assert revert.status_code == 200 and revert.json()["status"] == "REVERTED"
    actions = {a.action for a in db.scalars(select(AuditLog)).all()}
    assert {"RESPONSE_PROPOSED", "RESPONSE_APPROVED", "RESPONSE_EXECUTED", "RESPONSE_REVERTED"} <= actions


def test_assistant_is_grounded_and_says_when_evidence_is_missing(client, db) -> None:
    incident, _admin = _make_incident(client, db)
    analyst = as_role(client, db, RoleName.SECURITY_ANALYST)
    r = client.post("/api/v1/assistant/ask", headers=analyst, json={"question": f"Summarize incident INC-{incident.id}"})
    body = r.json()
    assert r.status_code == 200 and body["mode"] == "evidence_only"  # no API key configured in tests
    assert f"INC-{incident.id}" in body["citations"]
    assert all(c in {e["citation"] for e in body["evidence"]} for c in body["citations"])
    none = client.post("/api/v1/assistant/ask", headers=analyst, json={"question": "What happened to 10.9.9.9?"}).json()
    assert "insufficient" in none["answer"].lower() or none["evidence"][0]["record"]["flows"] == 0
    missing = client.post("/api/v1/assistant/ask", headers=analyst, json={"question": "Summarize INC-999999"}).json()
    assert "does not exist" in " ".join(missing["notes"]) and "insufficient" in missing["answer"].lower()


def test_report_generation_and_topology(client, db) -> None:
    incident, admin = _make_incident(client, db)
    r = client.get("/api/v1/reports/summary?include_demo=true", headers=admin)
    assert r.status_code == 200
    body = r.json()
    assert body["events"]["total"] == 1600 and body["incidents"]["total"] == 1
    assert body["mitre_techniques"][0]["technique_id"] == "T1498.001"
    md = client.get("/api/v1/reports/summary?fmt=markdown", headers=admin)
    assert md.status_code == 200 and md.text.startswith("# Z-NIDS security report")
    topo = client.get(f"/api/v1/assets/topology?minutes=10&incident_id={incident.id}", headers=admin).json()
    assert any(n["id"] == "internet" for n in topo["nodes"])
    edge = next(e for e in topo["edges"] if e["target"] == "10.1.0.80")
    assert edge["suspicious"] > 0 and edge["highlight"] is True
