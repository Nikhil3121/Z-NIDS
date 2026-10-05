"""Ingestion -> detection -> alert -> incident, end to end on PostgreSQL."""

from __future__ import annotations

import json

from sqlalchemy import func, select

from app.models.alert import Alert
from app.models.asset import Asset
from app.models.detection import Detection, MitreMapping
from app.models.enums import Classification, IncidentStatus, ProcessingStatus, RoleName
from app.models.incident import Incident
from app.models.network_event import EventRollup, NetworkEvent
from tests.support import as_role, flow, recent


def _sensor(client, admin_headers) -> dict[str, str]:
    r = client.post("/api/v1/sensors", headers=admin_headers, json={"name": "edge-zeek-01", "sensor_type": "zeek"})
    assert r.status_code == 201, r.text
    body = r.json()
    assert body["api_key"].startswith("zns_") and body["key_prefix"] == body["api_key"][:12]
    listed = client.get("/api/v1/sensors", headers=admin_headers).json()
    assert "api_key" not in listed[0]  # the key is shown once only
    return {"X-Sensor-Key": body["api_key"]}


def test_normal_traffic_is_ingested_and_processed(client, db) -> None:
    admin = as_role(client, db, RoleName.ADMIN)
    sensor = _sensor(client, admin)
    events = [flow(recent(60 - i), "10.1.0.5", "10.1.0.9", 443) for i in range(20)]
    r = client.post("/api/v1/events/ingest", headers=sensor, json={"events": events})
    assert r.status_code == 202, r.text
    assert r.json()["accepted"] == 20 and r.json()["rejected"] == []
    statuses = dict(db.execute(select(NetworkEvent.processing_status, func.count())
                               .group_by(NetworkEvent.processing_status)).all())
    assert statuses == {ProcessingStatus.PROCESSED: 20}
    assert db.scalar(select(func.count()).select_from(Detection)) == 0
    assert db.scalar(select(func.sum(EventRollup.events))) == 20
    # Internal endpoints were auto-discovered as assets.
    assert {str(a.ip_address) for a in db.scalars(select(Asset)).all()} == {"10.1.0.5", "10.1.0.9"}
    # Re-sending the same external ids is idempotent.
    ids = [{**e, "external_id": f"uid-{i}"} for i, e in enumerate(events[:3])]
    client.post("/api/v1/events/ingest", headers=sensor, json={"events": ids})
    again = client.post("/api/v1/events/ingest", headers=sensor, json={"events": ids}).json()
    assert again["accepted"] == 0 and again["duplicates"] == 3
    listed = client.get("/api/v1/events?src_ip=10.1.0.5&page_size=5", headers=admin).json()
    assert listed["total"] == 23 and len(listed["items"]) == 5


def test_port_scan_is_detected_by_signature_with_explanation_and_mitre(client, db) -> None:
    admin = as_role(client, db, RoleName.ADMIN)
    sensor = _sensor(client, admin)
    scan = [flow(recent(30 - i * 0.2), "203.0.113.50", "10.1.0.9", 1000 + i, flags="SR", state="REJ",
                 bytes_out=44, bytes_in=40, packets=1, duration_ms=1.0) for i in range(60)]
    assert client.post("/api/v1/events/ingest", headers=sensor, json={"events": scan}).status_code == 202
    dets = db.scalars(select(Detection).where(Detection.category == "port_scan")).all()
    assert dets, "port scan not detected"
    det = max(dets, key=lambda d: d.risk_score)
    assert det.classification == Classification.KNOWN_ATTACK and det.rule_id == "SIG-SCAN-001"
    comps = det.risk_components
    assert comps["signature"] > 0 and "formula" in comps and "reason" in comps
    assert any("uniq_dst_ports_60" in f.get("feature", "") for f in det.explanation)
    mitre = db.scalars(select(MitreMapping).where(MitreMapping.detection_id == det.id)).all()
    assert [m.technique_id for m in mitre] == ["T1595.001"]  # external source -> active scanning
    # Many detections, one deduplicated alert.
    alerts = db.scalars(select(Alert).where(Alert.category == "port_scan")).all()
    assert len(alerts) == 1 and alerts[0].occurrence_count == len(dets)
    detail = client.get(f"/api/v1/detections/{det.id}", headers=admin).json()
    assert detail["mitre"][0]["technique_id"] == "T1595.001" and detail["risk_components"]["signature"] > 0


def test_ddos_opens_an_incident_with_investigation_view(client, db) -> None:
    admin = as_role(client, db, RoleName.ADMIN)
    sensor = _sensor(client, admin)
    flood = [flow(recent(50 - i * 0.02), f"198.51.100.{1 + i % 60}", "10.1.0.80", 80, flags="S", state="S0",
                  bytes_out=60, bytes_in=0, packets=1, duration_ms=0.0) for i in range(1600)]
    for i in range(0, len(flood), 500):
        assert client.post("/api/v1/events/ingest", headers=sensor,
                           json={"events": flood[i:i + 500]}).status_code == 202
    alert = db.scalar(select(Alert).where(Alert.category == "ddos"))
    assert alert is not None and alert.severity.value == "critical"
    assert alert.dedup_key == "ddos|dst:10.1.0.80"
    incident = db.scalar(select(Incident))
    assert incident is not None and incident.status == IncidentStatus.NEW
    assert incident.correlation_rule == "single_alert_incident"
    inv = client.get(f"/api/v1/incidents/{incident.id}/investigation", headers=admin)
    assert inv.status_code == 200
    body = inv.json()
    assert body["incident"]["reference"] == f"INC-{incident.id}"
    assert body["detections"] and body["timeline"] and body["mitre"][0]["technique_id"] == "T1498.001"
    assert any(a["role"] == "target" and a["ip_address"] == "10.1.0.80" for a in body["affected_assets"])
    assert body["audit_visible"] is True
    dash = client.get("/api/v1/dashboard/overview?hours=1", headers=admin).json()
    assert dash["overview"]["active_incidents"] == 1 and dash["overview"]["critical_alerts"] == 1
    assert dash["overview"]["total_events"] == 1600


def test_malformed_events_are_rejected_individually(client, db) -> None:
    admin = as_role(client, db, RoleName.ADMIN)
    sensor = _sensor(client, admin)
    good = flow(recent(5), "10.1.0.5", "10.1.0.9", 22)
    bad = [
        {**good, "src_ip": "10.1.0.999"},
        {**good, "src_ip": "1' OR '1'='1"},
        {**good, "dst_port": 70000},
        {**good, "bytes_out": -5},
        {**good, "ts": "2999-01-01T00:00:00Z"},
        {**good, "unexpected_field": "x"},
        {**good, "tcp_flags": "SXZ"},
        {"src_ip": "10.1.0.5"},
    ]
    r = client.post("/api/v1/events/ingest", headers=sensor, json={"events": [good, *bad]})
    assert r.status_code == 202
    body = r.json()
    assert body["accepted"] == 1
    assert sorted(x["index"] for x in body["rejected"]) == list(range(1, len(bad) + 1))
    assert db.scalar(select(func.count()).select_from(NetworkEvent)) == 1


def test_zeek_and_suricata_log_ingestion(client, db) -> None:
    admin = as_role(client, db, RoleName.ADMIN)
    sensor = _sensor(client, admin)
    now = recent(10).timestamp()
    zeek = "\n".join([
        "#separator \\x09",
        "#fields\tts\tuid\tid.orig_h\tid.orig_p\tid.resp_h\tid.resp_p\tproto\tservice\tduration\torig_bytes\t"
        "resp_bytes\tconn_state\thistory\torig_pkts\torig_ip_bytes\tresp_pkts\tresp_ip_bytes",
        f"{now}\tCabc1\t10.1.0.5\t51000\t10.1.0.9\t22\ttcp\tssh\t1.2\t300\t900\tSF\tShADadFf\t8\t620\t9\t1270",
        "this line is garbage",
    ])
    r = client.post("/api/v1/events/ingest/zeek", headers={**sensor, "Content-Type": "text/plain"}, content=zeek)
    assert r.status_code == 202, r.text
    assert r.json()["accepted"] == 1 and len(r.json()["rejected"]) == 1
    ev = db.scalar(select(NetworkEvent).where(NetworkEvent.external_id == "Cabc1"))
    assert ev is not None and ev.app_protocol == "ssh" and ev.conn_state == "SF" and ev.bytes_out == 620

    ts = recent(5).strftime("%Y-%m-%dT%H:%M:%S.000000+0000")
    eve = json.dumps({
        "timestamp": ts, "flow_id": 77, "event_type": "alert", "src_ip": "203.0.113.9", "src_port": 4444,
        "dest_ip": "10.1.0.9", "dest_port": 445, "proto": "TCP",
        "alert": {"signature": "ET EXPLOIT test rule", "signature_id": 2000001,
                  "category": "Attempted Administrator Privilege Gain", "severity": 1},
        "flow": {"pkts_toserver": 3, "pkts_toclient": 2, "bytes_toserver": 400, "bytes_toclient": 200, "start": ts},
    })
    r = client.post("/api/v1/events/ingest/suricata", headers={**sensor, "Content-Type": "text/plain"}, content=eve)
    assert r.status_code == 202 and r.json()["accepted"] == 1, r.text
    det = db.scalar(select(Detection).where(Detection.category == "external_ids_alert"))
    assert det is not None and det.classification == Classification.KNOWN_ATTACK
