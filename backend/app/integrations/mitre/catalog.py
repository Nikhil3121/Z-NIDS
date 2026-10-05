"""MITRE ATT&CK (Enterprise) techniques relevant to network-flow telemetry, and
the evidence-gated mapping from detections to techniques.

Mappings are *hypotheses with a confidence*, never certainties:
  * signature / known-family detections map to the technique the behaviour
    implements, with confidence scaled by the detection's own confidence;
  * ML anomalies map only when specific evidence in the flow supports a
    technique, and their confidence is capped at 0.5.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any

ATTACK_URL = "https://attack.mitre.org/techniques/{}/"

# technique_id -> (name, tactic, description)
TECHNIQUES: dict[str, tuple[str, str, str]] = {
    "T1046": ("Network Service Discovery", "Discovery", "Enumerating services on remote hosts, e.g. port scanning."),
    "T1595.001": ("Active Scanning: Scanning IP Blocks", "Reconnaissance", "Scanning address ranges from outside."),
    "T1110": ("Brute Force", "Credential Access", "Systematic credential guessing."),
    "T1110.001": ("Brute Force: Password Guessing", "Credential Access", "Guessing passwords against a service."),
    "T1498": ("Network Denial of Service", "Impact", "Exhausting network bandwidth or connection capacity."),
    "T1498.001": ("Network Denial of Service: Direct Network Flood", "Impact", "High-volume traffic at a target."),
    "T1499.002": (
        "Endpoint Denial of Service: Service Exhaustion Flood",
        "Impact",
        "Exhausting a service's resources, e.g. slow HTTP connections.",
    ),
    "T1041": ("Exfiltration Over C2 Channel", "Exfiltration", "Stealing data over the command-and-control channel."),
    "T1048": ("Exfiltration Over Alternative Protocol", "Exfiltration", "Stealing data over a different protocol."),
    "T1071": ("Application Layer Protocol", "Command and Control", "C2 blended into common application protocols."),
    "T1071.004": ("Application Layer Protocol: DNS", "Command and Control", "C2 over DNS."),
    "T1572": ("Protocol Tunneling", "Command and Control", "Tunnelling traffic inside another protocol."),
    "T1571": ("Non-Standard Port", "Command and Control", "Using a port not normally associated with the protocol."),
    "T1021": ("Remote Services", "Lateral Movement", "Using remote services to move between hosts."),
    "T1021.001": ("Remote Services: Remote Desktop Protocol", "Lateral Movement", "Lateral movement over RDP."),
    "T1021.002": ("Remote Services: SMB/Windows Admin Shares", "Lateral Movement", "Lateral movement over SMB."),
    "T1021.006": ("Remote Services: Windows Remote Management", "Lateral Movement", "Lateral movement over WinRM."),
    "T1040": ("Network Sniffing", "Credential Access", "Capturing cleartext credentials from the network."),
}


@dataclass
class MappingHypothesis:
    technique_id: str
    confidence: float
    evidence: str


def _v(values: dict[str, Any], key: str, default: float = 0.0) -> float:
    try:
        return float(values.get(key, default) or 0.0)
    except (TypeError, ValueError):
        return default


def map_detection(category: str, confidence: float, values: dict[str, Any], direction: str) -> list[MappingHypothesis]:
    """Return evidence-backed technique hypotheses for one detection."""
    out: list[MappingHypothesis] = []
    ports = _v(values, "uniq_dst_ports_60")
    hosts = _v(values, "uniq_dst_ips_60")
    failed = _v(values, "failed_ratio_60")
    dport = int(_v(values, "dst_port", -1))

    if category == "port_scan":
        tid = "T1595.001" if direction == "inbound" else "T1046"
        out.append(
            MappingHypothesis(
                tid, 0.85 * confidence, f"{ports:.0f} ports / {hosts:.0f} hosts probed in 60s, {failed:.0%} failed"
            )
        )
    elif category == "brute_force":
        out.append(
            MappingHypothesis(
                "T1110.001",
                0.85 * confidence,
                f"{_v(values, 'conn_count_60'):.0f} connections/min to port {dport} "
                f"({_v(values, 'same_port_ratio_60'):.0%} same port)",
            )
        )
    elif category == "ddos":
        out.append(
            MappingHypothesis(
                "T1498.001",
                0.8 * confidence,
                f"{_v(values, 'dst_conn_count_60'):.0f} flows/min to the destination from "
                f"{_v(values, 'dst_uniq_src_60'):.0f} sources",
            )
        )
    elif category == "suspicious_port":
        out.append(MappingHypothesis("T1571", 0.6 * confidence, f"outbound connection to port {dport}"))
    elif category == "cleartext_protocol":
        out.append(MappingHypothesis("T1040", 0.3 * confidence, "cleartext Telnet session exposes credentials"))
    elif category in ("slow_dos",):
        out.append(
            MappingHypothesis("T1499.002", 0.7 * confidence, "long-lived low-volume connections to a web service")
        )
    elif category in ("exfiltration",):
        out.append(MappingHypothesis("T1048", 0.7 * confidence, "large outbound transfer"))
    elif category in ("unknown_anomaly", "behavioral_anomaly"):
        out.extend(_anomaly_hypotheses(values, direction, dport))
    return [m for m in out if m.confidence >= 0.1]


def _anomaly_hypotheses(values: dict[str, Any], direction: str, dport: int) -> list[MappingHypothesis]:
    """Evidence-gated, low-confidence hypotheses for anomalies (capped at 0.5)."""
    out: list[MappingHypothesis] = []
    bytes_out = _v(values, "bytes_out")
    ratio = _v(values, "out_in_ratio")
    if direction == "outbound" and bytes_out >= 10_000_000 and ratio >= 3.0:
        out.append(
            MappingHypothesis(
                "T1048", 0.45, f"{bytes_out / 1e6:,.1f} MB sent outbound; upload/download ratio e^{ratio:.1f}"
            )
        )
    if dport == 53 and direction == "outbound" and _v(values, "conn_count_60") >= 30:
        out.append(
            MappingHypothesis(
                "T1071.004", 0.4, f"{_v(values, 'conn_count_60'):.0f} DNS flows/min directly to an external server"
            )
        )
        if _v(values, "bytes_out") >= 150:
            out.append(MappingHypothesis("T1572", 0.3, f"DNS queries averaging {_v(values, 'bytes_out'):.0f} bytes"))
    if (
        direction == "outbound"
        and _v(values, "interarrival_cv_300", 1.0) <= 0.15
        and _v(values, "same_dst_ratio_300") >= 0.8
        and _v(values, "conn_count_300") >= 5
    ):
        out.append(
            MappingHypothesis(
                "T1071",
                0.35,
                f"machine-regular connections (CV {_v(values, 'interarrival_cv_300'):.2f}) "
                "to the same external host",
            )
        )
    if direction == "internal" and hosts_ge(values, 10) and dport in (135, 445, 3389, 5985, 5986):
        tid = {445: "T1021.002", 3389: "T1021.001", 5985: "T1021.006", 5986: "T1021.006"}.get(dport, "T1021")
        out.append(
            MappingHypothesis(
                tid,
                0.45,
                f"{_v(values, 'uniq_dst_ips_60'):.0f} internal hosts contacted on "
                f"remote-admin port {dport} within 60s",
            )
        )
    if dport in (80, 443, 8080) and _v(values, "duration") >= 60_000 and _v(values, "bytes_out") <= 2000:
        out.append(
            MappingHypothesis(
                "T1499.002",
                0.35,
                f"connection held {_v(values, 'duration') / 1000:.0f}s while sending "
                f"{_v(values, 'bytes_out'):.0f} bytes",
            )
        )
    return out


def hosts_ge(values: dict[str, Any], n: int) -> bool:
    return _v(values, "uniq_dst_ips_60") >= n
