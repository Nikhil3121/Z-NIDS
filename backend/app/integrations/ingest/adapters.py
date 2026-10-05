"""Sensor log adapters -> normalised event dicts (validated later by EventIn).

Each adapter is a pure function over text lines, so the same code runs in the
API (uploaded batches) and in the standalone sensor forwarder. Unparseable
lines are reported, never silently dropped. Register new sources in ADAPTERS.
"""

from __future__ import annotations

import json
from collections.abc import Callable, Iterable
from dataclasses import dataclass, field
from datetime import UTC, datetime
from typing import Any

_FLAG_LETTERS = {"S": 2, "H": 2 | 16, "A": 16, "D": 8, "F": 1, "R": 4}


@dataclass
class ParseResult:
    records: list[dict[str, Any]] = field(default_factory=list)
    errors: list[dict[str, Any]] = field(default_factory=list)


def _num(value: Any, default: float = 0.0) -> float:
    if value in (None, "", "-", "(empty)"):
        return default
    return float(value)


def _int(value: Any, default: int = 0) -> int:
    return int(_num(value, default))


def _zeek_history_flags(history: str | None) -> int:
    """Zeek conn history letters (originator upper-case, responder lower-case) -> flag union."""
    mask = 0
    for ch in history or "":
        mask |= _FLAG_LETTERS.get(ch.upper(), 0)
    return mask


# --- Zeek conn.log -----------------------------------------------------------


def _zeek_record(rec: dict[str, Any], ref: str) -> dict[str, Any]:
    ts = datetime.fromtimestamp(float(rec["ts"]), UTC)
    return {
        "ts": ts.isoformat(),
        "src_ip": rec["id.orig_h"],
        "src_port": _int(rec.get("id.orig_p"), 0),
        "dst_ip": rec["id.resp_h"],
        "dst_port": _int(rec.get("id.resp_p"), 0),
        "protocol": rec.get("proto", "other"),
        "app_protocol": None if rec.get("service") in (None, "-") else str(rec["service"]).split(",")[0],
        "duration_ms": _num(rec.get("duration")) * 1000.0,
        "packets_out": _int(rec.get("orig_pkts")),
        "packets_in": _int(rec.get("resp_pkts")),
        "bytes_out": _int(rec.get("orig_ip_bytes", rec.get("orig_bytes"))),
        "bytes_in": _int(rec.get("resp_ip_bytes", rec.get("resp_bytes"))),
        "tcp_flags": _zeek_history_flags(rec.get("history")) if rec.get("proto") == "tcp" else 0,
        "conn_state": None if rec.get("conn_state") in (None, "-") else rec["conn_state"],
        "external_id": rec.get("uid"),
        "raw_ref": ref,
    }


def parse_zeek_conn(lines: Iterable[str], source_name: str = "conn.log") -> ParseResult:
    """Supports both Zeek TSV (with #fields header) and JSON-per-line output."""
    out = ParseResult()
    fields: list[str] | None = None
    sep = "\t"
    for n, line in enumerate(lines, 1):
        line = line.rstrip("\n\r")
        if not line:
            continue
        try:
            if line.startswith("#"):
                if line.startswith("#separator"):
                    sep = line.split(" ", 1)[1].encode().decode("unicode_escape")
                elif line.startswith("#fields"):
                    fields = line.split(sep)[1:]
                continue
            if line.lstrip().startswith("{"):
                rec = json.loads(line)
            else:
                if fields is None:
                    raise ValueError("TSV record before #fields header")
                rec = dict(zip(fields, line.split(sep), strict=False))
            out.records.append(_zeek_record(rec, f"{source_name}:{n}"))
        except (ValueError, KeyError, TypeError, json.JSONDecodeError) as exc:
            out.errors.append({"line": n, "error": f"{type(exc).__name__}: {exc}"[:200]})
    return out


# --- Suricata EVE JSON -------------------------------------------------------


def _suricata_ts(value: str) -> str:
    # 2026-09-22T10:11:12.123456+0000 -> ISO 8601 with colon offset
    if len(value) > 5 and value[-5] in "+-" and value[-3] != ":":
        value = value[:-2] + ":" + value[-2:]
    return datetime.fromisoformat(value).astimezone(UTC).isoformat()


def parse_suricata_eve(lines: Iterable[str], source_name: str = "eve.json") -> ParseResult:
    """`flow` and `netflow` events become flows; `alert` events become flows carrying external_alert."""
    out = ParseResult()
    for n, line in enumerate(lines, 1):
        line = line.strip()
        if not line:
            continue
        try:
            rec = json.loads(line)
            etype = rec.get("event_type")
            if etype not in ("flow", "netflow", "alert"):
                continue
            flow = rec.get("flow") or rec.get("netflow") or {}
            tcp = rec.get("tcp") or {}
            flags = int(tcp.get("tcp_flags", "0"), 16) if isinstance(tcp.get("tcp_flags"), str) else 0
            start, end = flow.get("start"), flow.get("end")
            duration = 0.0
            if start and end:
                duration = (
                    datetime.fromisoformat(_suricata_ts(end)) - datetime.fromisoformat(_suricata_ts(start))
                ).total_seconds() * 1000
            record = {
                "ts": _suricata_ts(start or rec["timestamp"]),
                "src_ip": rec["src_ip"],
                "src_port": rec.get("src_port"),
                "dst_ip": rec["dest_ip"],
                "dst_port": rec.get("dest_port"),
                "protocol": str(rec.get("proto", "other")).lower(),
                "app_protocol": rec.get("app_proto") if rec.get("app_proto") not in (None, "failed") else None,
                "duration_ms": max(0.0, duration),
                "packets_out": _int(flow.get("pkts_toserver", flow.get("pkts"))),
                "packets_in": _int(flow.get("pkts_toclient")),
                "bytes_out": _int(flow.get("bytes_toserver", flow.get("bytes"))),
                "bytes_in": _int(flow.get("bytes_toclient")),
                "tcp_flags": flags,
                "conn_state": None,
                "external_id": f"{rec.get('flow_id', '')}:{etype}" if rec.get("flow_id") else None,
                "raw_ref": f"{source_name}:{n}",
            }
            if etype == "alert":
                alert = rec.get("alert") or {}
                record["external_alert"] = {
                    "signature": str(alert.get("signature", "suricata alert"))[:255],
                    "signature_id": alert.get("signature_id"),
                    "category": alert.get("category"),
                    "severity": alert.get("severity"),
                }
            out.records.append(record)
        except (ValueError, KeyError, TypeError, json.JSONDecodeError) as exc:
            out.errors.append({"line": n, "error": f"{type(exc).__name__}: {exc}"[:200]})
    return out


# --- NetFlow / IPFIX (goflow2 JSON) -----------------------------------------


def parse_netflow_json(lines: Iterable[str], source_name: str = "netflow") -> ParseResult:
    """goflow2 JSON records (TimeFlowStartNs/SrcAddr/DstAddr/...); unidirectional flows."""
    out = ParseResult()
    proto_map = {6: "tcp", 17: "udp", 1: "icmp", 58: "icmp"}
    for n, line in enumerate(lines, 1):
        line = line.strip()
        if not line:
            continue
        try:
            rec = json.loads(line)
            start_ns = rec.get("time_flow_start_ns") or rec.get("TimeFlowStartNs")
            end_ns = rec.get("time_flow_end_ns") or rec.get("TimeFlowEndNs") or start_ns
            if start_ns is None:
                raise KeyError("time_flow_start_ns")
            proto = rec.get("proto", rec.get("Proto"))
            out.records.append(
                {
                    "ts": datetime.fromtimestamp(int(start_ns) / 1e9, UTC).isoformat(),
                    "src_ip": rec.get("src_addr", rec.get("SrcAddr")),
                    "src_port": rec.get("src_port", rec.get("SrcPort")),
                    "dst_ip": rec.get("dst_addr", rec.get("DstAddr")),
                    "dst_port": rec.get("dst_port", rec.get("DstPort")),
                    "protocol": proto_map.get(int(proto), "other") if str(proto).isdigit() else str(proto).lower(),
                    "duration_ms": max(0.0, (int(end_ns) - int(start_ns)) / 1e6),
                    "packets_out": _int(rec.get("packets", rec.get("Packets"))),
                    "bytes_out": _int(rec.get("bytes", rec.get("Bytes"))),
                    "tcp_flags": _int(rec.get("tcp_flags", rec.get("TCPFlags"))),
                    "raw_ref": f"{source_name}:{n}",
                }
            )
        except (ValueError, KeyError, TypeError, json.JSONDecodeError) as exc:
            out.errors.append({"line": n, "error": f"{type(exc).__name__}: {exc}"[:200]})
    return out


ADAPTERS: dict[str, Callable[[Iterable[str], str], ParseResult]] = {
    "zeek": parse_zeek_conn,
    "suricata": parse_suricata_eve,
    "netflow": parse_netflow_json,
}
