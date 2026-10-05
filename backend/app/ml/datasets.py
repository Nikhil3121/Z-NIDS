"""Dataset loading, normalisation and versioning for ML research.

Supported inputs
----------------
* Z-NIDS normalised CSV (the format written by `generate_synthetic_events` and
  `export`): columns ts, src_ip, dst_ip, src_port, dst_port, protocol,
  app_protocol, duration_ms, packets_out, packets_in, bytes_out, bytes_in,
  tcp_flags, conn_state, label[, episode].
* CIC-IDS2017 "TrafficLabelling" CSVs (the variant that includes Source IP,
  Destination IP and Timestamp columns). The "MachineLearningCVE" variant has
  no addresses or timestamps and cannot drive window features.

Every dataset is identified by the SHA-256 of its file(s); the hash is stored
with each model and evaluation so results are traceable to exact data.
"""

from __future__ import annotations

import hashlib
import ipaddress
import json
import re
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

import numpy as np
import pandas as pd

from app.ml.registry.store import sha256_file

CANONICAL = [
    "ts",
    "src_ip",
    "dst_ip",
    "src_port",
    "dst_port",
    "protocol",
    "app_protocol",
    "duration_ms",
    "packets_out",
    "packets_in",
    "bytes_out",
    "bytes_in",
    "tcp_flags",
    "conn_state",
    "direction",
    "label",
    "episode",
]

_PRIVATE = [ipaddress.ip_network(n) for n in ("10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16")]

CIC_LABEL_MAP = {
    "benign": "normal",
    "ddos": "ddos",
    "dos hulk": "ddos",
    "dos goldeneye": "ddos",
    "dos slowloris": "slow_dos",
    "dos slowhttptest": "slow_dos",
    "portscan": "port_scan",
    "ftp-patator": "brute_force",
    "ssh-patator": "brute_force",
    "bot": "botnet_c2",
    "infiltration": "infiltration",
    "heartbleed": "heartbleed",
    "web attack brute force": "web_attack",
    "web attack xss": "web_attack",
    "web attack sql injection": "web_attack",
}


def _slug(label: str) -> str:
    return re.sub(r"[^a-z0-9]+", "_", label.lower()).strip("_") or "unknown"


def _internal(ip: str) -> bool:
    try:
        addr = ipaddress.ip_address(ip)
    except ValueError:
        return False
    return any(addr in net for net in _PRIVATE)


def add_direction(df: pd.DataFrame) -> pd.DataFrame:
    uniq = pd.unique(pd.concat([df["src_ip"], df["dst_ip"]]).astype(str))
    lookup = {ip: _internal(ip) for ip in uniq}
    s = df["src_ip"].astype(str).map(lookup).to_numpy()
    d = df["dst_ip"].astype(str).map(lookup).to_numpy()
    df["direction"] = np.select([s & d, s & ~d, ~s & d], ["internal", "outbound", "inbound"], "external")
    return df


def load_normalized_csv(path: Path) -> pd.DataFrame:
    df = pd.read_csv(path, low_memory=False)
    missing = {"ts", "src_ip", "dst_ip", "protocol"} - set(df.columns)
    if missing:
        raise ValueError(f"{path.name}: missing required columns {sorted(missing)}")
    if not np.issubdtype(df["ts"].dtype, np.number):
        df["ts"] = pd.to_datetime(df["ts"], utc=True).astype("int64") / 1e9
    for col, default in (
        ("src_port", 0),
        ("dst_port", 0),
        ("duration_ms", 0.0),
        ("packets_out", 0),
        ("packets_in", 0),
        ("bytes_out", 0),
        ("bytes_in", 0),
        ("tcp_flags", 0),
    ):
        df[col] = pd.to_numeric(df.get(col, default), errors="coerce").fillna(default)
    for col in ("app_protocol", "conn_state", "episode"):
        if col not in df:
            df[col] = ""
    df["label"] = df.get("label", pd.Series(["normal"] * len(df))).fillna("normal").astype(str).map(_slug)
    df["protocol"] = df["protocol"].astype(str).str.lower()
    if "direction" not in df:
        df = add_direction(df)
    return df[CANONICAL]


def load_cicids2017_csv(path: Path) -> pd.DataFrame:
    df = pd.read_csv(path, low_memory=False, encoding="latin-1")
    df.columns = [c.strip() for c in df.columns]
    needed = {"Source IP", "Destination IP", "Timestamp", "Label"}
    if not needed <= set(df.columns):
        raise ValueError(
            f"{path.name}: not a CIC-IDS2017 TrafficLabelling file (needs {sorted(needed)}); "
            "the MachineLearningCVE variant lacks addresses/timestamps"
        )
    ts = pd.to_datetime(df["Timestamp"], dayfirst=True, errors="coerce", format="mixed")
    keep = ts.notna()
    df, ts = df[keep], ts[keep]
    proto = df["Protocol"].map({6: "tcp", 17: "udp", 1: "icmp"}).fillna("other")
    flags = (
        (df.get("FIN Flag Count", 0) > 0) * 1
        + (df.get("SYN Flag Count", 0) > 0) * 2
        + (df.get("RST Flag Count", 0) > 0) * 4
        + (df.get("PSH Flag Count", 0) > 0) * 8
        + (df.get("ACK Flag Count", 0) > 0) * 16
    )
    labels = df["Label"].astype(str).str.replace("�", " ").str.replace("–", " ").str.strip().str.lower()
    labels = labels.str.replace(r"\s+", " ", regex=True).map(lambda v: CIC_LABEL_MAP.get(v, _slug(v)))
    out = pd.DataFrame(
        {
            # CIC timestamps are local (UTC-3) wall-clock; only relative ordering matters here.
            "ts": ts.dt.tz_localize("UTC").astype("int64") / 1e9,
            "src_ip": df["Source IP"].astype(str),
            "dst_ip": df["Destination IP"].astype(str),
            "src_port": pd.to_numeric(df.get("Source Port", 0), errors="coerce").fillna(0),
            "dst_port": pd.to_numeric(df["Destination Port"], errors="coerce").fillna(0),
            "protocol": proto,
            "app_protocol": "",
            "duration_ms": pd.to_numeric(df["Flow Duration"], errors="coerce").fillna(0).clip(lower=0) / 1000.0,
            "packets_out": pd.to_numeric(df["Total Fwd Packets"], errors="coerce").fillna(0),
            "packets_in": pd.to_numeric(df["Total Backward Packets"], errors="coerce").fillna(0),
            "bytes_out": pd.to_numeric(df["Total Length of Fwd Packets"], errors="coerce").fillna(0),
            "bytes_in": pd.to_numeric(df["Total Length of Bwd Packets"], errors="coerce").fillna(0),
            "tcp_flags": flags.astype(int),
            "conn_state": "",
            "label": labels.to_numpy(),
            "episode": "",
        }
    )
    out = add_direction(out)
    return out[CANONICAL]


def load_dataset(paths: list[Path], fmt: str) -> tuple[pd.DataFrame, str]:
    """Load one or more files; return (frame, combined sha256)."""
    loader = {"normalized": load_normalized_csv, "cicids2017": load_cicids2017_csv}.get(fmt)
    if loader is None:
        raise ValueError(f"unknown dataset format '{fmt}' (normalized | cicids2017)")
    frames, digest = [], hashlib.sha256()
    for path in sorted(paths):
        frames.append(loader(path))
        digest.update(sha256_file(path).encode())
    df = pd.concat(frames, ignore_index=True).sort_values("ts", kind="stable").reset_index(drop=True)
    return df, digest.hexdigest()


def write_dataset(df: pd.DataFrame, path: Path, params: dict[str, Any]) -> tuple[str, Path]:
    """Write a normalised CSV (gzip) with a manifest; return (sha256, manifest path)."""
    path.parent.mkdir(parents=True, exist_ok=True)
    df[CANONICAL].to_csv(path, index=False, compression="gzip" if path.suffix == ".gz" else None)
    checksum = sha256_file(path)
    manifest = {
        "file": path.name,
        "sha256": checksum,
        "rows": len(df),
        "labels": {str(k): int(v) for k, v in df["label"].value_counts().items()},
        "created_at": datetime.now(UTC).isoformat(),
        "params": params,
    }
    manifest_path = path.with_name(path.name.split(".")[0] + ".manifest.json")
    manifest_path.write_text(json.dumps(manifest, indent=2))
    return checksum, manifest_path
