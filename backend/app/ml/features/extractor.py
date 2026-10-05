"""Feature extraction shared by training, evaluation and live inference.

Leakage rule: every window feature for a flow is computed from flows with
`ts <= flow.ts` only (the flow itself plus its past). Nothing looks forward, so
the same function is valid on a historical dataset and on a live batch plus
its loaded context.
"""

from __future__ import annotations

import math
from collections import defaultdict

import numpy as np
import pandas as pd

from app.ml.features.registry import FEATURE_NAMES, FEATURES, WINDOWS

REQUIRED_COLUMNS = [
    "ts",  # float epoch seconds
    "src_ip",
    "dst_ip",
    "dst_port",
    "protocol",
    "duration_ms",
    "packets_out",
    "packets_in",
    "bytes_out",
    "bytes_in",
    "tcp_flags",
    "conn_state",
    "direction",
]

FIN, SYN, RST, PSH, ACK = 1, 2, 4, 8, 16
FAILED_STATES = {"S0", "REJ", "RSTO", "RSTOS0", "RSTR", "RSTRH", "SH", "SHR", "OTH"}


def _failed(flags: np.ndarray, states: pd.Series, protocol: pd.Series) -> np.ndarray:
    state_failed = states.fillna("").str.upper().isin(FAILED_STATES).to_numpy()
    has_state = states.notna().to_numpy() & (states.fillna("") != "").to_numpy()
    syn_no_ack = ((flags & SYN) > 0) & ((flags & ACK) == 0)
    rst = (flags & RST) > 0
    tcp = (protocol == "tcp").to_numpy()
    by_flags = tcp & (syn_no_ack | rst)
    return np.where(has_state, state_failed, by_flags)


class _Window:
    """Sliding time window over one source's flows with incremental statistics."""

    __slots__ = (
        "bytes_out",
        "failed",
        "gap_sq",
        "gap_sum",
        "gaps",
        "ips",
        "left",
        "plogp_ips",
        "plogp_ports",
        "ports",
        "w",
    )

    def __init__(self, w: int, start: int) -> None:
        self.w = w
        self.left = start
        self.ports: dict[int, int] = defaultdict(int)
        self.ips: dict[str, int] = defaultdict(int)
        self.failed = 0
        self.plogp_ports = 0.0
        self.plogp_ips = 0.0
        self.bytes_out = 0.0
        self.gap_sum = 0.0
        self.gap_sq = 0.0
        self.gaps = 0


def _clogc(c: int) -> float:
    return c * math.log(c) if c > 0 else 0.0


def _source_windows(
    ts: np.ndarray,
    src: np.ndarray,
    dst: np.ndarray,
    port: np.ndarray,
    failed: np.ndarray,
    bytes_out: np.ndarray,
) -> dict[str, np.ndarray]:
    n = len(ts)
    out: dict[str, np.ndarray] = {}
    for w in WINDOWS:
        for key in ("conn_count", "uniq_dst_ports", "uniq_dst_ips", "failed_ratio"):
            out[f"{key}_{w}"] = np.zeros(n)
    for key in (
        "dst_port_entropy_60",
        "dst_ip_entropy_60",
        "bytes_out_sum_60",
        "same_port_ratio_60",
        "interarrival_mean_60",
        "interarrival_cv_60",
        "interarrival_mean_300",
        "interarrival_cv_300",
        "same_dst_ratio_300",
    ):
        out[key] = np.zeros(n)

    # Stable sort by (source, time) keeps original order for equal timestamps.
    order = np.lexsort((np.arange(n), ts, src))
    i = 0
    while i < n:
        j = i
        s = src[order[i]]
        while j < n and src[order[j]] == s:
            j += 1
        idx = order[i:j]
        g_ts = ts[idx]
        gaps = np.empty(len(idx))
        gaps[0] = np.nan
        gaps[1:] = np.diff(g_ts)
        wins = [_Window(w, 0) for w in WINDOWS]
        for k, row in enumerate(idx):
            for win in wins:
                p, d = int(port[row]), dst[row]
                c = win.ports[p]
                win.plogp_ports += _clogc(c + 1) - _clogc(c)
                win.ports[p] = c + 1
                c = win.ips[d]
                win.plogp_ips += _clogc(c + 1) - _clogc(c)
                win.ips[d] = c + 1
                win.failed += int(failed[row])
                win.bytes_out += bytes_out[row]
                if k > 0:
                    win.gap_sum += gaps[k]
                    win.gap_sq += gaps[k] ** 2
                    win.gaps += 1
                # Evict flows that fell out of the window.
                while g_ts[win.left] < g_ts[k] - win.w:
                    old = idx[win.left]
                    op, od = int(port[old]), dst[old]
                    c = win.ports[op]
                    win.plogp_ports += _clogc(c - 1) - _clogc(c)
                    if c == 1:
                        del win.ports[op]
                    else:
                        win.ports[op] = c - 1
                    c = win.ips[od]
                    win.plogp_ips += _clogc(c - 1) - _clogc(c)
                    if c == 1:
                        del win.ips[od]
                    else:
                        win.ips[od] = c - 1
                    win.failed -= int(failed[old])
                    win.bytes_out -= bytes_out[old]
                    win.left += 1
                    # The gap *into* the new left edge no longer lies inside the window.
                    win.gap_sum -= gaps[win.left]
                    win.gap_sq -= gaps[win.left] ** 2
                    win.gaps -= 1

                count = k - win.left + 1
                w = win.w
                out[f"conn_count_{w}"][row] = count
                out[f"uniq_dst_ports_{w}"][row] = len(win.ports)
                out[f"uniq_dst_ips_{w}"][row] = len(win.ips)
                out[f"failed_ratio_{w}"][row] = win.failed / count
                if w == 60:
                    out["dst_port_entropy_60"][row] = max(0.0, math.log(count) - win.plogp_ports / count)
                    out["dst_ip_entropy_60"][row] = max(0.0, math.log(count) - win.plogp_ips / count)
                    out["bytes_out_sum_60"][row] = max(0.0, win.bytes_out)
                    out["same_port_ratio_60"][row] = win.ports.get(int(port[row]), 0) / count
                if w == 300:
                    out["same_dst_ratio_300"][row] = win.ips.get(dst[row], 0) / count
                if w in (60, 300):
                    if win.gaps >= 2:
                        mean = win.gap_sum / win.gaps
                        var = max(0.0, win.gap_sq / win.gaps - mean * mean)
                        out[f"interarrival_mean_{w}"][row] = mean
                        out[f"interarrival_cv_{w}"][row] = math.sqrt(var) / mean if mean > 1e-9 else 0.0
                    else:
                        # Fewer than two gaps: no regularity evidence; neutral (Poisson-like) values.
                        out[f"interarrival_mean_{w}"][row] = float(w)
                        out[f"interarrival_cv_{w}"][row] = 1.0
        i = j
    return out


def _destination_window(ts: np.ndarray, src: np.ndarray, dst: np.ndarray, w: int = 60) -> tuple[np.ndarray, np.ndarray]:
    n = len(ts)
    counts = np.zeros(n)
    uniq = np.zeros(n)
    order = np.lexsort((np.arange(n), ts, dst))
    i = 0
    while i < n:
        j = i
        d = dst[order[i]]
        while j < n and dst[order[j]] == d:
            j += 1
        idx = order[i:j]
        g_ts = ts[idx]
        left = 0
        srcs: dict[str, int] = defaultdict(int)
        for k, row in enumerate(idx):
            srcs[src[row]] += 1
            while g_ts[left] < g_ts[k] - w:
                old = src[idx[left]]
                srcs[old] -= 1
                if srcs[old] == 0:
                    del srcs[old]
                left += 1
            counts[row] = k - left + 1
            uniq[row] = len(srcs)
        i = j
    return counts, uniq


def extract_features(frame: pd.DataFrame) -> tuple[pd.DataFrame, pd.DataFrame]:
    """Return (model features, raw human-readable values), index-aligned with `frame`.

    `frame` must contain REQUIRED_COLUMNS. Rows may be in any order.
    """
    missing = [c for c in REQUIRED_COLUMNS if c not in frame.columns]
    if missing:
        raise ValueError(f"missing columns: {missing}")
    df = frame.reset_index(drop=True)
    n = len(df)
    if n == 0:
        empty = pd.DataFrame(columns=FEATURE_NAMES, dtype=float)
        return empty, empty.copy()

    ts = df["ts"].to_numpy(dtype=float)
    flags = df["tcp_flags"].fillna(0).to_numpy(dtype=np.int64)
    protocol = df["protocol"].astype(str).str.lower()
    port = df["dst_port"].fillna(-1).to_numpy(dtype=np.int64)
    src = df["src_ip"].astype(str).to_numpy()
    dst = df["dst_ip"].astype(str).to_numpy()
    duration = df["duration_ms"].fillna(0).clip(lower=0).to_numpy(dtype=float)
    b_out = df["bytes_out"].fillna(0).clip(lower=0).to_numpy(dtype=float)
    b_in = df["bytes_in"].fillna(0).clip(lower=0).to_numpy(dtype=float)
    p_out = df["packets_out"].fillna(0).clip(lower=0).to_numpy(dtype=float)
    p_in = df["packets_in"].fillna(0).clip(lower=0).to_numpy(dtype=float)
    failed = _failed(flags, df["conn_state"].astype("object"), protocol)
    direction = df["direction"].astype(str)

    seconds = np.maximum(duration / 1000.0, 1e-3)
    total_b = b_out + b_in
    total_p = p_out + p_in

    raw: dict[str, np.ndarray] = {
        "duration": duration,
        "bytes_out": b_out,
        "bytes_in": b_in,
        "packets_out": p_out,
        "packets_in": p_in,
        "bytes_per_sec": total_b / seconds,
        "packets_per_sec": total_p / seconds,
        "avg_packet_size": np.where(total_p > 0, total_b / np.maximum(total_p, 1), 0.0),
        "out_in_ratio": np.log((b_out + 1) / (b_in + 1)),
        "flag_syn": ((flags & SYN) > 0).astype(float),
        "flag_ack": ((flags & ACK) > 0).astype(float),
        "flag_rst": ((flags & RST) > 0).astype(float),
        "flag_fin": ((flags & FIN) > 0).astype(float),
        "flag_psh": ((flags & PSH) > 0).astype(float),
        "failed": failed.astype(float),
        "proto_tcp": (protocol == "tcp").to_numpy(dtype=float),
        "proto_udp": (protocol == "udp").to_numpy(dtype=float),
        "proto_icmp": (protocol == "icmp").to_numpy(dtype=float),
        "dst_port_wellknown": ((port >= 0) & (port < 1024)).astype(float),
        "dst_port_ephemeral": (port >= 49152).astype(float),
        "dir_inbound": (direction == "inbound").to_numpy(dtype=float),
        "dir_outbound": (direction == "outbound").to_numpy(dtype=float),
        "dir_internal": (direction == "internal").to_numpy(dtype=float),
    }
    raw.update(_source_windows(ts, src, dst, port, failed, b_out))
    raw["dst_conn_count_60"], raw["dst_uniq_src_60"] = _destination_window(ts, src, dst)

    raw_df = pd.DataFrame({name: raw[name] for name in FEATURE_NAMES})
    model_df = raw_df.copy()
    for spec in FEATURES:
        if spec.transform == "log1p":
            model_df[spec.name] = np.log1p(np.maximum(raw_df[spec.name].to_numpy(), 0.0))
    return model_df.astype(float), raw_df.astype(float)
