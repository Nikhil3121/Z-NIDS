"""Feature registry — the single documented definition of every model input.

FEATURE_VERSION must change whenever a feature is added, removed or its
computation changes; a model bundle refuses to score features of a different
version. docs/ml-methodology.md is generated from these descriptions.
"""

from __future__ import annotations

from dataclasses import dataclass

FEATURE_VERSION = "fv1"

# Time windows (seconds) for per-source rolling statistics.
WINDOWS: tuple[int, ...] = (10, 60, 300)
# Longest look-back any feature needs; inference loads this much context.
MAX_LOOKBACK_SECONDS = max(WINDOWS)


@dataclass(frozen=True)
class FeatureSpec:
    name: str
    label: str
    description: str
    # "log1p" features are stored transformed; `raw` inverts them for explanations.
    transform: str = "none"  # none | log1p | log_ratio
    unit: str = ""
    group: str = "flow"


def _window_specs() -> list[FeatureSpec]:
    specs: list[FeatureSpec] = []
    for w in WINDOWS:
        specs += [
            FeatureSpec(
                f"conn_count_{w}",
                f"Connections from source ({w}s)",
                f"Flows started by the source IP in the preceding {w}s (inclusive).",
                "log1p",
                "flows",
                "window",
            ),
            FeatureSpec(
                f"uniq_dst_ports_{w}",
                f"Distinct destination ports ({w}s)",
                f"Distinct destination ports contacted by the source in the preceding {w}s.",
                "log1p",
                "ports",
                "window",
            ),
            FeatureSpec(
                f"uniq_dst_ips_{w}",
                f"Distinct destination hosts ({w}s)",
                f"Distinct destination IPs contacted by the source in the preceding {w}s.",
                "log1p",
                "hosts",
                "window",
            ),
            FeatureSpec(
                f"failed_ratio_{w}",
                f"Failed connection ratio ({w}s)",
                f"Share of the source's flows in the preceding {w}s that were rejected/unanswered.",
                "none",
                "ratio",
                "window",
            ),
        ]
    return specs


FEATURES: list[FeatureSpec] = [
    FeatureSpec("duration", "Flow duration", "Flow duration in milliseconds.", "log1p", "ms"),
    FeatureSpec("bytes_out", "Bytes sent", "Bytes from the originator to the responder.", "log1p", "bytes"),
    FeatureSpec("bytes_in", "Bytes received", "Bytes from the responder to the originator.", "log1p", "bytes"),
    FeatureSpec("packets_out", "Packets sent", "Packets from the originator.", "log1p", "packets"),
    FeatureSpec("packets_in", "Packets received", "Packets from the responder.", "log1p", "packets"),
    FeatureSpec("bytes_per_sec", "Throughput", "Total bytes / max(duration, 1ms), per second.", "log1p", "B/s"),
    FeatureSpec("packets_per_sec", "Packet rate", "Total packets / max(duration, 1ms), per second.", "log1p", "pkt/s"),
    FeatureSpec("avg_packet_size", "Average packet size", "Total bytes / total packets.", "log1p", "bytes"),
    FeatureSpec(
        "out_in_ratio",
        "Outbound/inbound byte ratio",
        "ln((bytes_out+1)/(bytes_in+1)); positive = upload-heavy.",
        "log_ratio",
        "",
    ),
    FeatureSpec("flag_syn", "SYN flag", "SYN observed in the flow.", unit="bool"),
    FeatureSpec("flag_ack", "ACK flag", "ACK observed in the flow.", unit="bool"),
    FeatureSpec("flag_rst", "RST flag", "RST observed in the flow.", unit="bool"),
    FeatureSpec("flag_fin", "FIN flag", "FIN observed in the flow.", unit="bool"),
    FeatureSpec("flag_psh", "PSH flag", "PSH observed in the flow.", unit="bool"),
    FeatureSpec(
        "failed",
        "Failed connection",
        "Connection rejected or unanswered (Zeek S0/REJ/RSTO*/SH, or SYN without ACK).",
        unit="bool",
    ),
    FeatureSpec("proto_tcp", "TCP", "Protocol is TCP.", unit="bool"),
    FeatureSpec("proto_udp", "UDP", "Protocol is UDP.", unit="bool"),
    FeatureSpec("proto_icmp", "ICMP", "Protocol is ICMP.", unit="bool"),
    FeatureSpec("dst_port_wellknown", "Well-known destination port", "Destination port < 1024.", unit="bool"),
    FeatureSpec("dst_port_ephemeral", "Ephemeral destination port", "Destination port >= 49152.", unit="bool"),
    FeatureSpec("dir_inbound", "Inbound flow", "External source to internal destination.", unit="bool"),
    FeatureSpec("dir_outbound", "Outbound flow", "Internal source to external destination.", unit="bool"),
    FeatureSpec("dir_internal", "Internal flow", "Internal source to internal destination.", unit="bool"),
    *_window_specs(),
    FeatureSpec(
        "dst_port_entropy_60",
        "Destination-port entropy (60s)",
        "Shannon entropy (nats) of the source's destination ports over 60s.",
        "none",
        "nats",
        "window",
    ),
    FeatureSpec(
        "dst_ip_entropy_60",
        "Destination-host entropy (60s)",
        "Shannon entropy (nats) of the source's destination IPs over 60s.",
        "none",
        "nats",
        "window",
    ),
    FeatureSpec(
        "bytes_out_sum_60",
        "Bytes sent by source (60s)",
        "Sum of bytes sent by the source over 60s.",
        "log1p",
        "bytes",
        "window",
    ),
    FeatureSpec(
        "same_port_ratio_60",
        "Same-port repetition (60s)",
        "Share of the source's 60s flows that targeted this flow's destination port.",
        "none",
        "ratio",
        "window",
    ),
    FeatureSpec(
        "interarrival_mean_60",
        "Mean inter-arrival (60s)",
        "Mean seconds between the source's consecutive flows within 60s.",
        "log1p",
        "s",
        "window",
    ),
    FeatureSpec(
        "interarrival_cv_60",
        "Inter-arrival regularity (60s)",
        "Coefficient of variation of inter-arrival gaps; near 0 = machine-regular (beacon-like).",
        "none",
        "",
        "window",
    ),
    FeatureSpec(
        "interarrival_mean_300",
        "Mean inter-arrival (5m)",
        "Mean seconds between the source's consecutive flows within 300s.",
        "log1p",
        "s",
        "window",
    ),
    FeatureSpec(
        "interarrival_cv_300",
        "Inter-arrival regularity (5m)",
        "Coefficient of variation of the source's inter-arrival gaps over 300s; near 0 = periodic.",
        "none",
        "",
        "window",
    ),
    FeatureSpec(
        "same_dst_ratio_300",
        "Same-destination repetition (5m)",
        "Share of the source's 300s flows that went to this flow's destination IP.",
        "none",
        "ratio",
        "window",
    ),
    FeatureSpec(
        "dst_conn_count_60",
        "Connections to destination (60s)",
        "Flows received by the destination IP from any source over 60s.",
        "log1p",
        "flows",
        "destination",
    ),
    FeatureSpec(
        "dst_uniq_src_60",
        "Distinct sources to destination (60s)",
        "Distinct source IPs contacting the destination over 60s.",
        "log1p",
        "hosts",
        "destination",
    ),
]

FEATURE_NAMES: list[str] = [f.name for f in FEATURES]
FEATURES_BY_NAME: dict[str, FeatureSpec] = {f.name: f for f in FEATURES}
