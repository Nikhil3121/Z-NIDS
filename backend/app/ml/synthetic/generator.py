"""Synthetic LAB telemetry generator.

Produces *flow metadata only* for a fictional network — no packets are sent,
no host is contacted, no payload or malware exists. Internal hosts use
10.20.0.0/16; "internet" hosts use the RFC 5737 documentation ranges
(192.0.2.0/24, 198.51.100.0/24, 203.0.113.0/24), which are never routable.

Every generated record carries `dataset_label` (ground truth) and is meant to be
stored with is_demo=true. It exists for two purposes:
  1. the LAB / DEMO mode of the platform, and
  2. a reproducible dataset for the held-out-family (unknown attack) evaluation
     when a real labelled dataset (e.g. CIC-IDS2017) is not available.
Results on this data demonstrate the methodology; they are not evidence of
performance on real traffic.
"""

from __future__ import annotations

from collections.abc import Callable
from dataclasses import dataclass, field

import numpy as np
import pandas as pd

NORMAL = "normal"
ATTACK_FAMILIES = (
    "port_scan",
    "brute_force",
    "ddos",
    "exfiltration",
    "c2_beaconing",
    "dns_tunneling",
    "lateral_movement",
    "slow_dos",
)

# Flag bitmasks
FIN, SYN, RST, PSH, ACK = 1, 2, 4, 8, 16
FULL = SYN | ACK | FIN | PSH


@dataclass(frozen=True)
class LabNetwork:
    workstations: tuple[str, ...] = tuple(f"10.20.1.{i}" for i in range(10, 90))
    web_servers: tuple[str, ...] = ("10.20.10.10", "10.20.10.11")
    app_servers: tuple[str, ...] = ("10.20.10.30", "10.20.10.31")
    db_server: str = "10.20.20.5"
    file_server: str = "10.20.10.20"
    mail_server: str = "10.20.10.25"
    jump_host: str = "10.20.10.22"
    domain_controller: str = "10.20.0.10"
    dns_resolver: str = "10.20.0.53"
    backup_server: str = "10.20.20.40"
    internet_services: tuple[str, ...] = tuple(f"198.51.100.{i}" for i in range(1, 120))
    internet_clients: tuple[str, ...] = tuple(f"192.0.2.{i}" for i in range(1, 250))
    hostile: tuple[str, ...] = tuple(f"203.0.113.{i}" for i in range(1, 250))

    @property
    def servers(self) -> tuple[str, ...]:
        return (
            *self.web_servers,
            *self.app_servers,
            self.db_server,
            self.file_server,
            self.mail_server,
            self.jump_host,
            self.domain_controller,
            self.dns_resolver,
            self.backup_server,
        )

    def asset_inventory(self) -> list[dict[str, str]]:
        """Inventory for seeding the lab asset table (hostname, type, criticality)."""
        inv = [
            *(
                {"ip": ip, "hostname": f"web-{i:02d}.lab", "asset_type": "server", "criticality": "high"}
                for i, ip in enumerate(self.web_servers, 1)
            ),
            *(
                {"ip": ip, "hostname": f"app-{i:02d}.lab", "asset_type": "server", "criticality": "high"}
                for i, ip in enumerate(self.app_servers, 1)
            ),
            {"ip": self.db_server, "hostname": "db-01.lab", "asset_type": "database", "criticality": "critical"},
            {"ip": self.file_server, "hostname": "files-01.lab", "asset_type": "server", "criticality": "high"},
            {"ip": self.mail_server, "hostname": "mail-01.lab", "asset_type": "server", "criticality": "medium"},
            {"ip": self.jump_host, "hostname": "jump-01.lab", "asset_type": "server", "criticality": "high"},
            {"ip": self.domain_controller, "hostname": "dc-01.lab", "asset_type": "server", "criticality": "critical"},
            {"ip": self.dns_resolver, "hostname": "dns-01.lab", "asset_type": "network_device", "criticality": "high"},
            {"ip": self.backup_server, "hostname": "backup-01.lab", "asset_type": "server", "criticality": "medium"},
        ]
        inv += [
            {"ip": ip, "hostname": f"ws-{i:03d}.lab", "asset_type": "endpoint", "criticality": "low"}
            for i, ip in enumerate(self.workstations, 1)
        ]
        return inv


@dataclass
class _Flows:
    cols: dict[str, list[np.ndarray]] = field(default_factory=dict)

    def add(self, **arrays: np.ndarray | str | int | float | None) -> None:
        n = next(len(v) for v in arrays.values() if isinstance(v, np.ndarray))
        for key, value in arrays.items():
            arr = value if isinstance(value, np.ndarray) else np.full(n, value, dtype=object)
            self.cols.setdefault(key, []).append(arr)

    def frame(self) -> pd.DataFrame:
        if not self.cols:
            return pd.DataFrame()
        return pd.DataFrame({k: np.concatenate(v) for k, v in self.cols.items()})


class SyntheticTrafficGenerator:
    """Deterministic (seeded) generator of labelled lab flows."""

    def __init__(self, seed: int = 7, network: LabNetwork | None = None) -> None:
        self.rng = np.random.default_rng(seed)
        self.net = network or LabNetwork()

    # -- helpers ------------------------------------------------------------

    def _arrivals(self, start: float, end: float, rate_per_s: float, diurnal: bool = True) -> np.ndarray:
        """Poisson arrivals with optional day/night intensity modulation (thinning)."""
        span = end - start
        if span <= 0 or rate_per_s <= 0:
            return np.empty(0)
        if not diurnal:
            n = self.rng.poisson(rate_per_s * span)
            return np.sort(self.rng.uniform(start, end, n))
        # intensity(h) in [0.25, 1]; its daily mean is 0.25 + 0.75/pi. Scale the
        # candidate rate so the *average* rate stays `rate_per_s`, then thin.
        mean_intensity = 0.25 + 0.75 / np.pi
        peak = rate_per_s / mean_intensity
        n = self.rng.poisson(peak * span)
        t = np.sort(self.rng.uniform(start, end, n))
        hour = (t % 86400) / 3600.0
        intensity = 0.25 + 0.75 * np.clip(np.sin((hour - 6) / 12 * np.pi), 0, None)
        return t[self.rng.uniform(0, 1, n) < intensity]

    def _lognormal(self, n: int, median: float, sigma: float, low: float = 0, high: float | None = None) -> np.ndarray:
        x = self.rng.lognormal(np.log(max(median, 1e-6)), sigma, n)
        return np.clip(x, low, high if high is not None else np.inf)

    def _choice(self, pool: tuple[str, ...] | list[str], n: int) -> np.ndarray:
        return self.rng.choice(np.array(pool, dtype=object), n)

    def _eph(self, n: int) -> np.ndarray:
        return self.rng.integers(49152, 65535, n)

    def _tcp_session(
        self,
        flows: _Flows,
        t: np.ndarray,
        src: np.ndarray,
        dst: np.ndarray | str,
        dport: int | np.ndarray,
        app: str,
        label: str,
        *,
        bytes_out: np.ndarray,
        bytes_in: np.ndarray,
        duration: np.ndarray,
        episode: str = "",
        failed_share: float = 0.0,
    ) -> None:
        n = len(t)
        if n == 0:
            return
        failed = self.rng.uniform(0, 1, n) < failed_share
        mss = 1200.0
        p_out = np.maximum(1, np.ceil(bytes_out / mss) + self.rng.integers(1, 4, n))
        p_in = np.maximum(1, np.ceil(bytes_in / mss) + self.rng.integers(1, 4, n))
        state = np.where(failed, np.where(self.rng.uniform(0, 1, n) < 0.6, "REJ", "S0"), "SF").astype(object)
        flags = np.where(failed, np.where(state == "REJ", SYN | RST, SYN), FULL)
        flows.add(
            ts=t,
            src_ip=src,
            dst_ip=dst if isinstance(dst, np.ndarray) else np.full(n, dst, dtype=object),
            src_port=self._eph(n),
            dst_port=np.full(n, dport) if isinstance(dport, int) else dport,
            protocol="tcp",
            app_protocol=app,
            duration_ms=np.where(failed, self._lognormal(n, 2, 0.5), duration),
            packets_out=np.where(failed, 1, p_out),
            packets_in=np.where(failed, np.where(state == "REJ", 1, 0), p_in),
            bytes_out=np.where(failed, 60, bytes_out).astype(np.int64),
            bytes_in=np.where(failed, np.where(state == "REJ", 40, 0), bytes_in).astype(np.int64),
            tcp_flags=flags,
            conn_state=state,
            label=label,
            episode=episode,
        )

    def _udp(
        self,
        flows: _Flows,
        t: np.ndarray,
        src: np.ndarray,
        dst: np.ndarray | str,
        dport: int,
        app: str,
        label: str,
        *,
        bytes_out: np.ndarray,
        bytes_in: np.ndarray,
        episode: str = "",
    ) -> None:
        n = len(t)
        if n == 0:
            return
        flows.add(
            ts=t,
            src_ip=src,
            dst_ip=dst if isinstance(dst, np.ndarray) else np.full(n, dst, dtype=object),
            src_port=self._eph(n),
            dst_port=np.full(n, dport),
            protocol="udp",
            app_protocol=app,
            duration_ms=self._lognormal(n, 20, 0.8, 0.5, 5000),
            packets_out=np.ones(n, dtype=np.int64),
            packets_in=(bytes_in > 0).astype(np.int64),
            bytes_out=bytes_out.astype(np.int64),
            bytes_in=bytes_in.astype(np.int64),
            tcp_flags=0,
            conn_state="SF",
            label=label,
            episode=episode,
        )

    # -- normal traffic -----------------------------------------------------

    def normal(self, start: float, end: float, intensity: float = 1.0) -> pd.DataFrame:
        net, f = self.net, _Flows()
        ws = net.workstations
        # Web browsing (per-workstation Poisson).
        t = self._arrivals(start, end, 0.04 * len(ws) * intensity)
        n = len(t)
        self._tcp_session(
            f,
            t,
            self._choice(ws, n),
            self._choice(net.internet_services, n),
            self.rng.choice([443, 443, 443, 80], n),
            "https",
            NORMAL,
            bytes_out=self._lognormal(n, 1200, 0.8, 200),
            bytes_in=self._lognormal(n, 40_000, 1.6, 300, 50e6),
            duration=self._lognormal(n, 900, 1.2, 20, 600_000),
            failed_share=0.01,
        )
        # DNS to the internal resolver, and resolver upstream.
        t = self._arrivals(start, end, 0.06 * len(ws) * intensity)
        n = len(t)
        self._udp(
            f,
            t,
            self._choice(ws, n),
            net.dns_resolver,
            53,
            "dns",
            NORMAL,
            bytes_out=self._lognormal(n, 70, 0.15, 40, 300),
            bytes_in=self._lognormal(n, 180, 0.4, 60, 1500),
        )
        t = self._arrivals(start, end, 0.8 * intensity)
        n = len(t)
        self._udp(
            f,
            t,
            np.full(n, net.dns_resolver, dtype=object),
            self._choice(net.internet_services[:6], n),
            53,
            "dns",
            NORMAL,
            bytes_out=self._lognormal(n, 75, 0.15, 40, 300),
            bytes_in=self._lognormal(n, 200, 0.4, 60, 1500),
        )
        # SMB to the file server.
        t = self._arrivals(start, end, 0.008 * len(ws) * intensity)
        n = len(t)
        self._tcp_session(
            f,
            t,
            self._choice(ws, n),
            net.file_server,
            445,
            "smb",
            NORMAL,
            bytes_out=self._lognormal(n, 4000, 1.5, 300),
            bytes_in=self._lognormal(n, 60_000, 1.8, 300, 5e8),
            duration=self._lognormal(n, 2000, 1.2, 10),
            failed_share=0.005,
        )
        # Kerberos / LDAP to the domain controller.
        t = self._arrivals(start, end, 0.01 * len(ws) * intensity)
        n = len(t)
        self._tcp_session(
            f,
            t,
            self._choice(ws, n),
            net.domain_controller,
            self.rng.choice([88, 389], n),
            "kerberos",
            NORMAL,
            bytes_out=self._lognormal(n, 1500, 0.4, 200),
            bytes_in=self._lognormal(n, 2500, 0.5, 200),
            duration=self._lognormal(n, 40, 0.8, 2),
        )
        # App servers to the database (non-diurnal, steady).
        t = self._arrivals(start, end, 3.0 * intensity, diurnal=False)
        n = len(t)
        self._tcp_session(
            f,
            t,
            self._choice(net.app_servers, n),
            net.db_server,
            5432,
            "postgresql",
            NORMAL,
            bytes_out=self._lognormal(n, 900, 0.9, 100),
            bytes_in=self._lognormal(n, 6000, 1.4, 100, 5e7),
            duration=self._lognormal(n, 15, 1.0, 1),
        )
        # Internet clients to the public web servers.
        t = self._arrivals(start, end, 2.0 * intensity)
        n = len(t)
        self._tcp_session(
            f,
            t,
            self._choice(net.internet_clients, n),
            self._choice(net.web_servers, n),
            self.rng.choice([443, 443, 80], n),
            "https",
            NORMAL,
            bytes_out=self._lognormal(n, 900, 0.7, 150),
            bytes_in=self._lognormal(n, 25_000, 1.4, 300, 2e7),
            duration=self._lognormal(n, 400, 1.0, 5, 120_000),
            failed_share=0.02,
        )
        # Web servers to app servers.
        t = self._arrivals(start, end, 1.5 * intensity)
        n = len(t)
        self._tcp_session(
            f,
            t,
            self._choice(net.web_servers, n),
            self._choice(net.app_servers, n),
            8080,
            "http",
            NORMAL,
            bytes_out=self._lognormal(n, 800, 0.6, 100),
            bytes_in=self._lognormal(n, 8000, 1.2, 100),
            duration=self._lognormal(n, 30, 0.8, 1),
        )
        # Admin SSH to the jump host (occasional typo = failed attempt).
        t = self._arrivals(start, end, 0.01 * intensity)
        n = len(t)
        self._tcp_session(
            f,
            t,
            self._choice(ws[:6], n),
            net.jump_host,
            22,
            "ssh",
            NORMAL,
            bytes_out=self._lognormal(n, 30_000, 1.5, 2000),
            bytes_in=self._lognormal(n, 80_000, 1.5, 2000),
            duration=self._lognormal(n, 300_000, 1.2, 5000, 7_200_000),
            failed_share=0.05,
        )
        # Mail relay outbound.
        t = self._arrivals(start, end, 0.15 * intensity)
        n = len(t)
        self._tcp_session(
            f,
            t,
            np.full(n, net.mail_server, dtype=object),
            self._choice(net.internet_services, n),
            25,
            "smtp",
            NORMAL,
            bytes_out=self._lognormal(n, 30_000, 1.3, 800),
            bytes_in=self._lognormal(n, 1200, 0.4, 200),
            duration=self._lognormal(n, 800, 0.8, 50),
        )
        # Benign periodic traffic: NTP and update checks (regular like a beacon, but normal).
        for host in net.servers:
            period = float(self.rng.choice([64.0, 128.0]))
            t = np.arange(start + self.rng.uniform(0, period), end, period) + self.rng.normal(0, 0.05, 1)
            n = len(t)
            self._udp(
                f,
                t,
                np.full(n, host, dtype=object),
                net.internet_services[0],
                123,
                "ntp",
                NORMAL,
                bytes_out=np.full(n, 76.0),
                bytes_in=np.full(n, 76.0),
            )
        for host in self.rng.choice(np.array(ws, dtype=object), 20, replace=False):
            t = np.arange(start + self.rng.uniform(0, 300), end, 300.0) + self.rng.normal(0, 2.0, 1)
            n = len(t)
            self._tcp_session(
                f,
                t,
                np.full(n, host, dtype=object),
                net.internet_services[1],
                443,
                "https",
                NORMAL,
                bytes_out=self._lognormal(n, 900, 0.1),
                bytes_in=self._lognormal(n, 3000, 0.2),
                duration=self._lognormal(n, 250, 0.3, 20),
            )
        # Nightly backup upload (large, outbound, legitimate).
        day = 86400.0
        for d in np.arange(np.floor(start / day) * day, end, day):
            t0 = d + 2 * 3600
            if start <= t0 < end:
                t = t0 + np.sort(self.rng.uniform(0, 1800, 6))
                n = len(t)
                self._tcp_session(
                    f,
                    t,
                    np.full(n, net.backup_server, dtype=object),
                    net.internet_services[2],
                    443,
                    "https",
                    NORMAL,
                    bytes_out=self._lognormal(n, 4e8, 0.5),
                    bytes_in=self._lognormal(n, 2e5, 0.4),
                    duration=self._lognormal(n, 600_000, 0.4, 1000),
                )
        # Background noise: stray failed connections (misconfigurations, closed ports).
        t = self._arrivals(start, end, 0.05 * intensity)
        n = len(t)
        self._tcp_session(
            f,
            t,
            self._choice(ws, n),
            self._choice(net.servers, n),
            self.rng.choice([22, 80, 443, 445, 3389, 8080, 8443, 9000], n),
            "unknown",
            NORMAL,
            bytes_out=np.full(n, 60.0),
            bytes_in=np.zeros(n),
            duration=np.full(n, 3.0),
            failed_share=1.0,
        )
        return f.frame()

    # -- attack families ----------------------------------------------------

    def port_scan(self, t0: float, episode: str) -> pd.DataFrame:
        f, net = _Flows(), self.net
        attacker = str(self.rng.choice(net.hostile + net.workstations[-5:]))
        targets = list(
            self.rng.choice(
                np.array(net.servers + net.workstations[:10], dtype=object), int(self.rng.integers(1, 6)), replace=False
            )
        )
        n_ports = int(self.rng.integers(150, 1200))
        rate = float(self.rng.choice([5.0, 30.0, 150.0]))  # slow / medium / fast scans
        for tgt in targets:
            ports = self.rng.choice(np.arange(1, 65535), n_ports, replace=False)
            t = t0 + np.sort(self.rng.uniform(0, n_ports / rate, n_ports))
            n = len(t)
            open_mask = np.isin(ports, [22, 80, 443, 445, 3389, 5432, 8080, 53, 88, 389, 25])
            state = np.where(open_mask, "SH", np.where(self.rng.uniform(0, 1, n) < 0.7, "REJ", "S0")).astype(object)
            f.add(
                ts=t,
                src_ip=np.full(n, attacker, dtype=object),
                dst_ip=np.full(n, tgt, dtype=object),
                src_port=self._eph(n),
                dst_port=ports,
                protocol="tcp",
                app_protocol="unknown",
                duration_ms=self._lognormal(n, 1.5, 0.5, 0.1, 50),
                packets_out=np.ones(n, dtype=np.int64),
                packets_in=np.where(state == "S0", 0, 1),
                bytes_out=np.full(n, 44),
                bytes_in=np.where(state == "S0", 0, 40),
                tcp_flags=np.where(state == "REJ", SYN | RST, np.where(state == "SH", SYN | ACK | RST, SYN)),
                conn_state=state,
                label="port_scan",
                episode=episode,
            )
        return f.frame()

    def brute_force(self, t0: float, episode: str) -> pd.DataFrame:
        f, net = _Flows(), self.net
        attacker = str(self.rng.choice(net.hostile))
        target, port, app = [
            (net.jump_host, 22, "ssh"),
            (net.web_servers[0], 3389, "rdp"),
            (net.mail_server, 25, "smtp"),
            (net.jump_host, 21, "ftp"),
        ][int(self.rng.integers(0, 4))]
        n = int(self.rng.integers(300, 3000))
        rate = float(self.rng.uniform(1.0, 12.0))
        t = t0 + np.sort(self.rng.uniform(0, n / rate, n))
        self._tcp_session(
            f,
            t,
            np.full(n, attacker, dtype=object),
            target,
            port,
            app,
            "brute_force",
            bytes_out=self._lognormal(n, 1400, 0.2, 400),
            bytes_in=self._lognormal(n, 1800, 0.2, 400),
            duration=self._lognormal(n, 900, 0.4, 100),
            episode=episode,
            failed_share=0.05,
        )
        return f.frame()

    def ddos(self, t0: float, episode: str) -> pd.DataFrame:
        f, net = _Flows(), self.net
        bots = self.rng.choice(
            np.array(net.hostile + net.internet_clients, dtype=object), int(self.rng.integers(60, 240)), replace=False
        )
        target = str(self.rng.choice(net.web_servers))
        seconds = float(self.rng.uniform(60, 180))
        n = int(seconds * self.rng.uniform(25, 90))
        t = t0 + np.sort(self.rng.uniform(0, seconds, n))
        syn_flood = self.rng.uniform() < 0.6
        if syn_flood:
            f.add(
                ts=t,
                src_ip=self.rng.choice(bots, n),
                dst_ip=np.full(n, target, dtype=object),
                src_port=self._eph(n),
                dst_port=self.rng.choice([80, 443], n),
                protocol="tcp",
                app_protocol="unknown",
                duration_ms=np.zeros(n),
                packets_out=np.ones(n, dtype=np.int64),
                packets_in=np.zeros(n, dtype=np.int64),
                bytes_out=np.full(n, 60),
                bytes_in=np.zeros(n, dtype=np.int64),
                tcp_flags=SYN,
                conn_state="S0",
                label="ddos",
                episode=episode,
            )
        else:  # HTTP flood: completed but tiny, very high rate
            self._tcp_session(
                f,
                t,
                self.rng.choice(bots, n),
                target,
                80,
                "http",
                "ddos",
                bytes_out=self._lognormal(n, 350, 0.2, 100),
                bytes_in=self._lognormal(n, 600, 0.3, 100),
                duration=self._lognormal(n, 40, 0.5, 1),
                episode=episode,
                failed_share=0.3,
            )
        return f.frame()

    def exfiltration(self, t0: float, episode: str) -> pd.DataFrame:
        f, net = _Flows(), self.net
        victim = str(self.rng.choice((*net.workstations, net.db_server, net.file_server)))
        dest = str(self.rng.choice(net.hostile))
        port = int(self.rng.choice([443, 8443, 4444, 993]))
        n = int(self.rng.integers(4, 40))
        t = t0 + np.sort(self.rng.uniform(0, 1800, n))
        self._tcp_session(
            f,
            t,
            np.full(n, victim, dtype=object),
            dest,
            port,
            "unknown" if port != 443 else "https",
            "exfiltration",
            bytes_out=self._lognormal(n, 8e7, 0.9, 5e6, 3e9),
            bytes_in=self._lognormal(n, 20_000, 0.6, 1000),
            duration=self._lognormal(n, 90_000, 0.7, 2000),
            episode=episode,
        )
        return f.frame()

    def c2_beaconing(self, t0: float, episode: str) -> pd.DataFrame:
        f, net = _Flows(), self.net
        victim = str(self.rng.choice(net.workstations))
        c2 = str(self.rng.choice(net.hostile))
        period = float(self.rng.choice([15.0, 30.0, 60.0]))
        jitter = float(self.rng.uniform(0.0, 0.1)) * period
        count = int(self.rng.integers(60, 240))
        t = t0 + np.arange(count) * period + self.rng.normal(0, jitter + 1e-3, count)
        port = int(self.rng.choice([443, 8080, 8443, 53]))
        if port == 53:
            self._udp(
                f,
                np.sort(t),
                np.full(count, victim, dtype=object),
                c2,
                53,
                "dns",
                "c2_beaconing",
                bytes_out=self._lognormal(count, 110, 0.1),
                bytes_in=self._lognormal(count, 160, 0.2),
                episode=episode,
            )
        else:
            self._tcp_session(
                f,
                np.sort(t),
                np.full(count, victim, dtype=object),
                c2,
                port,
                "https" if port == 443 else "http",
                "c2_beaconing",
                bytes_out=self._lognormal(count, 450, 0.15),
                bytes_in=self._lognormal(count, 700, 0.4),
                duration=self._lognormal(count, 180, 0.3, 10),
                episode=episode,
            )
        return f.frame()

    def dns_tunneling(self, t0: float, episode: str) -> pd.DataFrame:
        f, net = _Flows(), self.net
        victim = str(self.rng.choice(net.workstations))
        server = str(self.rng.choice(net.hostile))
        seconds = float(self.rng.uniform(300, 1500))
        n = int(seconds * self.rng.uniform(2, 15))
        t = t0 + np.sort(self.rng.uniform(0, seconds, n))
        self._udp(
            f,
            t,
            np.full(n, victim, dtype=object),
            server,
            53,
            "dns",
            "dns_tunneling",
            bytes_out=self._lognormal(n, 240, 0.2, 120, 512),
            bytes_in=self._lognormal(n, 420, 0.3, 100, 1400),
            episode=episode,
        )
        return f.frame()

    def lateral_movement(self, t0: float, episode: str) -> pd.DataFrame:
        f, net = _Flows(), self.net
        pivot = str(self.rng.choice(net.workstations))
        targets = self.rng.choice(
            np.array(net.workstations + net.servers, dtype=object), int(self.rng.integers(15, 70)), replace=False
        )
        rows = []
        t = t0
        for tgt in targets:
            for port, app in ((445, "smb"), (135, "dcerpc"), (5985, "winrm"), (3389, "rdp")):
                if self.rng.uniform() < 0.6:
                    t += float(self.rng.exponential(1.5))
                    rows.append((t, tgt, port, app))
        if not rows:
            return pd.DataFrame()
        ts = np.array([r[0] for r in rows])
        n = len(ts)
        self._tcp_session(
            f,
            ts,
            np.full(n, pivot, dtype=object),
            np.array([r[1] for r in rows], dtype=object),
            np.array([r[2] for r in rows]),
            "smb",
            "lateral_movement",
            bytes_out=self._lognormal(n, 5000, 1.0, 300),
            bytes_in=self._lognormal(n, 3000, 1.0, 100),
            duration=self._lognormal(n, 600, 1.0, 10),
            episode=episode,
            failed_share=0.45,
        )
        return f.frame()

    def slow_dos(self, t0: float, episode: str) -> pd.DataFrame:
        f, net = _Flows(), self.net
        sources = self.rng.choice(np.array(net.hostile, dtype=object), int(self.rng.integers(1, 6)), replace=False)
        target = str(self.rng.choice(net.web_servers))
        n = int(self.rng.integers(300, 1500))
        t = t0 + np.sort(self.rng.uniform(0, 600, n))
        self._tcp_session(
            f,
            t,
            self.rng.choice(sources, n),
            target,
            80,
            "http",
            "slow_dos",
            bytes_out=self._lognormal(n, 500, 0.3, 100),
            bytes_in=self._lognormal(n, 80, 0.3, 0),
            duration=self._lognormal(n, 180_000, 0.4, 30_000, 900_000),
            episode=episode,
        )
        return f.frame()

    # -- dataset assembly ---------------------------------------------------

    def generate(
        self,
        start: float,
        hours: float,
        families: tuple[str, ...] = ATTACK_FAMILIES,
        episodes_per_family: int = 4,
        intensity: float = 1.0,
    ) -> pd.DataFrame:
        """Normal traffic for `hours` with attack episodes spread across the span."""
        end = start + hours * 3600
        parts = [self.normal(start, end, intensity)]
        builders: dict[str, Callable[[float, str], pd.DataFrame]] = {
            name: getattr(self, name) for name in ATTACK_FAMILIES
        }
        for family in families:
            if family not in builders:
                raise ValueError(f"unknown attack family: {family}")
            # Stratify episodes across the timeline so every time split sees each family.
            edges = np.linspace(start + 600, end - 2400, episodes_per_family + 1)
            for e in range(episodes_per_family):
                t0 = float(self.rng.uniform(edges[e], edges[e + 1]))
                parts.append(builders[family](t0, f"{family}-{e + 1}"))
        df = pd.concat([p for p in parts if len(p)], ignore_index=True)
        df = df[(df["ts"] >= start) & (df["ts"] < end + 3600)]
        return finalize(df, self.net)


def _is_internal(ips: pd.Series) -> np.ndarray:
    return ips.astype(str).str.startswith("10.").to_numpy()


def finalize(df: pd.DataFrame, net: LabNetwork | None = None) -> pd.DataFrame:
    """Add direction, sort by time and assign stable external IDs."""
    df = df.sort_values("ts", kind="stable").reset_index(drop=True)
    src_int, dst_int = _is_internal(df["src_ip"]), _is_internal(df["dst_ip"])
    df["direction"] = np.select(
        [src_int & dst_int, src_int & ~dst_int, ~src_int & dst_int], ["internal", "outbound", "inbound"], "external"
    )
    for col in ("packets_out", "packets_in", "bytes_out", "bytes_in", "tcp_flags", "src_port", "dst_port"):
        df[col] = pd.to_numeric(df[col]).fillna(0).astype(np.int64)
    df["duration_ms"] = pd.to_numeric(df["duration_ms"]).astype(float).round(3)
    df["episode"] = df["episode"].fillna("")
    return df
