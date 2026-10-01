"""Generate synthetic pcap files so NetWatch can be tried (and tested) without root.

Every scenario starts with the same "normal office LAN" background: clients
opening short HTTPS/HTTP/SSH sessions with full TCP handshakes, DNS lookups and
the odd ping. Attack scenarios then overlay one event in the middle, after the
detectors' warm-up period. Generation is seeded, so the same arguments always
produce byte-identical files, which keeps tests and the README output stable.

The traffic is plausible, not realistic: real networks are burstier and far
more varied. It exists to exercise each detector, not to benchmark it.
"""

from __future__ import annotations

import random
from collections.abc import Callable
from pathlib import Path

from scapy.layers.inet import ICMP, IP, TCP, UDP
from scapy.layers.l2 import Ether
from scapy.packet import Packet, Raw
from scapy.utils import wrpcap

START = 1_767_225_600.0  # 2026-01-01T00:00:00Z, so window timestamps are easy to read

CLIENTS = [f"192.168.1.{i}" for i in range(10, 30)]
SERVERS = [
    ("10.0.0.2", 443),
    ("10.0.0.3", 443),
    ("10.0.0.4", 80),
    ("10.0.0.5", 80),
    ("10.0.0.6", 22),
]
DNS_SERVER = "192.168.1.1"
SCANNER = "192.168.1.66"
SCAN_TARGET = "192.168.1.20"
FLOOD_TARGET = ("10.0.0.5", 80)
BULK_SERVER = ("10.0.0.3", 443)
BULK_CLIENT = "192.168.1.12"

# Fixed MACs: without them scapy would try to ARP-resolve every destination.
_MAC_A = "02:00:00:00:00:01"
_MAC_B = "02:00:00:00:00:02"

ATTACK_SECONDS = 6.0


class TrafficBuilder:
    """Collects timestamped packets; helper methods emit whole conversations."""

    def __init__(self, seed: int) -> None:
        self.rng = random.Random(seed)
        self.packets: list[Packet] = []

    def emit(self, ts: float, pkt: Packet) -> None:
        pkt.time = ts
        self.packets.append(pkt)

    def _tcp(
        self, ts: float, src: str, dst: str, sport: int, dport: int, flags: str, payload: int = 0
    ) -> None:
        pkt = (
            Ether(src=_MAC_A, dst=_MAC_B)
            / IP(src=src, dst=dst)
            / TCP(sport=sport, dport=dport, flags=flags)
        )
        if payload:
            pkt = pkt / Raw(load=bytes(payload))
        self.emit(ts, pkt)

    def ephemeral_port(self) -> int:
        return self.rng.randint(49152, 65535)

    def tcp_session(self, t: float, client: str, server: str, dport: int) -> None:
        """Handshake, a request, a few response segments with ACKs, and a FIN close."""
        rng, sport = self.rng, self.ephemeral_port()
        rtt = rng.uniform(0.002, 0.03)
        self._tcp(t, client, server, sport, dport, "S")
        self._tcp(t + rtt / 2, server, client, dport, sport, "SA")
        t += rtt
        self._tcp(t, client, server, sport, dport, "A")
        self._tcp(t + 0.001, client, server, sport, dport, "PA", rng.randint(200, 600))
        t += rtt
        for _ in range(rng.randint(2, 5)):
            t += rng.uniform(0.001, 0.02)
            self._tcp(t, server, client, dport, sport, "PA", rng.randint(800, 1400))
            self._tcp(t + rtt / 2, client, server, sport, dport, "A")
        t += rtt
        self._tcp(t, client, server, sport, dport, "FA")
        self._tcp(t + rtt / 2, server, client, dport, sport, "FA")
        self._tcp(t + rtt, client, server, sport, dport, "A")

    def dns_lookup(self, t: float, client: str) -> None:
        sport = self.ephemeral_port()
        base = Ether(src=_MAC_A, dst=_MAC_B)
        self.emit(
            t,
            base
            / IP(src=client, dst=DNS_SERVER)
            / UDP(sport=sport, dport=53)
            / Raw(load=bytes(self.rng.randint(30, 60))),
        )
        self.emit(
            t + self.rng.uniform(0.001, 0.01),
            base
            / IP(src=DNS_SERVER, dst=client)
            / UDP(sport=53, dport=sport)
            / Raw(load=bytes(self.rng.randint(60, 200))),
        )

    def ping(self, t: float, client: str, server: str) -> None:
        base = Ether(src=_MAC_A, dst=_MAC_B)
        self.emit(t, base / IP(src=client, dst=server) / ICMP(type=8) / Raw(load=bytes(56)))
        self.emit(t + 0.005, base / IP(src=server, dst=client) / ICMP(type=0) / Raw(load=bytes(56)))

    def normal(self, t0: float, t1: float, quiet: tuple[float, float] | None = None) -> None:
        """Background LAN traffic (~60 packets/s) from t0 to t1, optionally silent in ``quiet``."""
        rng = self.rng
        second = t0
        while second < t1:
            if quiet and quiet[0] <= second < quiet[1]:
                second += 1
                continue
            for _ in range(max(1, round(rng.gauss(4, 1)))):
                server, port = rng.choice(SERVERS)
                self.tcp_session(second + rng.random() * 0.7, rng.choice(CLIENTS), server, port)
            for _ in range(max(0, round(rng.gauss(5, 1.5)))):
                self.dns_lookup(second + rng.random() * 0.95, rng.choice(CLIENTS))
            if rng.random() < 0.5:
                self.ping(second + rng.random() * 0.9, rng.choice(CLIENTS), rng.choice(SERVERS)[0])
            second += 1

    def port_scan(self, t0: float, seconds: float, rate: int = 100) -> None:
        """SCANNER sends SYNs to many ports on SCAN_TARGET, like ``nmap -sS``."""
        open_ports = {22, 80, 443}
        ports = list(range(1, int(rate * seconds) + 1))
        self.rng.shuffle(ports)
        sport = self.ephemeral_port()
        for i, port in enumerate(ports):
            t = t0 + i / rate
            self._tcp(t, SCANNER, SCAN_TARGET, sport, port, "S")
            if port in open_ports:
                self._tcp(t + 0.001, SCAN_TARGET, SCANNER, port, sport, "SA")
                self._tcp(t + 0.002, SCANNER, SCAN_TARGET, sport, port, "R")
            else:
                self._tcp(t + 0.001, SCAN_TARGET, SCANNER, port, sport, "RA")

    def syn_flood(self, t0: float, seconds: float, rate: int = 400) -> None:
        """Spoofed SYNs to FLOOD_TARGET; the server answers some, nobody completes."""
        rng = self.rng
        server, port = FLOOD_TARGET
        for i in range(int(rate * seconds)):
            t = t0 + i / rate
            spoofed = (
                f"{rng.randint(1, 223)}.{rng.randint(0, 255)}.{rng.randint(0, 255)}."
                f"{rng.randint(1, 254)}"
            )
            sport = self.ephemeral_port()
            self._tcp(t, spoofed, server, sport, port, "S")
            if rng.random() < 0.25:  # the backlog fills up, so most SYNs go unanswered
                self._tcp(t + 0.001, server, spoofed, port, sport, "SA")

    def bulk_transfer(self, t0: float, seconds: float, rate: int = 600) -> None:
        """A large download: full-size segments from BULK_SERVER, an ACK every second one."""
        server, port = BULK_SERVER
        sport = self.ephemeral_port()
        self._tcp(t0, BULK_CLIENT, server, sport, port, "S")
        self._tcp(t0 + 0.005, server, BULK_CLIENT, port, sport, "SA")
        self._tcp(t0 + 0.01, BULK_CLIENT, server, sport, port, "A")
        for i in range(int(rate * seconds)):
            t = t0 + 0.02 + i / rate
            self._tcp(t, server, BULK_CLIENT, port, sport, "PA", 1400)
            if i % 2:
                self._tcp(t + 0.0005, BULK_CLIENT, server, sport, port, "A")

    def sorted_packets(self) -> list[Packet]:
        return sorted(self.packets, key=lambda p: float(p.time))


def _normal(b: TrafficBuilder, duration: float) -> None:
    b.normal(START, START + duration)


def _portscan(b: TrafficBuilder, duration: float) -> None:
    b.normal(START, START + duration)
    b.port_scan(START + duration / 2, ATTACK_SECONDS)


def _synflood(b: TrafficBuilder, duration: float) -> None:
    b.normal(START, START + duration)
    b.syn_flood(START + duration / 2, ATTACK_SECONDS)


def _spike(b: TrafficBuilder, duration: float) -> None:
    b.normal(START, START + duration)
    b.bulk_transfer(START + duration / 2, ATTACK_SECONDS)


def _outage(b: TrafficBuilder, duration: float) -> None:
    mid = START + duration // 2
    b.normal(START, START + duration, quiet=(mid, mid + ATTACK_SECONDS))


def _mixed(b: TrafficBuilder, duration: float) -> None:
    b.normal(START, START + duration, quiet=(START + duration * 0.8, START + duration * 0.8 + 6))
    b.port_scan(START + duration * 0.2, ATTACK_SECONDS)
    b.syn_flood(START + duration * 0.4, ATTACK_SECONDS)
    b.bulk_transfer(START + duration * 0.6, ATTACK_SECONDS)


# name -> (builder, default duration in seconds, description)
SCENARIOS: dict[str, tuple[Callable[[TrafficBuilder, float], None], float, str]] = {
    "normal": (_normal, 60, "background LAN traffic only; should raise no alerts"),
    "portscan": (_portscan, 60, f"{SCANNER} SYN-scans 600 ports on {SCAN_TARGET}"),
    "synflood": (_synflood, 60, "spoofed SYN flood against 10.0.0.5:80 (400 SYN/s)"),
    "spike": (_spike, 60, "a 6 s bulk download at ~15x the normal packet rate"),
    "outage": (_outage, 60, "all traffic stops for 6 s"),
    "mixed": (_mixed, 150, "port scan, SYN flood, spike and outage, one after another"),
}

MIN_DURATION = 25.0  # leaves room for the warm-up period before the attack


def build_scenario(name: str, duration: float | None = None, seed: int = 1) -> list[Packet]:
    """Return the packets of scenario ``name`` in timestamp order."""
    if name not in SCENARIOS:
        raise ValueError(f"unknown scenario {name!r}; choose from {', '.join(SCENARIOS)}")
    build, default_duration, _ = SCENARIOS[name]
    duration = default_duration if duration is None else duration
    if duration < MIN_DURATION:
        raise ValueError(f"duration must be at least {MIN_DURATION:g}s")
    builder = TrafficBuilder(seed)
    build(builder, duration)
    return builder.sorted_packets()


def write_scenario(
    name: str, path: str | Path, duration: float | None = None, seed: int = 1
) -> int:
    """Write scenario ``name`` to a pcap file and return the number of packets written."""
    packets = build_scenario(name, duration=duration, seed=seed)
    wrpcap(str(path), packets)
    return len(packets)
