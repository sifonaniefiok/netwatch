"""Turn scapy packets into small, plain records.

This is the only module that looks inside scapy packet objects. Everything
downstream (features, detectors, UI, tests) works on ``PacketRecord``, which
keeps the analysis core fast, easy to test without pcaps, and independent of
scapy's object model.
"""

from __future__ import annotations

from dataclasses import dataclass

from scapy.layers.inet import ICMP, IP, TCP, UDP
from scapy.layers.inet6 import IPv6
from scapy.packet import Packet

_IPV6_NEXT_HEADER_ICMPV6 = 58


@dataclass(frozen=True, slots=True)
class PacketRecord:
    """The handful of fields NetWatch needs from one packet.

    ``sport``/``dport`` are ``None`` for protocols without ports (ICMP, ...).
    ``flags`` holds TCP flags in scapy's letter form, e.g. ``"S"`` (SYN),
    ``"SA"`` (SYN-ACK), ``"PA"`` (PUSH-ACK); it is empty for non-TCP packets.
    """

    ts: float
    src: str
    dst: str
    sport: int | None
    dport: int | None
    proto: str
    length: int
    flags: str = ""

    @property
    def is_syn(self) -> bool:
        """A connection-opening SYN (SYN without ACK)."""
        return self.proto == "TCP" and "S" in self.flags and "A" not in self.flags

    @property
    def is_handshake_ack(self) -> bool:
        """A bare ACK, which is what completes a three-way handshake."""
        return self.proto == "TCP" and "A" in self.flags and "S" not in self.flags

    @property
    def is_probe(self) -> bool:
        """Does this packet *try to reach* a port, rather than reply from one?

        Port-scan detection counts distinct destination ports per source. If we
        counted every packet, a busy web server answering 50 clients would look
        like it "touched" 50 ports (the clients' ephemeral ports). So we only
        count packets that initiate or probe:

        * TCP without the ACK flag: SYN, FIN, NULL and XMAS scans all look like
          this, while every packet of an established connection carries ACK.
        * UDP where the destination port is lower than the source port: clients
          send from high ephemeral ports to low service ports (DNS 53, NTP 123),
          and replies go the other way.
        """
        if self.dport is None:
            return False
        if self.proto == "TCP":
            return "A" not in self.flags
        if self.proto == "UDP":
            return self.sport is not None and self.dport < self.sport
        return False


def parse_packet(pkt: Packet) -> PacketRecord | None:
    """Extract a ``PacketRecord`` from a scapy packet, or ``None`` if it is not IP.

    Non-IP frames (ARP, STP, ...) are skipped: every feature NetWatch computes
    is about IP hosts and ports.
    """
    if IP in pkt:
        ip = pkt[IP]
    elif IPv6 in pkt:
        ip = pkt[IPv6]
    else:
        return None

    sport: int | None = None
    dport: int | None = None
    flags = ""
    if TCP in pkt:
        proto = "TCP"
        sport, dport = int(pkt[TCP].sport), int(pkt[TCP].dport)
        flags = str(pkt[TCP].flags)
    elif UDP in pkt:
        proto = "UDP"
        sport, dport = int(pkt[UDP].sport), int(pkt[UDP].dport)
    elif ICMP in pkt or (isinstance(ip, IPv6) and ip.nh == _IPV6_NEXT_HEADER_ICMPV6):
        proto = "ICMP"
    else:
        proto = "OTHER"

    return PacketRecord(
        ts=float(pkt.time),
        src=str(ip.src),
        dst=str(ip.dst),
        sport=sport,
        dport=dport,
        proto=proto,
        length=len(pkt),
        flags=flags,
    )
