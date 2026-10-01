from scapy.layers.inet import ICMP, IP, TCP, UDP
from scapy.layers.inet6 import ICMPv6EchoRequest, IPv6
from scapy.layers.l2 import ARP, Ether
from scapy.packet import Raw

from netwatch.records import parse_packet
from tests.conftest import rec


def test_parse_tcp_packet_extracts_all_fields():
    pkt = Ether() / IP(src="1.2.3.4", dst="5.6.7.8") / TCP(sport=1234, dport=443, flags="SA")
    pkt = pkt / Raw(load=b"x" * 10)
    pkt.time = 1000.5
    r = parse_packet(pkt)
    assert r is not None
    assert (r.ts, r.src, r.dst, r.sport, r.dport, r.proto) == (
        1000.5,
        "1.2.3.4",
        "5.6.7.8",
        1234,
        443,
        "TCP",
    )
    assert r.flags == "SA"
    assert r.length == len(pkt)


def test_parse_udp_icmp_and_ipv6():
    udp = parse_packet(IP(src="1.1.1.1", dst="2.2.2.2") / UDP(sport=5353, dport=53))
    icmp = parse_packet(IP(src="1.1.1.1", dst="2.2.2.2") / ICMP())
    v6 = parse_packet(IPv6(src="::1", dst="::2") / ICMPv6EchoRequest())
    assert udp.proto == "UDP" and (udp.sport, udp.dport) == (5353, 53) and udp.flags == ""
    assert icmp.proto == "ICMP" and icmp.sport is None and icmp.dport is None
    assert v6.proto == "ICMP" and v6.src == "::1"


def test_non_ip_frames_are_skipped():
    assert parse_packet(Ether() / ARP()) is None


def test_syn_and_handshake_ack_classification():
    assert rec(0, flags="S").is_syn
    assert not rec(0, flags="SA").is_syn
    assert rec(0, flags="A").is_handshake_ack
    assert not rec(0, flags="SA").is_handshake_ack
    assert not rec(0, proto="UDP", flags="").is_syn


def test_probe_definition_ignores_replies():
    # Packets that open or probe a port count...
    assert rec(0, flags="S").is_probe
    assert rec(0, flags="F").is_probe  # FIN scan
    assert rec(0, flags="").is_probe  # NULL scan
    assert rec(0, proto="UDP", sport=50000, dport=53, flags="").is_probe
    # ...replies and established traffic do not.
    assert not rec(0, flags="SA").is_probe
    assert not rec(0, flags="PA").is_probe
    assert not rec(0, proto="UDP", sport=53, dport=50000, flags="").is_probe
    assert not rec(0, proto="ICMP", sport=None, dport=None, flags="").is_probe
