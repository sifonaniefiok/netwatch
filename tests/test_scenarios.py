"""End-to-end: synthetic pcap -> read back -> windows -> alerts."""

import pytest
from scapy.utils import rdpcap, wrpcapng

from netwatch.analyzer import Analyzer
from netwatch.records import parse_packet
from netwatch.sources import CaptureError, read_pcap
from netwatch.synth import SCAN_TARGET, SCANNER, build_scenario
from tests.conftest import SCENARIO_SECONDS


def analyze(path) -> Analyzer:
    analyzer = Analyzer()
    for _ in analyzer.run(read_pcap(path)):
        pass
    return analyzer


def alert_types(analyzer: Analyzer) -> set[str]:
    return {a.type for a in analyzer.alerts}


def test_pcap_round_trip_preserves_records(scenario_pcap):
    path = scenario_pcap("normal")
    expected = [parse_packet(p) for p in build_scenario("normal", duration=SCENARIO_SECONDS)]
    got = list(read_pcap(path))
    assert len(got) == len(expected) == len(rdpcap(str(path)))
    assert [(r.src, r.dst, r.sport, r.dport, r.proto, r.flags, r.length) for r in got] == [
        (r.src, r.dst, r.sport, r.dport, r.proto, r.flags, r.length) for r in expected
    ]
    assert got[0].ts == pytest.approx(expected[0].ts, abs=1e-6)  # pcap stores microseconds


def test_pcapng_files_are_read_too(tmp_path):
    packets = build_scenario("normal", duration=SCENARIO_SECONDS)[:200]
    path = tmp_path / "sample.pcapng"
    wrpcapng(str(path), packets)
    records = list(read_pcap(path))
    assert len(records) == 200
    assert records[0].src == parse_packet(packets[0]).src


def test_generation_is_deterministic():
    a = build_scenario("portscan", duration=25, seed=5)
    b = build_scenario("portscan", duration=25, seed=5)
    assert [bytes(p) for p in a] == [bytes(p) for p in b]


def test_unknown_scenario_and_short_duration_are_rejected():
    with pytest.raises(ValueError):
        build_scenario("nope")
    with pytest.raises(ValueError):
        build_scenario("normal", duration=5)


def test_normal_traffic_is_quiet(scenario_pcap):
    assert analyze(scenario_pcap("normal")).alerts == []


@pytest.mark.parametrize("seed", [2, 3, 4])
def test_normal_traffic_never_raises_serious_alerts(seed):
    analyzer = Analyzer()
    records = (parse_packet(p) for p in build_scenario("normal", duration=60, seed=seed))
    list(analyzer.run(records))
    assert [a for a in analyzer.alerts if a.severity.value != "low"] == []


def test_port_scan_is_detected_and_attributed(scenario_pcap):
    analyzer = analyze(scenario_pcap("portscan"))
    scans = [a for a in analyzer.alerts if a.type == "port_scan"]
    assert len(scans) == 1  # one alert, not one per second, thanks to the cooldown
    assert scans[0].source == SCANNER
    assert "on 1 host" in scans[0].explanation and SCAN_TARGET not in scans[0].source
    assert "syn_flood" not in alert_types(analyzer)


def test_syn_flood_is_detected(scenario_pcap):
    analyzer = analyze(scenario_pcap("synflood"))
    assert "syn_flood" in alert_types(analyzer)
    assert "port_scan" not in alert_types(analyzer)


def test_traffic_spike_is_detected(scenario_pcap):
    types = alert_types(analyze(scenario_pcap("spike")))
    assert "traffic_spike" in types
    assert not types & {"port_scan", "syn_flood", "traffic_drop"}


def test_outage_is_detected_as_drop(scenario_pcap):
    types = alert_types(analyze(scenario_pcap("outage")))
    assert "traffic_drop" in types
    assert "traffic_spike" not in types


def test_read_pcap_reports_bad_input(tmp_path):
    with pytest.raises(CaptureError, match="not found"):
        read_pcap(tmp_path / "missing.pcap")
    junk = tmp_path / "junk.pcap"
    junk.write_bytes(b"definitely not a capture file")
    with pytest.raises(CaptureError, match="not a pcap"):
        read_pcap(junk)
