import random

from netwatch.analyzer import Analyzer
from netwatch.detectors import (
    DetectionEngine,
    DetectorConfig,
    PortScanDetector,
    Severity,
    StatDetector,
    SynFloodDetector,
    VolumeDetector,
)
from netwatch.features import WindowStats
from tests.conftest import rec


def window(start: float, packets: int, **kwargs) -> WindowStats:
    kwargs.setdefault("bytes", packets * 500)
    kwargs.setdefault("unique_src", 10)
    kwargs.setdefault("unique_dst", 10)
    return WindowStats(start=start, duration=1.0, packets=packets, **kwargs)


def noisy_baseline(detector, n: int = 30, seed: int = 3) -> None:
    """Teach a detector ~100 packets/s with realistic jitter."""
    rng = random.Random(seed)
    for i in range(n):
        assert detector.check(window(i, rng.randint(90, 110))) == []


def test_volume_detector_flags_spike_and_drop():
    det = VolumeDetector(DetectorConfig())
    noisy_baseline(det)
    [spike] = det.check(window(30, 1200))
    assert spike.type == "traffic_spike" and spike.severity is Severity.HIGH
    assert "x normal" in spike.explanation and "baseline" in spike.explanation
    [drop] = det.check(window(31, 0))
    assert drop.type == "traffic_drop" and drop.severity is Severity.HIGH


def test_volume_detector_needs_magnitude_as_well_as_z_score():
    det = VolumeDetector(DetectorConfig(spike_factor=3.0))
    noisy_baseline(det)
    # Statistically unusual (z is large) but only ~1.6x normal: not called a spike.
    assert det.check(window(30, 160)) == []


def test_no_drop_alerts_on_nearly_idle_links():
    det = VolumeDetector(DetectorConfig(min_drop_baseline=5.0))
    for i in range(20):
        det.check(window(i, 2 + i % 2))
    assert det.check(window(20, 0)) == []


def test_statistical_detectors_stay_silent_during_warmup():
    det = VolumeDetector(DetectorConfig(warmup=10))
    for i in range(9):
        det.check(window(i, 100))
    # Huge jump, but the baseline only has 9 samples: no alert yet.
    assert det.check(window(9, 100_000)) == []


def test_stat_detector_flags_each_metric_independently():
    det = StatDetector(DetectorConfig())
    rng = random.Random(1)
    for i in range(30):
        det.check(
            window(
                i,
                100,
                bytes=rng.randint(45_000, 55_000),
                unique_src=rng.randint(9, 11),
                unique_dst=10,
            )
        )
    alerts = det.check(window(30, 100, bytes=50_000, unique_src=400, unique_dst=10))
    assert [a.type for a in alerts] == ["unique_src_anomaly"]
    assert "above baseline" in alerts[0].explanation


def test_port_scan_vertical_and_horizontal():
    det = PortScanDetector(DetectorConfig(port_scan_ports=20, port_scan_hosts=20))
    vertical = window(
        0,
        200,
        ports_per_src={"10.9.9.9": 150, "10.0.0.1": 3},
        hosts_per_src={"10.9.9.9": 1, "10.0.0.1": 2},
    )
    [alert] = det.check(vertical)
    assert alert.source == "10.9.9.9" and alert.severity is Severity.HIGH
    assert "150 distinct ports" in alert.explanation

    sweep = window(1, 200, ports_per_src={"10.6.6.6": 1}, hosts_per_src={"10.6.6.6": 40})
    [alert] = det.check(sweep)
    assert alert.type == "port_scan" and "host sweep" in alert.explanation
    assert alert.severity is Severity.MEDIUM


def test_busy_server_is_not_mistaken_for_a_scanner():
    analyzer = Analyzer()
    replies = [rec(0.01 * i, "web", f"client{i}", 443, 50000 + i, flags="PA") for i in range(80)]
    list(analyzer.run(replies))
    assert analyzer.alerts == []


def test_syn_flood_detected_with_spoofed_sources():
    analyzer = Analyzer()
    flood = [
        rec(i / 500, f"203.0.113.{i % 250}", "10.0.0.5", 1024 + i, 80, flags="S")
        for i in range(500)
    ]
    list(analyzer.run(flood))
    [alert] = [a for a in analyzer.alerts if a.type == "syn_flood"]
    assert alert.source == "distributed" and alert.target == "10.0.0.5:80"
    assert "0% of handshakes completed" in alert.explanation


def test_syn_flood_from_one_host_names_that_host():
    det = SynFloodDetector(DetectorConfig())
    stats = window(
        0,
        300,
        tcp_packets=300,
        syn_count=300,
        syn_by_target={"10.0.0.5:80": 300},
        syn_by_src={"6.6.6.6": 300},
    )
    [alert] = det.check(stats)
    assert alert.source == "6.6.6.6"


def test_completed_handshakes_and_port_scans_are_not_syn_floods():
    det = SynFloodDetector(DetectorConfig())
    busy_but_healthy = window(
        0,
        600,
        tcp_packets=600,
        syn_count=200,
        handshakes_completed=190,
        syn_by_target={"10.0.0.5:443": 200},
        completed_by_target={"10.0.0.5:443": 190},
        syn_by_src={f"c{i}": 2 for i in range(100)},
    )
    assert det.check(busy_but_healthy) == []
    # A port scan sends many SYNs too, but only one to each port.
    scan = window(
        1,
        300,
        tcp_packets=300,
        syn_count=300,
        syn_by_target={f"10.0.0.9:{p}": 1 for p in range(300)},
        syn_by_src={"6.6.6.6": 300},
    )
    assert det.check(scan) == []


def test_cooldown_suppresses_repeats_of_the_same_alert():
    engine = DetectionEngine(DetectorConfig(cooldown=10.0))
    scan = {"ports_per_src": {"6.6.6.6": 100}, "hosts_per_src": {"6.6.6.6": 1}}
    fired = [len(engine.evaluate(window(t, 100, **scan))) for t in range(25)]
    assert fired == [1] + [0] * 9 + [1] + [0] * 9 + [1] + [0] * 4


def test_partial_window_skips_baseline_detectors():
    engine = DetectionEngine(DetectorConfig())
    for i in range(20):
        engine.evaluate(window(i, 100))
    # The capture ended 0.1 s into this window: 10 packets is not a drop.
    assert engine.evaluate(window(20, 10), partial=True) == []
    assert engine.evaluate(window(20, 10)) != []


def test_alert_serialises_to_plain_types():
    det = PortScanDetector(DetectorConfig())
    [alert] = det.check(window(0, 1, ports_per_src={"x": 100}, hosts_per_src={"x": 1}))
    data = alert.to_dict()
    assert data["severity"] == "high" and data["source"] == "x" and data["type"] == "port_scan"
