"""Anomaly detectors that inspect one finished window at a time.

There are two families:

* **Statistical** detectors (``VolumeDetector``, ``StatDetector``) learn a
  baseline per metric with an EWMA and alert when a window's z-score crosses
  the threshold. They need no knowledge of attacks, only of "normal".
* **Rule** detectors (``PortScanDetector``, ``SynFloodDetector``) encode what
  a specific attack looks like. They need no warm-up and their alerts explain
  themselves ("probed 120 ports"), but they only catch what they describe.

``DetectionEngine`` runs all of them and removes repeats of the same alert.
"""

from __future__ import annotations

from collections.abc import Callable
from dataclasses import asdict, dataclass
from enum import Enum

from netwatch.baseline import GuardedBaseline
from netwatch.features import WindowStats
from netwatch.units import human_bytes


class Severity(str, Enum):
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"


@dataclass(frozen=True)
class Alert:
    """One detection. ``source`` is the host responsible (or ``"network"`` for
    traffic-wide anomalies); ``target`` is what was attacked, when known."""

    ts: float
    type: str
    severity: Severity
    source: str
    explanation: str
    target: str = ""

    def to_dict(self) -> dict[str, str | float]:
        data = asdict(self)
        data["severity"] = self.severity.value
        return data


@dataclass
class DetectorConfig:
    """Every tunable number in one place. Defaults suit a small LAN at 1 s windows."""

    alpha: float = 0.1  # EWMA weight of the newest window
    threshold: float = 4.0  # |z| at or above this is anomalous
    warmup: int = 10  # windows to learn before statistical alerts are allowed
    relearn_after: int = 30  # consecutive anomalous windows before accepting a new normal
    cooldown: float = 10.0  # seconds before the same alert may fire again
    port_scan_ports: int = 20  # distinct ports one source may probe per window
    port_scan_hosts: int = 20  # distinct hosts one source may probe per window
    syn_flood_rate: float = 50.0  # SYN/s towards one service before we look closer
    syn_flood_max_completion: float = 0.2  # flood if at most this share of handshakes finish
    syn_flood_min_ratio: float = 0.5  # ...and at least this share of TCP packets are SYNs
    spike_factor: float = 3.0  # a spike must also be this many times the baseline
    drop_factor: float = 0.25  # a drop must also fall below this fraction of the baseline
    min_drop_baseline: float = 5.0  # packets/s; quieter links are not judged for drops


def _fmt_value(value: float, unit: str) -> str:
    return f"{human_bytes(value)}/s" if unit == "B/s" else f"{value:.1f} {unit}"


class VolumeDetector:
    """Traffic spike / drop on packets per second.

    Two conditions must both hold, which keeps alerts meaningful:
    the window is statistically unusual (|z| >= threshold) *and* the change is
    large in absolute terms (at least ``spike_factor`` times the baseline, or
    below ``drop_factor`` of it). The z-score alone would flag a jump from 2 to
    9 packets/s on an idle link; the ratio alone would ignore how noisy the link is.
    """

    uses_baseline = True

    def __init__(self, config: DetectorConfig) -> None:
        self.config = config
        self.baseline = GuardedBaseline(
            alpha=config.alpha, warmup=config.warmup, relearn_after=config.relearn_after
        )

    def check(self, w: WindowStats) -> list[Alert]:
        cfg = self.config
        value = w.packets_per_s
        alerts: list[Alert] = []
        anomalous = False
        if self.baseline.ready:
            mean = self.baseline.mean
            z = self.baseline.zscore(value)
            anomalous = abs(z) >= cfg.threshold
            detail = f"{value:.1f} pkt/s vs baseline {mean:.1f} pkt/s (z={z:+.1f})"
            if anomalous and z > 0 and value >= cfg.spike_factor * mean:
                ratio = value / mean if mean > 0 else float("inf")
                severity = Severity.HIGH if ratio >= 10 else Severity.MEDIUM
                alerts.append(
                    Alert(
                        w.start,
                        "traffic_spike",
                        severity,
                        "network",
                        f"traffic spike: {detail}, {ratio:.1f}x normal",
                    )
                )
            elif (
                anomalous
                and z < 0
                and mean >= cfg.min_drop_baseline
                and value <= cfg.drop_factor * mean
            ):
                severity = Severity.HIGH if w.packets == 0 else Severity.MEDIUM
                alerts.append(
                    Alert(w.start, "traffic_drop", severity, "network", f"traffic drop: {detail}")
                )
        self.baseline.learn(value, anomalous)
        return alerts


# Metrics watched by the generic z-score detector, with a display unit.
STAT_METRICS: dict[str, tuple[Callable[[WindowStats], float], str]] = {
    "bytes_per_s": (lambda w: w.bytes_per_s, "B/s"),
    "unique_src": (lambda w: float(w.unique_src), "hosts"),
    "unique_dst": (lambda w: float(w.unique_dst), "hosts"),
}


class StatDetector:
    """Generic EWMA z-score check on each metric in :data:`STAT_METRICS`.

    Each metric has its own baseline, so a bandwidth-heavy backup does not
    make an unusual number of source hosts look normal, and vice versa.
    """

    uses_baseline = True

    def __init__(self, config: DetectorConfig) -> None:
        self.config = config
        self.baselines = {
            name: GuardedBaseline(
                alpha=config.alpha, warmup=config.warmup, relearn_after=config.relearn_after
            )
            for name in STAT_METRICS
        }

    def check(self, w: WindowStats) -> list[Alert]:
        alerts: list[Alert] = []
        threshold = self.config.threshold
        for name, (getter, unit) in STAT_METRICS.items():
            baseline = self.baselines[name]
            value = getter(w)
            anomalous = False
            if baseline.ready:
                z = baseline.zscore(value)
                anomalous = abs(z) >= threshold
                if anomalous:
                    severity = Severity.MEDIUM if abs(z) >= 2 * threshold else Severity.LOW
                    direction = "above" if z > 0 else "below"
                    alerts.append(
                        Alert(
                            w.start,
                            f"{name}_anomaly",
                            severity,
                            "network",
                            f"{name} {_fmt_value(value, unit)} is {abs(z):.1f} std devs "
                            f"{direction} baseline {_fmt_value(baseline.mean, unit)} "
                            f"(threshold {threshold})",
                        )
                    )
            baseline.learn(value, anomalous)
        return alerts


class PortScanDetector:
    """One source probing many distinct ports (vertical scan) or hosts (sweep).

    Only "probe" packets count (see ``PacketRecord.is_probe``), so servers
    replying to many clients do not trigger it.
    """

    uses_baseline = False

    def __init__(self, config: DetectorConfig) -> None:
        self.config = config

    def check(self, w: WindowStats) -> list[Alert]:
        cfg = self.config
        alerts: list[Alert] = []
        for src, ports in w.ports_per_src.items():
            hosts = w.hosts_per_src.get(src, 0)
            if ports < cfg.port_scan_ports and hosts < cfg.port_scan_hosts:
                continue
            if ports >= cfg.port_scan_ports:
                kind = "port scan"
                severity = Severity.HIGH if ports >= 5 * cfg.port_scan_ports else Severity.MEDIUM
                limit = f"threshold {cfg.port_scan_ports} ports"
            else:
                kind = "host sweep"
                severity = Severity.HIGH if hosts >= 5 * cfg.port_scan_hosts else Severity.MEDIUM
                limit = f"threshold {cfg.port_scan_hosts} hosts"
            alerts.append(
                Alert(
                    w.start,
                    "port_scan",
                    severity,
                    src,
                    f"{kind}: {src} probed {ports} distinct ports on {hosts} host(s) "
                    f"in {w.duration:g}s ({limit})",
                )
            )
        return alerts


class SynFloodDetector:
    """Many SYNs to one service, few completed handshakes, SYN-heavy TCP mix.

    In a SYN flood the attacker sends connection requests and never finishes
    them, tying up the server's half-open connection table. So we look at the
    most-SYNed service (``dst:port``) and require: a high SYN rate towards it,
    a low share of completed handshakes for it, and a high share of SYNs in all
    TCP traffic. Requiring a single target is what separates a flood from a
    port scan, which sends one SYN to each of many ports.
    """

    uses_baseline = False

    def __init__(self, config: DetectorConfig) -> None:
        self.config = config

    def check(self, w: WindowStats) -> list[Alert]:
        cfg = self.config
        if not w.syn_by_target:
            return []
        target, syns = max(w.syn_by_target.items(), key=lambda item: item[1])
        rate = syns / w.duration
        completion = w.completed_by_target.get(target, 0) / syns
        if (
            rate < cfg.syn_flood_rate
            or completion > cfg.syn_flood_max_completion
            or w.syn_ratio < cfg.syn_flood_min_ratio
        ):
            return []
        top_src, top_count = max(w.syn_by_src.items(), key=lambda item: item[1])
        if top_count > w.syn_count / 2:
            source = top_src
            origin = f"mostly from {top_src}"
        else:
            source = "distributed"
            origin = f"from {len(w.syn_by_src)} distinct sources (possibly spoofed)"
        return [
            Alert(
                w.start,
                "syn_flood",
                Severity.HIGH,
                source,
                f"SYN flood: {rate:.0f} SYN/s to {target}, {completion:.0%} of handshakes "
                f"completed, SYN ratio {w.syn_ratio:.2f}, {origin}",
                target=target,
            )
        ]


class DetectionEngine:
    """Runs every detector on each window and applies the alert cooldown.

    The cooldown stops a 30-second attack from producing 30 identical alerts:
    an alert with the same (type, source, target) is suppressed until
    ``cooldown`` seconds have passed since it last fired.
    """

    def __init__(self, config: DetectorConfig | None = None) -> None:
        self.config = config or DetectorConfig()
        self.detectors = [
            VolumeDetector(self.config),
            StatDetector(self.config),
            PortScanDetector(self.config),
            SynFloodDetector(self.config),
        ]
        self._last_fired: dict[tuple[str, str, str], float] = {}

    def evaluate(self, w: WindowStats, partial: bool = False) -> list[Alert]:
        """Return new alerts for window ``w``.

        ``partial`` marks a window that was cut short (end of a file, Ctrl-C).
        Its rates are not comparable to full windows, so baseline detectors
        skip it instead of reporting a fake traffic drop.
        """
        alerts: list[Alert] = []
        for detector in self.detectors:
            if partial and detector.uses_baseline:
                continue
            for alert in detector.check(w):
                key = (alert.type, alert.source, alert.target)
                last = self._last_fired.get(key)
                if last is not None and alert.ts - last < self.config.cooldown:
                    continue
                self._last_fired[key] = alert.ts
                alerts.append(alert)
        return alerts
