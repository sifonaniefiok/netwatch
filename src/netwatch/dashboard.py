"""The dashboard's model and layout, with no curses code at all.

``DashboardState`` remembers what the screen needs (recent rates, talkers,
alerts). ``build_screen`` turns that state into a list of ``(text, style)``
lines for a given terminal size. Because both are plain Python, tests can
check exactly what the dashboard would show; ``netwatch.tui`` only has to
paint the lines.
"""

from __future__ import annotations

from collections import Counter, deque
from dataclasses import dataclass, field
from datetime import datetime, timezone

from netwatch.analyzer import WindowResult
from netwatch.detectors import Alert, Severity
from netwatch.features import PROTOCOLS
from netwatch.units import human_bytes

SPARK_UNICODE = "▁▂▃▄▅▆▇█"
SPARK_ASCII = "_.-:=+*#"
RECENT_WINDOWS = 10  # protocol mix and top talkers cover this many recent windows

Line = tuple[str, str]  # (text, style name); styles are mapped to colours by the tui


def sparkline(values: list[float], width: int, ascii_only: bool = False) -> str:
    """Draw the last ``width`` values as one row of block characters, scaled to their max."""
    chars = SPARK_ASCII if ascii_only else SPARK_UNICODE
    values = values[-width:] if width > 0 else []
    peak = max(values, default=0)
    if peak <= 0:
        return chars[0] * len(values)
    top = len(chars) - 1
    return "".join(chars[round(v / peak * top)] for v in values)


def bar(fraction: float, width: int, ascii_only: bool = False) -> str:
    """A horizontal bar ``width`` cells wide, filled to ``fraction`` (clamped to 0..1)."""
    fill, empty = ("#", ".") if ascii_only else ("█", "░")
    filled = round(max(0.0, min(1.0, fraction)) * width)
    return fill * filled + empty * (width - filled)


@dataclass
class DashboardState:
    """Everything the dashboard displays, updated one window at a time."""

    title: str
    window: float = 1.0
    history: int = 300
    pps: deque[float] = field(init=False)
    bps: deque[float] = field(init=False)
    recent_talkers: deque[dict[str, int]] = field(init=False)
    recent_protocols: deque[dict[str, int]] = field(init=False)
    alerts: deque[Alert] = field(init=False)
    severity_counts: Counter[str] = field(default_factory=Counter)
    total_packets: int = 0
    total_bytes: int = 0
    windows_seen: int = 0
    paused: bool = False
    status: str = "starting"

    def __post_init__(self) -> None:
        self.pps = deque(maxlen=self.history)
        self.bps = deque(maxlen=self.history)
        self.recent_talkers = deque(maxlen=RECENT_WINDOWS)
        self.recent_protocols = deque(maxlen=RECENT_WINDOWS)
        self.alerts = deque(maxlen=500)

    def update(self, results: list[WindowResult]) -> None:
        """Absorb newly closed windows. This keeps running while paused,
        so no alert is missed; pausing only freezes what is drawn."""
        for result in results:
            stats = result.stats
            self.windows_seen += 1
            self.total_packets += stats.packets
            self.total_bytes += stats.bytes
            self.pps.append(stats.packets_per_s)
            self.bps.append(stats.bytes_per_s)
            self.recent_talkers.append(stats.bytes_per_src)
            self.recent_protocols.append(stats.protocols)
            for alert in result.alerts:
                self.alerts.appendleft(alert)
                self.severity_counts[alert.severity.value] += 1
            if self.status == "starting":
                self.status = "running"

    def toggle_pause(self) -> None:
        self.paused = not self.paused

    def top_talkers(self, n: int = 5) -> list[tuple[str, int]]:
        total: Counter[str] = Counter()
        for window in self.recent_talkers:
            total.update(window)
        return total.most_common(n)

    def protocol_mix(self) -> list[tuple[str, int, float]]:
        """(protocol, packets, share) over the recent windows, in a fixed order."""
        total: Counter[str] = Counter()
        for window in self.recent_protocols:
            total.update(window)
        packets = sum(total.values())
        return [(p, total[p], total[p] / packets if packets else 0.0) for p in PROTOCOLS]


_ALERT_STYLE = {Severity.HIGH: "high", Severity.MEDIUM: "medium", Severity.LOW: "low"}


def _clock(ts: float) -> str:
    return datetime.fromtimestamp(ts, timezone.utc).strftime("%H:%M:%S")


def build_screen(
    state: DashboardState, width: int, height: int, ascii_only: bool = False
) -> list[Line]:
    """Lay out the dashboard for a ``width`` x ``height`` terminal.

    Fixed sections come first; the alert log gets whatever rows remain.
    Every line is cut to ``width - 1`` characters because curses raises an
    error when writing into the bottom-right cell.
    """
    inner = max(width - 1, 0)
    lines: list[Line] = []

    def add(text: str, style: str = "normal") -> None:
        lines.append((text[:inner], style))

    status = "PAUSED" if state.paused else state.status.upper()
    add(f" NetWatch | {state.title} | window {state.window:g}s | {status}", "header")
    add(" q quit   p pause/resume (analysis continues while paused)", "dim")

    pps = list(state.pps)
    bps = list(state.bps)
    now_pps = pps[-1] if pps else 0.0
    now_bps = bps[-1] if bps else 0.0
    add("")
    add(
        f" Packets/s  now {now_pps:8.1f}   avg {sum(pps) / len(pps) if pps else 0:8.1f}"
        f"   peak {max(pps, default=0):8.1f}",
        "label",
    )
    add(" " + sparkline(pps, inner - 2, ascii_only), "spark")
    add(
        f" Bytes/s    now {human_bytes(now_bps):>10}   peak {human_bytes(max(bps, default=0)):>10}",
        "label",
    )
    add(" " + sparkline(bps, inner - 2, ascii_only), "spark")
    sev = state.severity_counts
    add(
        f" Totals     {state.total_packets:,} packets, {human_bytes(state.total_bytes)}, "
        f"{state.windows_seen} windows | alerts: {sev['high']} high, {sev['medium']} medium, "
        f"{sev['low']} low"
    )

    add("")
    add(f" Protocols (last {RECENT_WINDOWS} windows)", "label")
    for proto, count, share in state.protocol_mix():
        add(f"   {proto:<6}{bar(share, 24, ascii_only)} {share:6.1%}  {count:>8,} pkts")

    add("")
    add(f" Top talkers by bytes (last {RECENT_WINDOWS} windows)", "label")
    talkers = state.top_talkers()
    biggest = talkers[0][1] if talkers else 1
    for src, sent in talkers:
        add(f"   {src:<39} {bar(sent / biggest, 16, ascii_only)} {human_bytes(sent):>10}")
    if not talkers:
        add("   (no traffic yet)", "dim")

    add("")
    add(" Alerts (newest first)", "label")
    room = height - len(lines)
    if not state.alerts:
        add("   none so far", "dim")
    for alert in list(state.alerts)[: max(room, 0)]:
        add(
            f"   {_clock(alert.ts)} {alert.severity.value.upper():<6} {alert.type:<20} "
            f"{alert.explanation}",
            _ALERT_STYLE[alert.severity],
        )
    return lines[:height]
