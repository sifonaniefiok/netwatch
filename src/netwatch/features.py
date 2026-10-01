"""Group packet records into fixed time windows and compute per-window features.

Detection never looks at individual packets; it looks at one window at a time
("in this second there were 412 packets from 37 hosts..."). Windows are
aligned to multiples of the window length, so replaying the same pcap always
produces the same windows.

This runs once per packet, so it uses plain counters and sets rather than
pandas: building a DataFrame per packet would be far too slow for live
traffic. pandas is used later, on the (much smaller) table of finished
windows, in ``netwatch.report``.
"""

from __future__ import annotations

import math
from collections import Counter, defaultdict
from dataclasses import dataclass, field

from netwatch.records import PacketRecord

PROTOCOLS = ("TCP", "UDP", "ICMP", "OTHER")

# A flow as seen in a TCP handshake: (src, sport, dst, dport).
_FlowKey = tuple[str, int | None, str, int | None]


@dataclass
class WindowStats:
    """Features of one time window. Counts are totals for the window."""

    start: float
    duration: float
    packets: int = 0
    bytes: int = 0
    unique_src: int = 0
    unique_dst: int = 0
    protocols: dict[str, int] = field(default_factory=dict)
    tcp_packets: int = 0
    syn_count: int = 0
    handshakes_completed: int = 0
    bytes_per_src: dict[str, int] = field(default_factory=dict)
    # Distinct destination ports / hosts each source *probed* (see PacketRecord.is_probe).
    ports_per_src: dict[str, int] = field(default_factory=dict)
    hosts_per_src: dict[str, int] = field(default_factory=dict)
    # SYNs per targeted service "dst:dport", completions for the same keys, SYNs per sender.
    syn_by_target: dict[str, int] = field(default_factory=dict)
    completed_by_target: dict[str, int] = field(default_factory=dict)
    syn_by_src: dict[str, int] = field(default_factory=dict)

    @property
    def packets_per_s(self) -> float:
        return self.packets / self.duration

    @property
    def bytes_per_s(self) -> float:
        return self.bytes / self.duration

    @property
    def syn_ratio(self) -> float:
        """Share of TCP packets that are connection-opening SYNs (0 when there is no TCP)."""
        return self.syn_count / self.tcp_packets if self.tcp_packets else 0.0

    @property
    def completion_ratio(self) -> float:
        """Share of SYNs whose handshake finished in this window (1 when there were no SYNs)."""
        return self.handshakes_completed / self.syn_count if self.syn_count else 1.0

    def top_talkers(self, n: int = 5) -> list[tuple[str, int]]:
        """The ``n`` sources that sent the most bytes, largest first."""
        return Counter(self.bytes_per_src).most_common(n)

    def to_row(self) -> dict[str, float | int | str]:
        """A flat dict (one table row) for CSV/JSON export via pandas."""
        top = self.top_talkers(1)
        row: dict[str, float | int | str] = {
            "start": self.start,
            "packets": self.packets,
            "bytes": self.bytes,
            "packets_per_s": self.packets_per_s,
            "bytes_per_s": self.bytes_per_s,
            "unique_src": self.unique_src,
            "unique_dst": self.unique_dst,
        }
        for proto in PROTOCOLS:
            row[proto.lower()] = self.protocols.get(proto, 0)
        row.update(
            {
                "syn_ratio": round(self.syn_ratio, 4),
                "completion_ratio": round(self.completion_ratio, 4),
                "max_ports_per_src": max(self.ports_per_src.values(), default=0),
                "max_hosts_per_src": max(self.hosts_per_src.values(), default=0),
                "top_talker": top[0][0] if top else "",
            }
        )
        return row


class _Accumulator:
    """Mutable running totals for the window that is currently open."""

    def __init__(self, index: int, duration: float) -> None:
        self.index = index
        self.start = index * duration
        self.duration = duration
        self.packets = 0
        self.bytes = 0
        self.srcs: set[str] = set()
        self.dsts: set[str] = set()
        self.protocols: Counter[str] = Counter()
        self.tcp_packets = 0
        self.syn_count = 0
        self.handshakes_completed = 0
        self.bytes_per_src: Counter[str] = Counter()
        self.ports_per_src: defaultdict[str, set[int]] = defaultdict(set)
        self.hosts_per_src: defaultdict[str, set[str]] = defaultdict(set)
        self.syn_by_target: Counter[str] = Counter()
        self.completed_by_target: Counter[str] = Counter()
        self.syn_by_src: Counter[str] = Counter()
        # Flows that sent a SYN in this window and are waiting for their final ACK.
        # Handshakes split across a window boundary are not matched; at a 1 s window
        # and millisecond handshakes this is a small, accepted undercount.
        self.pending_syns: set[_FlowKey] = set()

    def add(self, rec: PacketRecord) -> None:
        self.packets += 1
        self.bytes += rec.length
        self.srcs.add(rec.src)
        self.dsts.add(rec.dst)
        self.protocols[rec.proto] += 1
        self.bytes_per_src[rec.src] += rec.length

        if rec.proto == "TCP":
            self.tcp_packets += 1
            flow = (rec.src, rec.sport, rec.dst, rec.dport)
            target = f"{rec.dst}:{rec.dport}"
            if rec.is_syn:
                self.syn_count += 1
                self.syn_by_target[target] += 1
                self.syn_by_src[rec.src] += 1
                self.pending_syns.add(flow)
            elif rec.is_handshake_ack and flow in self.pending_syns:
                # The client's final ACK travels in the same direction as its SYN.
                self.pending_syns.discard(flow)
                self.handshakes_completed += 1
                self.completed_by_target[target] += 1

        if rec.is_probe and rec.dport is not None:
            self.ports_per_src[rec.src].add(rec.dport)
            self.hosts_per_src[rec.src].add(rec.dst)

    def finish(self) -> WindowStats:
        return WindowStats(
            start=self.start,
            duration=self.duration,
            packets=self.packets,
            bytes=self.bytes,
            unique_src=len(self.srcs),
            unique_dst=len(self.dsts),
            protocols=dict(self.protocols),
            tcp_packets=self.tcp_packets,
            syn_count=self.syn_count,
            handshakes_completed=self.handshakes_completed,
            bytes_per_src=dict(self.bytes_per_src),
            ports_per_src={src: len(p) for src, p in self.ports_per_src.items()},
            hosts_per_src={src: len(h) for src, h in self.hosts_per_src.items()},
            syn_by_target=dict(self.syn_by_target),
            completed_by_target=dict(self.completed_by_target),
            syn_by_src=dict(self.syn_by_src),
        )


class Windower:
    """Streams records into fixed-length windows and emits each window once it closes.

    A window closes when a record (or a clock tick via :meth:`advance`) arrives
    at or after its end. Windows with no traffic at all are still emitted as
    empty windows, because "nothing happened" is exactly what a traffic-drop
    detector needs to see. A record slightly older than the open window (out of
    order delivery) is counted in the open window rather than dropped.
    """

    def __init__(self, window: float = 1.0) -> None:
        if window <= 0:
            raise ValueError("window length must be positive")
        self.window = window
        self._current: _Accumulator | None = None

    def add(self, rec: PacketRecord) -> list[WindowStats]:
        """Add one record; return any windows that closed because of it."""
        closed = self.advance(rec.ts)
        if self._current is None:
            self._current = _Accumulator(self._index(rec.ts), self.window)
        self._current.add(rec)
        return closed

    def advance(self, now: float) -> list[WindowStats]:
        """Close every window that ends at or before ``now``.

        Afterwards the open window is the one containing ``now``, so a quiet
        period produces one empty window per elapsed window length.
        """
        closed: list[WindowStats] = []
        if self._current is None:
            return closed
        target = self._index(now)
        while self._current.index < target:
            closed.append(self._current.finish())
            self._current = _Accumulator(self._current.index + 1, self.window)
        return closed

    def _index(self, ts: float) -> int:
        # Windows are numbered rather than chained by adding floats, so that
        # boundaries never drift (0.1 + 0.1 + 0.1 != 0.3 in floating point).
        return math.floor(ts / self.window)

    def flush(self) -> list[WindowStats]:
        """Close the open window, e.g. at the end of a pcap file."""
        if self._current is None:
            return []
        last = self._current.finish()
        self._current = None
        return [last]
