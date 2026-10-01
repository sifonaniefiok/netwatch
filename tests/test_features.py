import pandas as pd
import pytest

from netwatch.features import Windower
from tests.conftest import rec


def collect(windower: Windower, records) -> list:
    windows = []
    for r in records:
        windows.extend(windower.add(r))
    return windows + windower.flush()


def test_basic_window_counts_and_rates():
    w = Windower(window=2.0)
    records = [
        rec(10.0, src="a", dst="x", length=100),
        rec(10.5, src="b", dst="x", length=300, proto="UDP", flags="", sport=5000, dport=53),
        rec(11.9, src="a", dst="y", length=600, proto="ICMP", flags="", sport=None, dport=None),
    ]
    [stats] = collect(w, records)
    assert stats.start == 10.0 and stats.duration == 2.0
    assert (stats.packets, stats.bytes) == (3, 1000)
    assert stats.packets_per_s == 1.5 and stats.bytes_per_s == 500
    assert (stats.unique_src, stats.unique_dst) == (2, 2)
    assert stats.protocols == {"TCP": 1, "UDP": 1, "ICMP": 1}
    assert stats.top_talkers() == [("a", 700), ("b", 300)]


def test_windows_are_aligned_and_gaps_produce_empty_windows():
    w = Windower(window=1.0)
    windows = collect(w, [rec(100.2), rec(100.7), rec(103.1)])
    assert [x.start for x in windows] == [100.0, 101.0, 102.0, 103.0]
    assert [x.packets for x in windows] == [2, 0, 0, 1]


def test_advance_closes_windows_without_new_packets():
    w = Windower(window=1.0)
    assert w.add(rec(5.5)) == []
    closed = w.advance(7.2)
    assert [x.start for x in closed] == [5.0, 6.0]
    assert [x.packets for x in closed] == [1, 0]
    assert w.advance(7.9) == []  # still inside window 7


def test_fractional_windows_do_not_drift():
    w = Windower(window=0.1)
    windows = collect(w, [rec(i * 0.1 + 0.05) for i in range(50)])
    assert len(windows) == 50
    assert all(x.packets == 1 for x in windows)


def test_window_must_be_positive():
    with pytest.raises(ValueError):
        Windower(window=0)


def test_syn_ratio_and_handshake_completion():
    w = Windower()
    handshake = [
        rec(0.1, "c", "s", 40000, 80, flags="S"),
        rec(0.11, "s", "c", 80, 40000, flags="SA"),
        rec(0.12, "c", "s", 40000, 80, flags="A"),
    ]
    half_open = [rec(0.2 + i / 100, f"evil{i}", "s", 1000 + i, 80, flags="S") for i in range(3)]
    [stats] = collect(w, handshake + half_open)
    assert stats.tcp_packets == 6
    assert stats.syn_count == 4
    assert stats.handshakes_completed == 1
    assert stats.syn_ratio == pytest.approx(4 / 6)
    assert stats.completion_ratio == pytest.approx(1 / 4)
    assert stats.syn_by_target == {"s:80": 4}
    assert stats.completed_by_target == {"s:80": 1}


def test_unique_ports_per_source_counts_only_probes():
    w = Windower()
    scan = [rec(0.01 * p, "scanner", "victim", 5555, p, flags="S") for p in range(1, 31)]
    # A server replying to 30 clients hits 30 ephemeral ports, but these are replies.
    replies = [rec(0.5, "server", f"client{i}", 443, 50000 + i, flags="PA") for i in range(30)]
    [stats] = collect(w, scan + replies)
    assert stats.ports_per_src == {"scanner": 30}
    assert stats.hosts_per_src == {"scanner": 1}
    assert "server" not in stats.ports_per_src


def test_streaming_windows_match_pandas_groupby():
    """Cross-check the hand-written streaming code against a pandas aggregation."""
    records = [
        rec(t / 7, src=f"h{t % 5}", dst=f"d{t % 3}", length=60 + t) for t in range(0, 200, 3)
    ]
    windows = collect(Windower(window=2.0), records)

    df = pd.DataFrame(
        [{"ts": r.ts, "src": r.src, "dst": r.dst, "length": r.length} for r in records]
    )
    df["window"] = (df["ts"] // 2.0) * 2.0
    expected = df.groupby("window").agg(
        packets=("length", "size"),
        bytes=("length", "sum"),
        unique_src=("src", "nunique"),
        unique_dst=("dst", "nunique"),
    )
    got = pd.DataFrame([x.to_row() for x in windows]).set_index("start")
    for column in expected.columns:
        assert got[column].tolist() == expected[column].tolist()


def test_to_row_is_flat_and_complete():
    [stats] = collect(Windower(), [rec(0.5, flags="S")])
    row = stats.to_row()
    assert {
        "start",
        "packets",
        "bytes",
        "tcp",
        "udp",
        "icmp",
        "other",
        "syn_ratio",
        "max_ports_per_src",
        "top_talker",
    } <= row.keys()
    assert all(isinstance(v, (int, float, str)) for v in row.values())
