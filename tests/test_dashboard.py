"""The dashboard model, layout and runner loop, tested without a real terminal."""

from netwatch.analyzer import Analyzer, WindowResult
from netwatch.dashboard import DashboardState, bar, build_screen, sparkline
from netwatch.detectors import Alert, Severity
from netwatch.features import WindowStats
from netwatch.runner import pump
from netwatch.sources import Feed, PacedReplay, feed_from_iterable
from tests.conftest import rec


def result(start: float, packets: int, alerts=()) -> WindowResult:
    stats = WindowStats(
        start=start,
        duration=1.0,
        packets=packets,
        bytes=packets * 100,
        protocols={"TCP": packets},
        bytes_per_src={"10.0.0.1": packets * 100},
    )
    return WindowResult(stats, list(alerts))


def test_sparkline_scales_to_peak_and_width():
    assert sparkline([0, 5, 10], 10) == "▁▅█"
    assert sparkline(list(range(100)), 8) == sparkline(list(range(92, 100)), 8)
    assert len(sparkline(list(range(100)), 8)) == 8
    assert sparkline([0, 0], 5) == "▁▁"
    assert set(sparkline([1, 2, 3], 5, ascii_only=True)) <= set("_.-:=+*#")


def test_bar_is_clamped():
    assert bar(0.5, 10) == "█████░░░░░"
    assert bar(2.0, 4, ascii_only=True) == "####"
    assert bar(-1.0, 3, ascii_only=True) == "..."


def test_state_tracks_totals_talkers_protocols_and_alerts():
    state = DashboardState(title="test")
    alert = Alert(1.0, "port_scan", Severity.HIGH, "6.6.6.6", "port scan: boom")
    state.update([result(0, 10), result(1, 30, [alert])])
    assert state.total_packets == 40 and state.windows_seen == 2
    assert list(state.pps) == [10, 30]
    assert state.top_talkers() == [("10.0.0.1", 4000)]
    assert state.protocol_mix()[0] == ("TCP", 40, 1.0)
    assert state.alerts[0] is alert and state.severity_counts["high"] == 1
    assert state.status == "running"


def test_build_screen_respects_terminal_size():
    state = DashboardState(title="replay demo.pcap")
    alerts = [Alert(i, "port_scan", Severity.MEDIUM, "x", "port scan " * 30) for i in range(50)]
    state.update([result(i, 50 + i, alerts if i == 5 else ()) for i in range(40)])
    for width, height in [(120, 40), (60, 15), (20, 5)]:
        lines = build_screen(state, width, height)
        assert len(lines) <= height
        assert all(len(text) <= width - 1 for text, _ in lines)
    text = "\n".join(t for t, _ in build_screen(state, 120, 60))
    assert "replay demo.pcap" in text and "Packets/s" in text and "Top talkers" in text
    assert "port_scan" in text


def test_pause_is_shown_in_header():
    state = DashboardState(title="t")
    state.toggle_pause()
    assert "PAUSED" in build_screen(state, 80, 24)[0][0]


class FakeWindow:
    """Just enough of a curses window for render()."""

    def __init__(self, height: int, width: int) -> None:
        self.size = (height, width)
        self.rows: dict[int, str] = {}
        self.refreshed = False

    def getmaxyx(self):
        return self.size

    def erase(self):
        self.rows.clear()

    def addnstr(self, y, x, text, n, attr=0):
        self.rows[y] = text[:n]

    def refresh(self):
        self.refreshed = True


def test_render_paints_layout_on_a_window():
    from netwatch.tui import render

    state = DashboardState(title="fake")
    state.update([result(0, 5)])
    win = FakeWindow(30, 100)
    render(win, state, styles={}, ascii_only=True)
    assert win.refreshed and "NetWatch" in win.rows[0]
    assert len(win.rows) == len(build_screen(state, 100, 30, ascii_only=True))


def test_pump_processes_feed_and_flushes_at_end():
    feed = Feed()
    analyzer = Analyzer()
    for t in (0.1, 0.2, 1.5):
        feed.put(rec(t))
    assert [r.stats.packets for r in pump(feed, analyzer)] == [2]  # window 0 closed
    feed.close()
    assert [r.stats.packets for r in pump(feed, analyzer)] == [1]  # final partial window
    assert pump(feed, analyzer) == []


def test_pump_uses_clock_to_close_quiet_windows():
    feed = Feed()
    analyzer = Analyzer()
    feed.put(rec(10.2))
    pump(feed, analyzer)
    results = pump(feed, analyzer, clock=lambda: 13.0)
    assert [r.stats.packets for r in results] == [1, 0, 0]


def test_feed_from_iterable_delivers_everything():
    feed = feed_from_iterable(rec(t) for t in range(5))
    got = []
    while not feed.finished:
        got.extend(feed.drain(timeout=0.1))
    assert [r.ts for r in got] == [0, 1, 2, 3, 4] and feed.error is None


def test_paced_replay_sleeps_by_capture_time_over_speed():
    now = [100.0]
    sleeps = []

    def fake_sleep(seconds):
        sleeps.append(seconds)
        now[0] += seconds

    replay = PacedReplay(
        [rec(50.0), rec(52.0), rec(56.0)], speed=2.0, sleep=fake_sleep, clock=lambda: now[0]
    )
    assert replay.now() is None
    assert [r.ts for r in replay] == [50.0, 52.0, 56.0]
    assert sleeps == [1.0, 2.0]
    assert replay.now() == 56.0
