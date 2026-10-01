"""Command-line interface: argument parsing and wiring sources to outputs.

Commands:
    netwatch analyze FILE            offline analysis, prints alerts (CI/pipe friendly)
    netwatch replay FILE             replay a capture in the dashboard
    netwatch live -i IFACE           sniff an interface (needs root / CAP_NET_RAW)
    netwatch demo                    write synthetic pcaps to try the above without root
"""

from __future__ import annotations

import argparse
import contextlib
import sys
from collections.abc import Callable, Iterable
from pathlib import Path

from netwatch import __version__
from netwatch.analyzer import Analyzer, WindowResult
from netwatch.dashboard import DashboardState
from netwatch.detectors import Alert, DetectorConfig
from netwatch.records import PacketRecord
from netwatch.report import (
    alert_json,
    format_alert,
    format_summary,
    summarize,
    write_csv,
    write_json,
)
from netwatch.runner import Clock, iter_feed, live_clock
from netwatch.sources import (
    CaptureError,
    Feed,
    LiveCapture,
    PacedReplay,
    feed_from_iterable,
    read_pcap,
)
from netwatch.synth import SCENARIOS, write_scenario


def _positive_float(text: str) -> float:
    value = float(text)
    if value <= 0:
        raise argparse.ArgumentTypeError("must be greater than 0")
    return value


def _fraction(text: str) -> float:
    value = float(text)
    if not 0 < value <= 1:
        raise argparse.ArgumentTypeError("must be in the range (0, 1]")
    return value


def _detection_options() -> argparse.ArgumentParser:
    parent = argparse.ArgumentParser(add_help=False)
    group = parent.add_argument_group("detection")
    defaults = DetectorConfig()
    group.add_argument(
        "--window", type=_positive_float, default=1.0, help="window length in seconds (default: 1)"
    )
    group.add_argument(
        "--threshold",
        type=_positive_float,
        default=defaults.threshold,
        help=f"z-score alert threshold (default: {defaults.threshold})",
    )
    group.add_argument(
        "--warmup",
        type=int,
        default=defaults.warmup,
        help=f"windows to learn before statistical alerts (default: {defaults.warmup})",
    )
    group.add_argument(
        "--alpha",
        type=_fraction,
        default=defaults.alpha,
        help=f"EWMA weight of the newest window, 0-1 (default: {defaults.alpha})",
    )
    group.add_argument(
        "--cooldown",
        type=float,
        default=defaults.cooldown,
        help=f"seconds before a repeated alert fires again (default: {defaults.cooldown:g})",
    )
    group.add_argument(
        "--scan-ports",
        type=int,
        default=defaults.port_scan_ports,
        help="distinct ports per source per window that count as a port scan "
        f"(default: {defaults.port_scan_ports})",
    )
    group.add_argument(
        "--scan-hosts",
        type=int,
        default=defaults.port_scan_hosts,
        help="distinct hosts per source per window that count as a sweep "
        f"(default: {defaults.port_scan_hosts})",
    )
    group.add_argument(
        "--syn-rate",
        type=_positive_float,
        default=defaults.syn_flood_rate,
        help=f"SYN/s to one service before SYN-flood checks (default: {defaults.syn_flood_rate:g})",
    )
    return parent


def _output_options() -> argparse.ArgumentParser:
    parent = argparse.ArgumentParser(add_help=False)
    group = parent.add_argument_group("output")
    group.add_argument("--csv", metavar="PATH", help="write per-window features as CSV")
    group.add_argument("--json", metavar="PATH", help="write summary and alerts as JSON")
    group.add_argument(
        "--jsonl",
        action="store_true",
        help="print alerts as JSON lines instead of text (headless modes)",
    )
    return parent


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="netwatch",
        description="Real-time network traffic analyser with lightweight statistical anomaly "
        "detection and a terminal dashboard.",
    )
    parser.add_argument("--version", action="version", version=f"netwatch {__version__}")
    sub = parser.add_subparsers(dest="command", metavar="COMMAND")
    common = [_detection_options(), _output_options()]

    analyze = sub.add_parser(
        "analyze", parents=common, help="analyse a pcap/pcapng as fast as possible and print alerts"
    )
    analyze.add_argument("file", help="pcap or pcapng file")

    replay = sub.add_parser(
        "replay", parents=common, help="replay a pcap/pcapng in the live dashboard"
    )
    replay.add_argument("file", help="pcap or pcapng file")
    pace = replay.add_mutually_exclusive_group()
    pace.add_argument(
        "--speed",
        type=_positive_float,
        default=1.0,
        help="playback speed multiplier (default: 1 = real time)",
    )
    pace.add_argument("--fast", action="store_true", help="no pacing: process as fast as possible")
    replay.add_argument(
        "--no-ui", action="store_true", help="print alerts instead of the dashboard"
    )

    live = sub.add_parser(
        "live", parents=common, help="capture from a network interface (needs root or CAP_NET_RAW)"
    )
    live.add_argument("-i", "--iface", required=True, help="interface to sniff, e.g. eth0")
    live.add_argument("--bpf", metavar="FILTER", help='BPF capture filter, e.g. "tcp or udp"')
    live.add_argument("--no-ui", action="store_true", help="print alerts instead of the dashboard")

    demo = sub.add_parser("demo", help="write synthetic pcaps (normal traffic and attacks)")
    demo.add_argument(
        "--out",
        default="netwatch-demo",
        help="output directory (default: netwatch-demo)",
    )
    demo.add_argument(
        "--scenario",
        choices=sorted(SCENARIOS),
        action="append",
        help="scenario to write (repeatable; default: all)",
    )
    demo.add_argument("--seed", type=int, default=1, help="random seed (default: 1)")
    return parser


def _make_analyzer(args: argparse.Namespace) -> Analyzer:
    config = DetectorConfig(
        alpha=args.alpha,
        threshold=args.threshold,
        warmup=args.warmup,
        cooldown=args.cooldown,
        port_scan_ports=args.scan_ports,
        port_scan_hosts=args.scan_hosts,
        syn_flood_rate=args.syn_rate,
    )
    return Analyzer(config, window=args.window)


def _alert_printer(args: argparse.Namespace) -> Callable[[Alert], None]:
    fmt = alert_json if args.jsonl else format_alert

    def emit(alert: Alert) -> None:
        print(fmt(alert), flush=True)  # flush so `| grep` and `| jq` see alerts immediately

    return emit


def _print_results(
    results: Iterable[WindowResult], analyzer: Analyzer, args: argparse.Namespace
) -> None:
    """Print alerts as windows close; on Ctrl-C, flush what was collected so far."""
    emit = _alert_printer(args)
    try:
        for result in results:
            for alert in result.alerts:
                emit(alert)
    except KeyboardInterrupt:
        for result in analyzer.flush():
            for alert in result.alerts:
                emit(alert)


def _finish(analyzer: Analyzer, args: argparse.Namespace) -> None:
    """Summary goes to stderr so stdout carries only alerts (clean for pipes)."""
    print(format_summary(summarize(analyzer)), file=sys.stderr)
    if args.csv:
        write_csv(analyzer, args.csv)
        print(f"wrote per-window CSV to {args.csv}", file=sys.stderr)
    if args.json:
        write_json(analyzer, args.json)
        print(f"wrote JSON report to {args.json}", file=sys.stderr)


def _dashboard(
    feed: Feed, analyzer: Analyzer, title: str, window: float, clock: Clock | None
) -> None:
    """Show the dashboard until q (or Ctrl-C), then close the last partial window."""
    # Imported here so headless use never touches curses (absent on some platforms).
    from netwatch.tui import run_dashboard

    with contextlib.suppress(KeyboardInterrupt):
        run_dashboard(feed, analyzer, DashboardState(title=title, window=window), clock)
    analyzer.flush()


def _want_ui(args: argparse.Namespace) -> bool:
    if args.no_ui:
        return False
    if not sys.stdout.isatty():
        print("stdout is not a terminal; running without the dashboard (--no-ui)", file=sys.stderr)
        return False
    return True


def cmd_analyze(args: argparse.Namespace) -> int:
    analyzer = _make_analyzer(args)
    _print_results(analyzer.run(read_pcap(args.file)), analyzer, args)
    _finish(analyzer, args)
    return 0


def cmd_replay(args: argparse.Namespace) -> int:
    analyzer = _make_analyzer(args)
    records = read_pcap(args.file)
    paced = None if args.fast else PacedReplay(records, speed=args.speed)
    source: Iterable[PacketRecord] = records if paced is None else paced
    if _want_ui(args):
        pace = "fast" if paced is None else f"x{args.speed:g}"
        feed = feed_from_iterable(source)
        _dashboard(
            feed,
            analyzer,
            f"replay {Path(args.file).name} ({pace})",
            args.window,
            paced.now if paced else None,
        )
        if feed.error is not None:
            raise CaptureError(f"replay failed: {feed.error}")
    else:
        _print_results(analyzer.run(source), analyzer, args)
    _finish(analyzer, args)
    return 0


def cmd_live(args: argparse.Namespace) -> int:
    analyzer = _make_analyzer(args)
    capture = LiveCapture(args.iface, args.bpf)
    capture.start()
    try:
        if _want_ui(args):
            title = f"live {args.iface}" + (f" (bpf: {args.bpf})" if args.bpf else "")
            _dashboard(capture, analyzer, title, args.window, live_clock)
        else:
            _print_results(iter_feed(capture, analyzer, live_clock), analyzer, args)
    finally:
        capture.stop()
    _finish(analyzer, args)
    if capture.error is not None:
        raise CaptureError(f"capture stopped: {capture.error}")
    return 0


def cmd_demo(args: argparse.Namespace) -> int:
    out = Path(args.out)
    out.mkdir(parents=True, exist_ok=True)
    names = args.scenario or list(SCENARIOS)
    print(f"Writing synthetic captures to {out}/ ...")
    for name in names:
        path = out / f"{name}.pcap"
        count = write_scenario(name, path, seed=args.seed)
        print(f"  {path.name:<14} {count:>7,} packets  {SCENARIOS[name][2]}")
    example = out / ("mixed.pcap" if "mixed" in names else f"{names[0]}.pcap")
    print("\nTry:")
    print(f"  netwatch analyze {example}")
    print(f"  netwatch replay {example} --speed 5")
    return 0


COMMANDS: dict[str, Callable[[argparse.Namespace], int]] = {
    "analyze": cmd_analyze,
    "replay": cmd_replay,
    "live": cmd_live,
    "demo": cmd_demo,
}


def main(argv: list[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)
    if args.command is None:
        parser.print_help()
        return 2
    try:
        return COMMANDS[args.command](args)
    except CaptureError as exc:
        print(f"netwatch: error: {exc}", file=sys.stderr)
        return 1
