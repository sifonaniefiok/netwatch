"""Where packets come from: pcap files (offline replay) and live interfaces.

Sources only produce ``PacketRecord`` objects. A ``Feed`` hands records from a
background thread to the main thread through a queue, which is what lets the
curses dashboard keep reacting to key presses while scapy blocks on a socket
or a paced replay sleeps between packets.
"""

from __future__ import annotations

import contextlib
import os
import queue
import socket
import sys
import threading
import time
from collections.abc import Callable, Iterable, Iterator
from pathlib import Path

from scapy.error import Scapy_Exception
from scapy.interfaces import get_if_list
from scapy.packet import Packet
from scapy.sendrecv import AsyncSniffer
from scapy.utils import PcapReader

from netwatch.records import PacketRecord, parse_packet


class CaptureError(Exception):
    """A source could not be opened; the message is meant for the user."""


def read_pcap(path: str | Path) -> Iterator[PacketRecord]:
    """Stream records from a pcap or pcapng file without loading it all into memory.

    The file is opened (and validated) immediately, so a bad path fails here,
    in the caller's thread, rather than later inside a replay thread. scapy's
    ``PcapReader`` detects pcap vs pcapng from the file's magic number.
    """
    path = Path(path)
    if not path.is_file():
        raise CaptureError(f"capture file not found: {path}")
    try:
        reader = PcapReader(str(path))
    except Scapy_Exception as exc:
        raise CaptureError(f"{path} is not a pcap/pcapng file ({exc})") from exc
    return _parse_all(reader)


def _parse_all(reader: PcapReader) -> Iterator[PacketRecord]:
    with reader:
        for pkt in reader:
            rec = parse_packet(pkt)
            if rec is not None:
                yield rec


class PacedReplay:
    """Replays records with their original timing, sped up by ``speed``.

    Iterating sleeps between records so that, at ``speed=1``, a 60 s capture
    takes 60 s. :meth:`now` maps the wall clock back onto capture time, which
    lets the dashboard close windows during quiet periods exactly as it would
    for live traffic.
    """

    def __init__(
        self,
        records: Iterable[PacketRecord],
        speed: float = 1.0,
        sleep: Callable[[float], None] = time.sleep,
        clock: Callable[[], float] = time.monotonic,
    ) -> None:
        if speed <= 0:
            raise ValueError("speed must be positive")
        self.records = records
        self.speed = speed
        self._sleep = sleep
        self._clock = clock
        self._origin: tuple[float, float] | None = None  # (first capture ts, wall clock then)

    def now(self) -> float | None:
        """Current position in capture time, or None before the first record."""
        if self._origin is None:
            return None
        first_ts, started = self._origin
        return first_ts + (self._clock() - started) * self.speed

    def __iter__(self) -> Iterator[PacketRecord]:
        for rec in self.records:
            if self._origin is None:
                self._origin = (rec.ts, self._clock())
            else:
                delay = (rec.ts - self._origin[0]) / self.speed - (self._clock() - self._origin[1])
                if delay > 0:
                    self._sleep(delay)
            yield rec


class Feed:
    """Thread-safe handoff of records from a producer thread to the main loop."""

    def __init__(self) -> None:
        self._queue: queue.Queue[PacketRecord] = queue.Queue()
        self._done = threading.Event()
        self._error: BaseException | None = None

    def put(self, rec: PacketRecord) -> None:
        self._queue.put(rec)

    def close(self, error: BaseException | None = None) -> None:
        """Mark the producer as finished, optionally with the error that stopped it."""
        self._error = error
        self._done.set()

    @property
    def error(self) -> BaseException | None:
        """Why the producer stopped early, if it failed."""
        return self._error

    def producer_done(self) -> bool:
        return self._done.is_set()

    @property
    def finished(self) -> bool:
        """True once the producer is done *and* every record has been taken."""
        return self.producer_done() and self._queue.empty()

    def drain(self, timeout: float = 0.0, limit: int = 10_000) -> list[PacketRecord]:
        """Return up to ``limit`` queued records, waiting up to ``timeout`` for the first.

        The limit keeps one busy tick from starving the UI of redraws.
        """
        items: list[PacketRecord] = []
        try:
            items.append(self._queue.get(timeout=timeout) if timeout else self._queue.get_nowait())
            while len(items) < limit:
                items.append(self._queue.get_nowait())
        except queue.Empty:
            pass
        return items


def feed_from_iterable(records: Iterable[PacketRecord]) -> Feed:
    """Run ``records`` (e.g. a ``PacedReplay``) on a daemon thread, returning its feed."""
    feed = Feed()

    def produce() -> None:
        try:
            for rec in records:
                feed.put(rec)
        except Exception as exc:  # reported to the user by the main loop
            feed.close(exc)
        else:
            feed.close()

    threading.Thread(target=produce, name="netwatch-replay", daemon=True).start()
    return feed


def check_live_capture(iface: str) -> None:
    """Fail early, with a helpful message, if live capture on ``iface`` cannot work.

    Without this, scapy raises its permission error inside the sniffer thread,
    after the dashboard has already started.
    """
    if iface not in get_if_list():
        raise CaptureError(
            f"interface {iface!r} not found; available: {', '.join(sorted(get_if_list()))}"
        )
    if sys.platform.startswith("linux"):
        try:
            socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.htons(0x0003)).close()
        except PermissionError as exc:
            raise CaptureError(
                "live capture needs root or the CAP_NET_RAW capability "
                f"(try: sudo netwatch live -i {iface}); "
                "to try NetWatch without root, run `netwatch demo` and replay a pcap"
            ) from exc
    elif hasattr(os, "geteuid") and os.geteuid() != 0:
        raise CaptureError(f"live capture usually needs root (try: sudo netwatch live -i {iface})")


class LiveCapture(Feed):
    """A feed filled by scapy's ``AsyncSniffer`` sniffing a network interface."""

    def __init__(self, iface: str, bpf: str | None = None) -> None:
        super().__init__()
        self.iface = iface
        self.bpf = bpf
        self._sniffer: AsyncSniffer | None = None

    def _on_packet(self, pkt: Packet) -> None:
        rec = parse_packet(pkt)
        if rec is not None:
            self.put(rec)

    def start(self) -> None:
        check_live_capture(self.iface)
        self._sniffer = AsyncSniffer(
            iface=self.iface, filter=self.bpf, prn=self._on_packet, store=False
        )
        self._sniffer.start()
        # A bad BPF filter or a capture failure surfaces inside the sniffer thread;
        # give it a moment so we can report it instead of showing an empty dashboard.
        time.sleep(0.3)
        if self._sniffer.exception is not None:
            raise CaptureError(f"capture failed on {self.iface}: {self._sniffer.exception}")

    @property
    def error(self) -> BaseException | None:
        if self._sniffer is not None and self._sniffer.exception is not None:
            return self._sniffer.exception
        return super().error

    def producer_done(self) -> bool:
        # The sniffer thread can also die on its own, e.g. if the interface goes away.
        sniffer_dead = self._sniffer is not None and not self._sniffer.thread.is_alive()
        return super().producer_done() or sniffer_dead

    def stop(self) -> None:
        if self._sniffer is not None and self._sniffer.running:
            # stop() re-raises the sniffer thread's own failure. It stays
            # available through `error`, and the caller reports it.
            with contextlib.suppress(Exception):
                self._sniffer.stop()
        self.close()
