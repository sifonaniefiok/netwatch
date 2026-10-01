"""Main-loop glue between a background ``Feed`` and the ``Analyzer``.

Used by both the curses dashboard and the headless live mode, so the two
behave identically apart from how results are displayed.
"""

from __future__ import annotations

import time
from collections.abc import Callable, Iterator

from netwatch.analyzer import Analyzer, WindowResult
from netwatch.sources import Feed

Clock = Callable[[], float | None]

# Live windows close this long after their end, so packets still queued in the
# sniffer thread are counted in the window they belong to.
LIVE_GRACE_SECONDS = 0.25


def live_clock() -> float:
    return time.time() - LIVE_GRACE_SECONDS


def pump(
    feed: Feed, analyzer: Analyzer, clock: Clock | None = None, timeout: float = 0.0
) -> list[WindowResult]:
    """Process whatever the feed has queued and return the windows that closed.

    ``clock`` (live time or paced-replay time) closes windows during silence,
    so an outage shows up as empty windows instead of no windows at all. Once
    the feed is finished, the last partial window is flushed; calling again
    after that is harmless and returns nothing.
    """
    results: list[WindowResult] = []
    for rec in feed.drain(timeout):
        results.extend(analyzer.process(rec))
    if feed.finished:
        results.extend(analyzer.flush())
    elif clock is not None:
        now = clock()
        if now is not None:
            results.extend(analyzer.advance(now))
    return results


def iter_feed(feed: Feed, analyzer: Analyzer, clock: Clock | None = None) -> Iterator[WindowResult]:
    """Yield window results until the feed is finished (blocking, for headless modes)."""
    while True:
        yield from pump(feed, analyzer, clock, timeout=0.25)
        if feed.finished:
            return
