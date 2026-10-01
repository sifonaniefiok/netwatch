"""Curses rendering of the dashboard: painting lines and handling keys only.

All decisions about *what* to show live in ``netwatch.dashboard``; this module
just maps style names to colours and runs the event loop.
"""

from __future__ import annotations

import contextlib
import curses
import locale

from netwatch.analyzer import Analyzer
from netwatch.dashboard import DashboardState, build_screen
from netwatch.runner import Clock, pump
from netwatch.sources import Feed

TICK_MS = 250  # how often the screen refreshes and keys are polled


def _init_styles() -> dict[str, int]:
    styles = {
        "normal": curses.A_NORMAL,
        "dim": curses.A_DIM,
        "header": curses.A_REVERSE | curses.A_BOLD,
        "label": curses.A_BOLD,
        "spark": curses.A_NORMAL,
        "low": curses.A_NORMAL,
        "medium": curses.A_BOLD,
        "high": curses.A_BOLD,
    }
    if curses.has_colors():
        curses.start_color()
        curses.use_default_colors()
        for pair, (name, colour) in enumerate(
            (
                ("spark", curses.COLOR_CYAN),
                ("low", curses.COLOR_BLUE),
                ("medium", curses.COLOR_YELLOW),
                ("high", curses.COLOR_RED),
            ),
            start=1,
        ):
            curses.init_pair(pair, colour, -1)
            styles[name] |= curses.color_pair(pair)
    return styles


def render(
    win: curses.window, state: DashboardState, styles: dict[str, int], ascii_only: bool
) -> None:
    """Draw one frame. ``win`` only needs ``getmaxyx``, ``erase``, ``addnstr`` and ``refresh``."""
    height, width = win.getmaxyx()
    win.erase()
    for y, (text, style) in enumerate(build_screen(state, width, height, ascii_only)):
        try:
            win.addnstr(y, 0, text, max(width - 1, 0), styles.get(style, 0))
        except curses.error:
            break  # terminal shrank mid-draw; the next tick redraws at the new size
    win.refresh()


def _loop(
    stdscr: curses.window,
    feed: Feed,
    analyzer: Analyzer,
    state: DashboardState,
    clock: Clock | None,
) -> None:
    with contextlib.suppress(curses.error):  # some terminals cannot hide the cursor
        curses.curs_set(0)
    stdscr.timeout(TICK_MS)
    styles = _init_styles()
    ascii_only = "utf" not in locale.getpreferredencoding(False).lower()
    while True:
        key = stdscr.getch()
        if key in (ord("q"), ord("Q")):
            return
        if key in (ord("p"), ord("P")):
            state.toggle_pause()
        state.update(pump(feed, analyzer, clock))
        if feed.finished:
            state.status = f"error: {feed.error}" if feed.error else "finished"
        # While paused the last frame stays on screen; a key press (or resize)
        # still redraws so the PAUSED marker appears immediately.
        if not state.paused or key != -1:
            render(stdscr, state, styles, ascii_only)


def run_dashboard(
    feed: Feed, analyzer: Analyzer, state: DashboardState, clock: Clock | None = None
) -> None:
    """Run the full-screen dashboard until the user presses q."""
    locale.setlocale(locale.LC_ALL, "")  # lets curses draw the Unicode sparkline
    curses.wrapper(_loop, feed, analyzer, state, clock)
