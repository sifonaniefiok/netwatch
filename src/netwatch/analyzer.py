"""The pipeline that every mode shares: records -> windows -> detections.

``Analyzer`` is deliberately ignorant of where packets come from (pcap, live
interface, a test's list of records) and of how results are shown (curses,
stdout, JSON). That keeps the CLI, the dashboard and the tests all exercising
exactly the same detection code.
"""

from __future__ import annotations

from collections import Counter
from collections.abc import Iterable, Iterator
from dataclasses import dataclass

from netwatch.detectors import Alert, DetectionEngine, DetectorConfig
from netwatch.features import Windower, WindowStats
from netwatch.records import PacketRecord


@dataclass
class WindowResult:
    """A closed window together with the alerts it produced."""

    stats: WindowStats
    alerts: list[Alert]


class Analyzer:
    """Feeds records through the windower and detection engine, keeping history for reports."""

    def __init__(self, config: DetectorConfig | None = None, window: float = 1.0) -> None:
        self.windower = Windower(window)
        self.engine = DetectionEngine(config)
        self.rows: list[dict[str, float | int | str]] = []  # one row per window, for pandas
        self.alerts: list[Alert] = []
        self.bytes_by_src: Counter[str] = Counter()  # whole-run totals for "top talkers"

    def process(self, rec: PacketRecord) -> list[WindowResult]:
        """Add one packet; return results for any windows it closed."""
        self.bytes_by_src[rec.src] += rec.length
        return self._evaluate(self.windower.add(rec))

    def advance(self, now: float) -> list[WindowResult]:
        """Close windows up to ``now`` even if no packet arrived (live clocks)."""
        return self._evaluate(self.windower.advance(now))

    def flush(self) -> list[WindowResult]:
        """Close the last, possibly incomplete, window at the end of input."""
        return self._evaluate(self.windower.flush(), partial=True)

    def run(self, records: Iterable[PacketRecord]) -> Iterator[WindowResult]:
        """Process a finite stream of records, yielding each window as it closes."""
        for rec in records:
            yield from self.process(rec)
        yield from self.flush()

    def _evaluate(self, windows: list[WindowStats], partial: bool = False) -> list[WindowResult]:
        results = []
        for stats in windows:
            alerts = self.engine.evaluate(stats, partial=partial)
            self.rows.append(stats.to_row())
            self.alerts.extend(alerts)
            results.append(WindowResult(stats, alerts))
        return results
