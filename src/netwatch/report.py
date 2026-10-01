"""Summaries and exports built with pandas.

By the time a run ends, NetWatch holds one small row per window (not per
packet), so turning that history into a DataFrame is cheap and gives us
percentiles, group-bys and CSV/JSON writers for free.
"""

from __future__ import annotations

import json
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

import pandas as pd

from netwatch.analyzer import Analyzer
from netwatch.detectors import Alert
from netwatch.features import PROTOCOLS
from netwatch.units import human_bytes

ALERT_COLUMNS = ["ts", "type", "severity", "source", "target", "explanation"]
SEVERITY_ORDER = ["high", "medium", "low"]


def iso_time(ts: float) -> str:
    """UTC timestamp like 2026-01-01T00:00:30Z (UTC so output is the same on every machine)."""
    return datetime.fromtimestamp(ts, timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def format_alert(alert: Alert) -> str:
    """One human-readable line per alert, aligned for scanning in a terminal."""
    return (
        f"{iso_time(alert.ts)}  {alert.severity.value.upper():<6}  {alert.type:<20}  "
        f"{alert.source:<15}  {alert.explanation}"
    )


def alert_json(alert: Alert) -> str:
    """One JSON object per line, for piping into jq or a log shipper."""
    data = alert.to_dict()
    data["time"] = iso_time(alert.ts)
    return json.dumps(data)


def windows_frame(analyzer: Analyzer) -> pd.DataFrame:
    """Per-window feature table, one row per window, with a readable UTC ``time`` column."""
    df = pd.DataFrame(analyzer.rows)
    if not df.empty:
        df.insert(0, "time", pd.to_datetime(df["start"], unit="s", utc=True))
    return df


def alerts_frame(alerts: list[Alert]) -> pd.DataFrame:
    return pd.DataFrame([a.to_dict() for a in alerts], columns=ALERT_COLUMNS)


def _rate_stats(series: pd.Series) -> dict[str, float]:
    return {
        "mean": round(float(series.mean()), 2),
        "p95": round(float(series.quantile(0.95)), 2),
        "max": round(float(series.max()), 2),
    }


def summarize(analyzer: Analyzer, top_n: int = 5) -> dict[str, Any]:
    """Whole-run summary as plain Python types (safe to ``json.dump``)."""
    windows = windows_frame(analyzer)
    alerts = alerts_frame(analyzer.alerts)
    talkers = pd.Series(analyzer.bytes_by_src, dtype="int64").nlargest(top_n)
    summary: dict[str, Any] = {
        "window_seconds": analyzer.windower.window,
        "windows": len(windows),
        "packets": 0,
        "bytes": 0,
    }
    if not windows.empty:
        summary.update(
            {
                "start": iso_time(float(windows["start"].min())),
                "end": iso_time(float(windows["start"].max()) + analyzer.windower.window),
                "packets": int(windows["packets"].sum()),
                "bytes": int(windows["bytes"].sum()),
                "packets_per_s": _rate_stats(windows["packets_per_s"]),
                "bytes_per_s": _rate_stats(windows["bytes_per_s"]),
                "protocols": {p: int(windows[p.lower()].sum()) for p in PROTOCOLS},
            }
        )
    summary.update(
        {
            "top_talkers": [{"src": src, "bytes": int(n)} for src, n in talkers.items()],
            "alerts_total": len(alerts),
            "alerts_by_severity": {
                sev: int(n) for sev, n in alerts["severity"].value_counts().items()
            },
            "alerts_by_type": {kind: int(n) for kind, n in alerts["type"].value_counts().items()},
        }
    )
    return summary


def format_summary(summary: dict[str, Any]) -> str:
    """Render :func:`summarize` output as a short plain-text report."""
    lines = ["", "NetWatch summary", "----------------"]
    if not summary["windows"]:
        lines.append("no IP packets seen")
        return "\n".join(lines)
    lines.append(
        f"time      {summary['start']} -> {summary['end']} "
        f"({summary['windows']} windows of {summary['window_seconds']:g}s)"
    )
    lines.append(f"traffic   {summary['packets']:,} packets, {human_bytes(summary['bytes'])}")
    pps, bps = summary["packets_per_s"], summary["bytes_per_s"]
    lines.append(f"pkt/s     mean {pps['mean']:.1f}  p95 {pps['p95']:.1f}  max {pps['max']:.1f}")
    lines.append(
        f"bytes/s   mean {human_bytes(bps['mean'])}  p95 {human_bytes(bps['p95'])}  "
        f"max {human_bytes(bps['max'])}"
    )
    total = summary["packets"] or 1
    mix = "  ".join(f"{p} {n / total:.0%}" for p, n in summary["protocols"].items())
    lines.append(f"protocols {mix}")
    talkers = ", ".join(f"{t['src']} ({human_bytes(t['bytes'])})" for t in summary["top_talkers"])
    lines.append(f"talkers   {talkers}")
    by_sev = summary["alerts_by_severity"]
    sev_text = ", ".join(f"{by_sev[s]} {s}" for s in SEVERITY_ORDER if s in by_sev)
    lines.append(f"alerts    {summary['alerts_total']}" + (f" ({sev_text})" if sev_text else ""))
    for kind, n in summary["alerts_by_type"].items():
        lines.append(f"          {kind}: {n}")
    return "\n".join(lines)


def write_csv(analyzer: Analyzer, path: str | Path) -> None:
    """Per-window features as CSV: easy to plot in a spreadsheet or notebook."""
    windows_frame(analyzer).to_csv(path, index=False)


def write_json(analyzer: Analyzer, path: str | Path) -> None:
    """Run summary plus every alert as one JSON document."""
    alerts = alerts_frame(analyzer.alerts)
    alerts.insert(1, "time", [iso_time(ts) for ts in alerts["ts"]])
    document = {
        "summary": summarize(analyzer),
        "alerts": json.loads(alerts.to_json(orient="records")),
    }
    Path(path).write_text(json.dumps(document, indent=2) + "\n")
