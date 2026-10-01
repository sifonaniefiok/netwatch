"""Number formatting shared by alerts, reports and the dashboard."""

from __future__ import annotations


def human_bytes(n: float) -> str:
    """Format a byte count with a decimal unit, e.g. ``1.5 MB``."""
    for scale, unit in ((1e9, "GB"), (1e6, "MB"), (1e3, "KB")):
        if n >= scale:
            return f"{n / scale:.1f} {unit}"
    return f"{n:.0f} B"
