"""Shared helpers: hand-built records and cached synthetic pcaps."""

from __future__ import annotations

from pathlib import Path

import pytest

from netwatch.records import PacketRecord
from netwatch.synth import START, write_scenario

# Shorter than the CLI defaults to keep the suite fast, but still past the warm-up.
SCENARIO_SECONDS = 30


def rec(
    ts: float,
    src: str = "10.0.0.1",
    dst: str = "10.0.0.2",
    sport: int | None = 40000,
    dport: int | None = 80,
    proto: str = "TCP",
    length: int = 100,
    flags: str = "A",
) -> PacketRecord:
    """Build a PacketRecord with sensible defaults; tests override what they care about."""
    return PacketRecord(ts, src, dst, sport, dport, proto, length, flags)


@pytest.fixture(scope="session")
def scenario_pcap(tmp_path_factory: pytest.TempPathFactory):
    """Return a function mapping a scenario name to a generated pcap path (built once)."""
    cache: dict[str, Path] = {}
    directory = tmp_path_factory.mktemp("pcaps")

    def get(name: str) -> Path:
        if name not in cache:
            path = directory / f"{name}.pcap"
            write_scenario(name, path, duration=SCENARIO_SECONDS)
            cache[name] = path
        return cache[name]

    return get


@pytest.fixture
def start() -> float:
    return START
