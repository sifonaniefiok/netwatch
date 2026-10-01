import json

import pandas as pd
import pytest

from netwatch import __version__
from netwatch.cli import main
from netwatch.synth import SCANNER


def test_analyze_prints_alerts_and_summary(scenario_pcap, capsys):
    assert main(["analyze", str(scenario_pcap("portscan"))]) == 0
    out, err = capsys.readouterr()
    assert "port_scan" in out and SCANNER in out
    assert "NetWatch summary" in err  # summary on stderr keeps stdout pipe-friendly
    assert "NetWatch summary" not in out


def test_analyze_writes_csv_and_json_reports(scenario_pcap, tmp_path, capsys):
    csv_path, json_path = tmp_path / "windows.csv", tmp_path / "report.json"
    code = main(
        [
            "analyze",
            str(scenario_pcap("synflood")),
            "--csv",
            str(csv_path),
            "--json",
            str(json_path),
        ]
    )
    assert code == 0
    windows = pd.read_csv(csv_path)
    assert len(windows) == 30
    assert {"time", "packets_per_s", "syn_ratio", "top_talker"} <= set(windows.columns)
    report = json.loads(json_path.read_text())
    assert report["summary"]["packets"] == int(windows["packets"].sum())
    assert report["summary"]["alerts_by_type"]["syn_flood"] == 1
    assert any(a["type"] == "syn_flood" and a["severity"] == "high" for a in report["alerts"])


def test_jsonl_output_is_one_json_object_per_line(scenario_pcap, capsys):
    main(["analyze", str(scenario_pcap("portscan")), "--jsonl"])
    lines = capsys.readouterr().out.strip().splitlines()
    alerts = [json.loads(line) for line in lines]
    assert {"time", "type", "severity", "source", "explanation"} <= alerts[0].keys()


def test_detection_options_are_applied(scenario_pcap, capsys):
    # With a scan threshold above the scan's 100 ports/s, the port scan goes unreported.
    main(["analyze", str(scenario_pcap("portscan")), "--scan-ports", "500"])
    assert "port_scan" not in capsys.readouterr().out


def test_replay_headless_fast_matches_analyze(scenario_pcap, capsys):
    main(["analyze", str(scenario_pcap("portscan"))])
    analyzed = capsys.readouterr().out
    main(["replay", str(scenario_pcap("portscan")), "--fast", "--no-ui"])
    assert capsys.readouterr().out == analyzed


def test_demo_writes_requested_scenarios(tmp_path, capsys):
    assert main(["demo", "--out", str(tmp_path), "--scenario", "outage"]) == 0
    assert (tmp_path / "outage.pcap").stat().st_size > 0
    assert "netwatch analyze" in capsys.readouterr().out


def test_errors_exit_with_status_1(tmp_path, capsys):
    assert main(["analyze", str(tmp_path / "missing.pcap")]) == 1
    assert main(["live", "-i", "definitely-not-an-iface0", "--no-ui"]) == 1
    err = capsys.readouterr().err
    assert "capture file not found" in err and "not found; available" in err


def test_live_permission_error_is_explained(monkeypatch, capsys):
    import socket

    from netwatch import sources

    def denied(*args, **kwargs):
        raise PermissionError("Operation not permitted")

    monkeypatch.setattr(sources, "get_if_list", lambda: ["eth0"])
    monkeypatch.setattr(sources.sys, "platform", "linux")
    monkeypatch.setattr(socket, "socket", denied)
    assert main(["live", "-i", "eth0", "--no-ui"]) == 1
    assert "needs root or the CAP_NET_RAW" in capsys.readouterr().err


def test_no_command_shows_help_and_version_works(capsys):
    assert main([]) == 2
    assert "analyze" in capsys.readouterr().out
    with pytest.raises(SystemExit):
        main(["--version"])
    assert __version__ in capsys.readouterr().out
