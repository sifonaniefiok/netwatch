# NetWatch

[![CI](https://github.com/sifonaniefiok/netwatch/actions/workflows/ci.yml/badge.svg)](https://github.com/sifonaniefiok/netwatch/actions/workflows/ci.yml)

A real-time network traffic analyser that detects anomalies using lightweight statistical
models and visualises packet flow in the terminal.

NetWatch reads packets from a live interface or a pcap/pcapng file, groups them into
fixed time windows (1 second by default), computes per-window features, and runs two
kinds of detectors over them:

- **Statistical**: an EWMA baseline per metric with z-score thresholds. It learns what
  "normal" looks like and flags windows that are far from it.
- **Rules**: port scans and host sweeps, SYN floods, and traffic spikes and drops. Each
  rule describes one known attack pattern.

Results appear in a curses dashboard with sparklines, protocol mix, top talkers and an
alert log. A headless mode prints alerts as text or JSON lines and writes CSV/JSON
reports, so the same analysis also works in CI and shell pipelines.

Built with Python, [Scapy](https://scapy.net/) (capture and parsing),
[pandas](https://pandas.pydata.org/) (reports) and curses (dashboard).

## Demo

You don't need root or a real network to try it. `netwatch demo` writes synthetic
captures: normal LAN traffic, plus versions with an attack in the middle.

```console
$ netwatch demo
Writing synthetic captures to netwatch-demo/ ...
  normal.pcap      4,022 packets  background LAN traffic only; should raise no alerts
  portscan.pcap    5,225 packets  192.168.1.66 SYN-scans 600 ports on 192.168.1.20
  synflood.pcap    7,047 packets  spoofed SYN flood against 10.0.0.5:80 (400 SYN/s)
  spike.pcap       9,425 packets  a 6 s bulk download at ~15x the normal packet rate
  outage.pcap      3,568 packets  all traffic stops for 6 s
  mixed.pcap      19,469 packets  port scan, SYN flood, spike and outage, one after another

Try:
  netwatch analyze netwatch-demo/mixed.pcap
  netwatch replay netwatch-demo/mixed.pcap --speed 5
```

Running `analyze` on the mixed capture (real output, unedited). Alerts go to stdout and
the summary goes to stderr:

```console
$ netwatch analyze netwatch-demo/mixed.pcap --csv windows.csv --json report.json
2026-01-01T00:00:30Z  MEDIUM  traffic_spike         network          traffic spike: 287.0 pkt/s vs baseline 66.6 pkt/s (z=+15.1), 4.3x normal
2026-01-01T00:00:30Z  HIGH    port_scan             192.168.1.66     port scan: 192.168.1.66 probed 100 distinct ports on 1 host(s) in 1s (threshold 20 ports)
2026-01-01T00:01:00Z  MEDIUM  traffic_spike         network          traffic spike: 599.0 pkt/s vs baseline 71.4 pkt/s (z=+30.7), 8.4x normal
2026-01-01T00:01:00Z  LOW     bytes_per_s_anomaly   network          bytes_per_s 60.5 KB/s is 5.2 std devs above baseline 23.3 KB/s (threshold 4.0)
2026-01-01T00:01:00Z  MEDIUM  unique_src_anomaly    network          unique_src 414.0 hosts is 249.1 std devs above baseline 11.7 hosts (threshold 4.0)
2026-01-01T00:01:00Z  MEDIUM  unique_dst_anomaly    network          unique_dst 114.0 hosts is 63.3 std devs above baseline 11.7 hosts (threshold 4.0)
2026-01-01T00:01:00Z  HIGH    syn_flood             distributed      SYN flood: 401 SYN/s to 10.0.0.5:80, 0% of handshakes completed, SYN ratio 0.70, from 404 distinct sources (possibly spoofed)
2026-01-01T00:01:30Z  HIGH    traffic_spike         network          traffic spike: 976.0 pkt/s vs baseline 66.4 pkt/s (z=+69.2), 14.7x normal
2026-01-01T00:01:30Z  MEDIUM  bytes_per_s_anomaly   network          bytes_per_s 900.7 KB/s is 117.7 std devs above baseline 23.6 KB/s (threshold 4.0)
2026-01-01T00:02:00Z  HIGH    traffic_drop          network          traffic drop: 0.0 pkt/s vs baseline 73.0 pkt/s (z=-4.9)
2026-01-01T00:02:00Z  LOW     unique_src_anomaly    network          unique_src 0.0 hosts is 5.7 std devs below baseline 12.6 hosts (threshold 4.0)
2026-01-01T00:02:00Z  LOW     unique_dst_anomaly    network          unique_dst 0.0 hosts is 5.7 std devs below baseline 12.6 hosts (threshold 4.0)

NetWatch summary
----------------
time      2026-01-01T00:00:00Z -> 2026-01-01T00:02:30Z (150 windows of 1s)
traffic   19,469 packets, 8.7 MB
pkt/s     mean 129.8  p95 564.1  max 997.0
bytes/s   mean 58.2 KB  p95 45.7 KB  max 922.7 KB
protocols TCP 92%  UDP 8%  ICMP 1%  OTHER 0%
talkers   10.0.0.3 (5.8 MB), 10.0.0.2 (530.7 KB), 10.0.0.4 (507.9 KB), 10.0.0.5 (483.3 KB), 10.0.0.6 (479.0 KB)
alerts    12 (4 high, 5 medium, 3 low)
          traffic_spike: 3
          bytes_per_s_anomaly: 2
          unique_src_anomaly: 2
          unique_dst_anomaly: 2
          port_scan: 1
          syn_flood: 1
          traffic_drop: 1
wrote per-window CSV to windows.csv
wrote JSON report to report.json
```

Each of the four injected events is caught in the window where it starts. Every attack
also triggers related statistical alerts: a spoofed SYN flood really does bring in 400
"new" source hosts in one second. The cooldown stops a 6-second attack from repeating
the same alert six times. The `normal.pcap` capture raises no alerts.

The dashboard (`netwatch replay netwatch-demo/mixed.pcap --speed 5`) is shown below. This
frame was produced by the same layout function the curses UI paints, captured just after
the SYN flood. In a terminal, alerts are coloured by severity:

```text
 NetWatch | replay mixed.pcap (x5) | window 1s | RUNNING
 q quit   p pause/resume (analysis continues while paused)

 Packets/s  now    570.0   avg    130.4   peak    599.0
 ▂▂▂▂▂▂▂▂▂▂▂▂▂▂▂▂▂▂▂▂▂▂▂▂▂▂▂▂▂▂▄▄▄▄▄▄▂▂▂▁▂▂▂▂▂▂▂▂▂▂▂▂▂▂▂▂▂▂▂▂███▇▇█
 Bytes/s    now    43.4 KB   peak    60.5 KB
 ▄▃▃▄▃▃▅▄▃▃▄▃▃▅▄▃▃▃▄▄▂▃▃▄▃▅▄▄▃▃▅▄▃▅▆▅▂▄▄▂▄▄▃▄▄▃▃▃▄▃▄▃▄▃▂▄▄▃▄▅█▆▆▆▆▆
 Totals     8,609 packets, 1.6 MB, 66 windows | alerts: 2 high, 4 medium, 1 low

 Protocols (last 10 windows)
   TCP   ███████████████████████░  96.6%     3,590 pkts
   UDP   █░░░░░░░░░░░░░░░░░░░░░░░   3.2%       118 pkts
   ICMP  ░░░░░░░░░░░░░░░░░░░░░░░░   0.2%         8 pkts
   OTHER ░░░░░░░░░░░░░░░░░░░░░░░░   0.0%         0 pkts

 Top talkers by bytes (last 10 windows)
   10.0.0.5                                ████████████████    69.6 KB
   10.0.0.6                                ████████████░░░░    52.5 KB
   10.0.0.3                                █████████░░░░░░░    39.8 KB
   10.0.0.2                                ██████░░░░░░░░░░    24.6 KB
   10.0.0.4                                █████░░░░░░░░░░░    20.3 KB

 Alerts (newest first)
   00:01:00 HIGH   syn_flood            SYN flood: 401 SYN/s to 10.0.0.5:80, 0% of handshakes compl
   00:01:00 MEDIUM unique_dst_anomaly   unique_dst 114.0 hosts is 63.3 std devs above baseline 11.7
   00:01:00 MEDIUM unique_src_anomaly   unique_src 414.0 hosts is 249.1 std devs above baseline 11.
   00:01:00 LOW    bytes_per_s_anomaly  bytes_per_s 60.5 KB/s is 5.2 std devs above baseline 23.3 K
   00:01:00 MEDIUM traffic_spike        traffic spike: 599.0 pkt/s vs baseline 71.4 pkt/s (z=+30.7)
   00:00:30 HIGH   port_scan            port scan: 192.168.1.66 probed 100 distinct ports on 1 host
   00:00:30 MEDIUM traffic_spike        traffic spike: 287.0 pkt/s vs baseline 66.6 pkt/s (z=+15.1)
```

## Install

Requires Python 3.10+.

```bash
git clone https://github.com/sifonaniefiok/netwatch.git
cd netwatch
pip install .            # or: pip install -e ".[dev]" for development
```

This installs the `netwatch` command (`python -m netwatch` also works). Live capture
needs root or the `CAP_NET_RAW` capability. Offline analysis needs neither. `--bpf`
filters are compiled by scapy using libpcap/tcpdump, so one of them must be installed.

## Usage

### `netwatch analyze FILE`: offline analysis (CI and pipe friendly)

Reads a pcap or pcapng file as fast as possible. Alerts go to stdout, one per line, and
the summary goes to stderr.

```bash
netwatch analyze capture.pcap
netwatch analyze capture.pcap --csv windows.csv --json report.json
netwatch analyze capture.pcap --jsonl | jq 'select(.severity == "high")'
```

- `--csv PATH`: one row per window with every feature (packets/s, bytes/s, unique
  hosts, protocol counts, SYN ratio, handshake completion, max ports per source, top
  talker). It is ready to plot.
- `--json PATH`: the run summary (totals, rate statistics, protocol mix, top talkers,
  alert counts) plus every alert.
- `--jsonl`: print alerts as JSON lines instead of text.

### `netwatch replay FILE`: replay a capture in the dashboard

```bash
netwatch replay capture.pcap              # original timing
netwatch replay capture.pcap --speed 10   # 10x faster
netwatch replay capture.pcap --fast       # no pacing at all
netwatch replay capture.pcap --no-ui      # print alerts instead of the dashboard
```

### `netwatch live -i IFACE`: live capture

```bash
sudo netwatch live -i eth0
sudo netwatch live -i eth0 --bpf "tcp or udp"
sudo netwatch live -i eth0 --no-ui --jsonl >> alerts.jsonl
```

Without the needed privileges, NetWatch exits with a clear message before it starts.
The same happens for an unknown interface, for which it lists the available ones.

### `netwatch demo`: synthetic captures

```bash
netwatch demo                                  # all scenarios into ./netwatch-demo
netwatch demo --out /tmp/demo --scenario synflood --scenario outage --seed 7
```

### Dashboard keys

| Key | Action |
| --- | --- |
| `q` | quit (the summary and any `--csv`/`--json` reports are written on exit) |
| `p` | pause/resume the display. Analysis keeps running while paused, so no alert is missed. |

If stdout is not a terminal, `replay` and `live` switch to `--no-ui` automatically.

### Detection options (all commands except `demo`)

| Option | Default | Meaning |
| --- | --- | --- |
| `--window` | 1 | window length in seconds |
| `--threshold` | 4.0 | \|z\| at or above this is anomalous |
| `--warmup` | 10 | windows to learn before statistical alerts are allowed |
| `--alpha` | 0.1 | EWMA weight of the newest window |
| `--cooldown` | 10 | seconds before an identical alert may fire again |
| `--scan-ports` | 20 | distinct ports one source may probe per window |
| `--scan-hosts` | 20 | distinct hosts one source may probe per window |
| `--syn-rate` | 50 | SYN/s towards one service before SYN-flood checks apply |

## How detection works

### Features per window

Each window gets the following counts: packets and bytes (and their per-second rates),
unique source and destination IPs, protocol mix (TCP/UDP/ICMP/other), bytes per source
(top talkers), and TCP SYNs with how many of them completed a handshake. It also counts
the distinct destination ports and hosts that each source *probed*.

A packet counts as a probe only if it opens or probes a connection. That means TCP
without the ACK flag (SYN, FIN, NULL and XMAS scans), or UDP sent from a higher port to
a lower one. Without this rule, a web server replying to 50 clients would look like it
"touched" 50 ports, because replies go to the clients' random high ports.

### EWMA baseline and z-scores

For each watched metric, NetWatch keeps an exponentially weighted moving average (EWMA)
of its mean and variance. When a new window value `x` arrives:

```
diff = x - mean
mean = mean + alpha * diff
var  = (1 - alpha) * (var + alpha * diff²)
```

With `alpha = 0.1`, each window moves the baseline 10% of the way towards the new value.
Recent windows count most, and older ones fade away geometrically. This takes three
numbers of memory per metric and O(1) work per window.

How unusual a window is comes from its **z-score**: the distance from the mean, measured
in standard deviations:

```
z = (x - mean) / std
```

`|z| >= 4` (configurable) is anomalous. Four details make this usable in practice:

1. **Warm-up.** No statistical alerts fire during the first 10 windows, while the
   baseline is still mostly noise.
2. **Warm start.** For the first `1/alpha` samples the weight is `1/n` instead of
   `alpha`, which makes the early estimate a plain average. Otherwise the very first value
   would dominate.
3. **No pollution.** Anomalous windows are *not* learned from, so a long attack cannot
   slowly drag the baseline up until the attack looks normal. If 30 windows in a row are
   anomalous, NetWatch treats it as a new normal and starts learning again, so it does
   not alert forever after a lasting change.
4. **Standard deviation floor.** Perfectly steady traffic has a variance near zero, which
   would make a tiny wobble look infinitely surprising. The std used is at least 1 and at
   least 10% of the mean.

The z-score detector watches `bytes_per_s`, `unique_src` and `unique_dst`, each with
its own baseline. Its alerts are named after the metric, for example
`unique_src_anomaly`. Severity is `low`, or `medium` when |z| is at least twice the
threshold.

### Rules

| Alert | Fires when | Why it is built this way |
| --- | --- | --- |
| `traffic_spike` | packets/s has z ≥ threshold **and** is ≥ 3x the baseline | Both conditions must hold. The z-score alone would flag 2 → 9 pkt/s on an idle link, and the ratio alone would ignore how noisy a link is. High severity at ≥ 10x. |
| `traffic_drop` | packets/s has z ≤ -threshold **and** is ≤ 25% of the baseline, with a baseline of ≥ 5 pkt/s | Catches outages and dead links. Nearly idle links are not judged. High severity when traffic stops completely. |
| `port_scan` | one source probes ≥ 20 distinct ports (port scan) or ≥ 20 distinct hosts (host sweep) in one window | Uses probe packets only, see above. High severity at 5x the threshold. |
| `syn_flood` | the most-SYNed service (`dst:port`) gets ≥ 50 SYN/s, **and** ≤ 20% of those handshakes complete, **and** ≥ 50% of all TCP packets are SYNs | Requiring a single target separates a flood from a port scan, which sends one SYN to each of many ports. The alert names the attacker if one host sent most SYNs, otherwise it reports `distributed` with the number of sources. |

Two engine-level rules apply as well:

- **Cooldown.** An alert with the same type, source and target is suppressed for 10 s
  after it fires.
- **Partial windows.** A window cut short (end of file, Ctrl-C) is not judged by the
  baseline detectors, because a 0.3 s window would look like a traffic drop.

## Architecture

```
pcap / interface ─► records.parse_packet ─► features.Windower ─► detectors.DetectionEngine ─► alerts
   (sources.py)      (scapy → PacketRecord)   (per-window stats)    (EWMA z-scores + rules)        │
                                                                                                  ▼
                                               dashboard.py / tui.py (curses)  ·  report.py (pandas CSV/JSON)
```

Scapy appears only in `records.py`, `sources.py` and `synth.py`. Everything after
parsing works on a small frozen `PacketRecord` dataclass, so the core can be tested with
hand-written records and no pcap. The curses code in `tui.py` only paints lines. The
dashboard's state and layout live in `dashboard.py` as plain Python, so tests check them
directly.

| File | Responsibility |
| --- | --- |
| `src/netwatch/records.py` | `PacketRecord` and `parse_packet`: scapy packet → timestamp, IPs, ports, protocol, length, TCP flags |
| `src/netwatch/features.py` | `Windower`: streams records into aligned windows (including empty ones) and computes `WindowStats` |
| `src/netwatch/baseline.py` | `Ewma` (mean/variance/z-score) and `GuardedBaseline` (warm-up, pollution guard, relearning) |
| `src/netwatch/detectors.py` | `VolumeDetector`, `StatDetector`, `PortScanDetector`, `SynFloodDetector`, `DetectionEngine` (cooldown), `Alert` |
| `src/netwatch/analyzer.py` | `Analyzer`: records → windows → alerts, plus history for reports. Shared by every mode. |
| `src/netwatch/sources.py` | `read_pcap`, `PacedReplay`, thread-safe `Feed`, `LiveCapture` (scapy `AsyncSniffer`), privilege checks |
| `src/netwatch/runner.py` | `pump`: main-loop glue between a feed, the analyzer and a clock (live or replay time) |
| `src/netwatch/dashboard.py` | `DashboardState`, `build_screen`, sparkline and bar helpers (no curses) |
| `src/netwatch/tui.py` | curses rendering and key handling |
| `src/netwatch/report.py` | pandas summaries, CSV/JSON export, alert formatting |
| `src/netwatch/synth.py` | seeded synthetic traffic scenarios written with `wrpcap` |
| `src/netwatch/cli.py` | argparse commands: `analyze`, `replay`, `live`, `demo` |
| `src/netwatch/units.py` | byte formatting shared by alerts, reports and the dashboard |
| `tests/` | pytest suite: parsing, windowing (cross-checked against pandas), EWMA math, every detector, pcap/pcapng round trips, CLI end to end, dashboard model and rendering |

**Why pandas is not on the per-packet path.** Building DataFrames per packet would be far
too slow for a live stream. The windower uses plain counters and sets, and pandas works
on the much smaller per-window table: percentiles, group-bys and exports.

## Limitations

- **Throughput.** Packet parsing goes through scapy's full dissector, which handles
  roughly 5,000 packets/s on a typical machine. The analysis itself is much faster. This
  suits a home or lab network, not a busy production link.
- **Synthetic tests.** The demo traffic is plausible, not realistic. Real networks are
  burstier, so expect to tune `--threshold`, `--warmup` and the rule thresholds for your
  network. The defaults are a starting point, not a guarantee.
- **Correlated alerts.** One event can raise several related alerts in the same window,
  for example `syn_flood` plus `traffic_spike` plus `unique_src_anomaly`. NetWatch does
  not merge them into one incident.
- **Simple rules.** Slow scans spread over many windows (for example `nmap -T1`) stay
  under the per-window thresholds. Handshakes that cross a window boundary are not
  matched, which slightly undercounts completions. Busy NAT gateways or proxies can
  trigger host-sweep alerts.
- **Headers only.** No payload inspection, no flow reassembly, and no signatures. This is
  an anomaly detector, not a replacement for Suricata or Zeek.
- **Long gaps.** A gap in a capture is replayed as one empty window per elapsed window
  length. That is correct for drop detection, but a capture with an hours-long gap will
  produce many empty windows.
- **Memory.** Per-window history is kept in memory for the end-of-run report (one small
  row per window).
- **Platform.** Live capture has been exercised on Linux. curses is not available in the
  standard Windows Python build, but `analyze` and `--no-ui` do not need it.

## Ethics

Only capture and analyse traffic on networks you own or are explicitly authorised to
monitor. Intercepting other people's traffic without permission is illegal in many
jurisdictions and a breach of trust everywhere. The synthetic attack captures exist so
you can test detection without attacking anything.

## Development

```bash
pip install -e ".[dev]"
ruff check .              # lint
ruff format .             # format
pytest                    # full test suite
netwatch demo && netwatch analyze netwatch-demo/mixed.pcap
```

CI (GitHub Actions) runs ruff, pytest and a CLI smoke test on Python 3.10, 3.11 and 3.12.

## License

MIT © 2026 Sifon Aniefiok. See [LICENSE](LICENSE).
