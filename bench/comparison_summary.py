#!/usr/bin/env python3
"""One-core comparison: rawg (before/after rebase), pure iroh, Xray, AWG.

Reads the `m1c-<stack>-<topology>-<n>.json` cells (1 logical CPU per node, client
included). Medians over valid runs; a run is valid only if its byte-for-byte
pattern check passed. Writes `results/comparison-1core.json` and prints tables.

Definitions, identical for every stack:
  MiB/s       receiver-side, first to last payload byte
  CPU s/GiB   cgroup CPU time of the node over the run / GiB delivered
  CPU %       the same CPU time over the transfer window, in percent of ONE core
  Memory      sum of VmHWM (peak RSS) of the stack's processes in that container
  RTT         16-byte echo on a separate connection/Link; idle = before the load
"""
import json
import statistics as s
from pathlib import Path

from measure import rtt_summary

WARMUP_PROBES = 3  # the first idle probes after connection setup are a start-up effect; reported separately

HERE = Path(__file__).resolve().parent
STACKS = [("rawgpre", "rawg до rebase", "lev"), ("rawg", "rawg после rebase", "lev"),
          ("iroh", "чистый iroh/QUIC", "cmp"), ("xray", "Xray VLESS+REALITY+Vision", "cmp"),
          ("awg", "AWG 3.1 userspace", "cmp")]


def load(key, kind, topology):
    root = HERE / "results" / ("lev-iroh" if kind == "lev" else "protocol-compare")
    runs = [json.loads(p.read_text()) for p in sorted(root.glob(f"m1c-{key}-{topology}-*.json"))]
    return runs, [d for d in runs if d.get("success") and d.get("verified")]


def pick(d, kind):
    raw_idle = d["client"]["echo_idle_rtt_ms"]
    idle = rtt_summary(raw_idle[WARMUP_PROBES:])
    second = raw_idle[1] if len(raw_idle) > 1 else None
    if kind == "lev":
        roles = [r for r in d["memory"] if r != "relay"]  # the iroh relay container is idle in these cells
        return {"mib_s": d["stream"]["mib_s"], "cpu_gib": {r: d["cpu_seconds_per_gib"][r] for r in roles},
                "cpu_pct": {r: d["cpu_percent_window"][r] for r in roles},
                "mem_mib": {r: d["memory"][r]["peak_kb"] / 1024 for r in roles},
                "idle": idle, "second": second, "load": d["echo"], "ovh": d["overhead_eth0"]}
    return {"mib_s": d["mib_s"], "cpu_gib": d["cpu_s_per_gib"], "cpu_pct": d["cpu_percent"],
            "mem_mib": {r: v["peak_kb"] / 1024 for r, v in d["memory"].items()},
            "idle": idle, "second": second, "load": d["echo"], "ovh": d["outer_tx_payload"]}


def med(values):
    return s.median(values)


rows = []
for topology in ("direct", "chain"):
    for key, label, kind in STACKS:
        runs, valid = load(key, kind, topology)
        if not valid:
            continue
        got = [pick(d, kind) for d in valid]
        roles = list(got[0]["cpu_gib"])
        speeds = [g["mib_s"] for g in got]
        quart = s.quantiles(speeds, n=4, method="inclusive") if len(speeds) > 1 else [speeds[0]] * 3
        rows.append({
            "topology": topology, "stack": key, "label": label, "n": len(valid), "failed": len(runs) - len(valid),
            "mib_s": med(speeds), "mib_s_iqr": quart[2] - quart[0],
            "cpu_s_per_gib": {r: med([g["cpu_gib"][r] for g in got]) for r in roles},
            "cpu_percent": {r: med([g["cpu_pct"][r] for g in got]) for r in roles},
            "memory_mib": {r: med([g["mem_mib"][r] for g in got]) for r in roles},
            "rtt_idle_ms": {k: med([g["idle"][k] for g in got]) for k in ("p50_ms", "p95_ms", "p99_ms")},
            "second_probe_ms": med([g["second"] for g in got if g["second"] is not None]),
            "rtt_load_ms": {k: med([g["load"][k] for g in got]) for k in ("p50_ms", "p95_ms", "p99_ms")},
            "echo_timeouts": sum(g["load"]["timeouts"] for g in got),
            "outer_tx_payload": med([g["ovh"] for g in got]),
        })

(HERE / "results" / "comparison-1core.json").write_text(json.dumps(rows, indent=2))
f = lambda v, n=1: f"{v:.{n}f}"
for topology, title in (("direct", "C → E"), ("chain", "C → A → E")):
    print(f"\n### {title}  (1 logical CPU на каждый узел)")
    for r in (x for x in rows if x["topology"] == topology):
        roles = list(r["cpu_s_per_gib"])
        print(f"{r['label']:28} n={r['n']} {f(r['mib_s']):>6} МиБ/с (IQR {f(r['mib_s_iqr'])}) | "
              f"CPU с/ГиБ " + " ".join(f"{k}={f(r['cpu_s_per_gib'][k], 2)}" for k in roles) + " | "
              f"CPU% " + " ".join(f"{k}={f(r['cpu_percent'][k], 0)}" for k in roles) + " | "
              f"RAM МиБ " + " ".join(f"{k}={f(r['memory_mib'][k], 0)}" for k in roles) + " | "
              f"RTT idle p50/95/99 " + "/".join(f(r['rtt_idle_ms'][k], 2) for k in ("p50_ms", "p95_ms", "p99_ms")) + " | "
              f"2-я проба {f(r['second_probe_ms'], 1)} | load " + "/".join(f(r['rtt_load_ms'][k], 1) for k in ("p50_ms", "p95_ms", "p99_ms")) + " | "
              f"ovh {f(r['outer_tx_payload'], 3)}")
