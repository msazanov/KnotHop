#!/usr/bin/env python3
"""Summarise matched local stream runs; CPU accounting includes the drain period.

Usage: python3 bench/optimization_summary.py 'bulk-base-*.json' 'bulk-new-*.json'
Patterns are relative to bench/results/lev-iroh. Rates are not battery energy.
"""
import argparse
import json
import statistics
from pathlib import Path


def summarize(pattern):
    root = Path(__file__).resolve().parent / "results" / "lev-iroh"
    runs = [json.loads(p.read_text()) for p in sorted(root.glob(pattern))]
    valid = [d for d in runs if d.get("success") and d.get("verified")
             and not d["stream"].get("send_error") and d["stream"].get("mib_s") is not None]
    if not valid:
        raise ValueError(f"no valid measurements: {pattern}")
    speeds = [d["stream"]["mib_s"] for d in valid]
    q1, _, q3 = statistics.quantiles(speeds, n=4, method="inclusive") if len(speeds) > 1 else (speeds[0],) * 3
    cpu = {}
    for role in ("c", "e", "a"):
        if not all(role in d["cpu_percent_one_core"] for d in valid):
            continue
        values = []
        for d in valid:
            # Old artifacts store only rounded CPU% and wall time. This is an
            # approximation; newer artifacts preserve exact cgroup CPU deltas.
            seconds = d.get("cpu_seconds", {}).get(role)
            if seconds is None:
                seconds = d["cpu_percent_one_core"][role] / 100 * d["wall_s"]
            values.append(seconds * 1073741824 / d["stream"]["bytes_recv"])
        cpu[role] = statistics.median(values)
    result = {"pattern": pattern, "n": len(valid), "rejected": len(runs) - len(valid),
              "mib_s_median": statistics.median(speeds), "mib_s_iqr": q3 - q1,
              "cpu_s_per_gib_median": cpu,
              "overhead_median": statistics.median([d["overhead_eth0"] for d in valid])}
    echo = [d["echo"] for d in valid if d.get("echo")]
    if echo:
        result["echo"] = {k: statistics.median([d[k] for d in echo])
                          for k in ("p50_ms", "p95_ms", "p99_ms")}
        result["echo"]["timeouts"] = sum(d["timeouts"] for d in echo)
    return result


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("patterns", nargs="+")
    args = parser.parse_args()
    print(json.dumps([summarize(p) for p in args.patterns], indent=2))
