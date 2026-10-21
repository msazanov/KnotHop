#!/usr/bin/env python3
"""Medians of the final L3 series (`g1-<cond>-<stack>-<n>.json`) as tables.

CPU per GiB is the VPN process CPU on the client / on the exit divided by what the transfer delivered
(`bytes` of the TCP upload). Counts of runs are printed so a median of 1 is not mistaken for a median of 5.
"""
import json
import statistics as st
from pathlib import Path

ROOT = Path(__file__).resolve().parent / "results" / "l3"
CONDS = [("lan", "локальная сеть"), ("d25", "RTT 50 мс"), ("l05", "RTT 50 мс, потери 0,5%"), ("l2", "RTT 50 мс, потери 2%")]
STACKS = [("rawg", "rawg (RNS, датаграммы QUIC)"), ("rawg-hop", "rawg через узел A (2 звена)"), ("awg", "AmneziaWG 3.1 userspace"), ("direct", "без туннеля")]


def load(cond, stack):
    key = "hop" if stack == "rawg-hop" else stack
    return [json.loads(p.read_text()) for p in sorted(ROOT.glob(f"g1-{key}-{cond}-*.json" if stack == "rawg-hop" else f"g1-{cond}-{key}-*.json"))
            if json.loads(p.read_text()).get("success")]


def med(runs, test, field, sub=None):
    vals = []
    for r in runs:
        v = r["tests"].get(test, {}).get(field)
        if sub and isinstance(v, dict):
            v = v.get(sub)
        if isinstance(v, (int, float)):
            vals.append(v)
    return (st.median(vals), len(vals)) if vals else (None, 0)


def f(v, n=1):
    return "—" if v is None else f"{v:.{n}f}"


for cond, label in CONDS:
    print(f"\n### {label}")
    print("| Стек | n | ping p50, мс | TCP вверх / вниз, Мбит/с | UDP 100 Мбит/с, потери % | ping под нагрузкой p50 / p95, мс (потери %) | QUIC внутри, Мбит/с | CPU клиента / выхода, с на ГиБ (TCP вверх) |")
    print("|---|---:|---:|---:|---:|---:|---:|---:|")
    for stack, name in STACKS:
        runs = load(cond, stack)
        if not runs:
            continue
        up, _ = med(runs, "tcp_up", "mbit_s"); down, _ = med(runs, "tcp_down", "mbit_s")
        p50, _ = med(runs, "ping_idle", "p50_ms"); loss, _ = med(runs, "udp_1200_100m", "loss_pct")
        l50, _ = med(runs, "ping_loaded", "p50_ms"); l95, _ = med(runs, "ping_loaded", "p95_ms"); ll, _ = med(runs, "ping_loaded", "loss_pct")
        q, nq = med(runs, "quic", "goodput_mbit_s")
        cpus = []
        for r in runs:
            t = r["tests"].get("tcp_up", {})
            if t.get("bytes") and t.get("cpu_s"):
                gib = t["bytes"] / 2**30
                cpus.append((t["cpu_s"].get("c_vpn", 0) / gib, t["cpu_s"].get("e_vpn", 0) / gib))
        cpu = f"{st.median(c for c, _ in cpus):.1f} / {st.median(e for _, e in cpus):.1f}" if cpus else "—"
        print(f"| {name} | {len(runs)} | {f(p50, 2)} | {f(up, 0)} / {f(down, 0)} | {f(loss, 2)} | {f(l50)} / {f(l95)} ({f(ll, 0)}) | {f(q)}{'' if nq == len(runs) else f' (n={nq})'} | {cpu} |")
