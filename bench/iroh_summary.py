#!/usr/bin/env python3
"""Сводка results/iroh/{m,l}-*.json. Медиана и min..max по повторам, неуспешные прогоны не скрываются."""
import glob, json, re, statistics as st, sys
from collections import defaultdict
from pathlib import Path
HERE = Path(__file__).resolve().parent
def load(prefix):
    g = defaultdict(list)
    for p in sorted(glob.glob(str(HERE / "results/iroh" / f"{prefix}-*.json"))):
        d = json.load(open(p)); tag = d["cell"]["tag"] if "tag" in d["cell"] else Path(p).stem
        key = re.sub(r"-r\d+$", "", Path(p).stem)
        g[key].append(d)
    return g
def fmt(v, n=1): return "-" if v is None else f"{v:.{n}f}"
def rng(xs): return f"{min(xs):.1f}..{max(xs):.1f}" if xs else "-"
mode = sys.argv[1] if len(sys.argv) > 1 else "m"
g = load(mode)
if mode == "m":
    print("| Сценарий | Направление/тест | n (ок/всего) | МиБ/с, медиана | min..max | CPU клиент/сервер, % ядра | RTT p50 / p95, мс | wire/payload (veth клиента) |")
    print("|---|---|---|---|---|---|---|---|")
    for key, rows in g.items():
        ok = [r for r in rows if r["success"]]
        if "echo" in key:
            p50 = [r["client"]["rtt_ms"]["p50"] for r in ok]; p95 = [r["client"]["rtt_ms"]["p95"] for r in ok]
            print(f"| {key.split('-')[1]} | echo 32 Б | {len(ok)}/{len(rows)} | - | - | - | {st.median(p50):.2f} / {st.median(p95):.2f} | - |"); continue
        v = [r["client"]["mib_s"] for r in ok]
        cpu = [(r["cpu_percent_one_core"]["client"], r["cpu_percent_one_core"]["server"]) for r in ok]
        ov = []
        for r in ok:
            n = r["client_nic_delta"]; pay = r["cell"]["mib"] * 1048576
            ov.append((n["rx_bytes"] + n["tx_bytes"]) / pay)
        print(f"| {key.split('-')[1]} | {key.split('-')[2]} | {len(ok)}/{len(rows)} | {fmt(st.median(v)) if v else '-'} | {rng(v)} | "
              f"{fmt(st.median(c for c, _ in cpu), 0) if cpu else '-'}/{fmt(st.median(s for _, s in cpu), 0) if cpu else '-'} | - | {fmt(st.median(ov), 3) if ov else '-'} |")
elif mode == "l":
    print("| Потери | Доп. задержка, мс | QUIC (iroh) МиБ/с, медиана [min..max] | TCP (iperf3) МиБ/с, медиана [min..max] | QUIC / TCP |")
    print("|---|---|---|---|---|")
    keys = sorted({re.match(r"l-(?:quic|tcp)-(l\d+-d\d+)", k).group(1) for k in g}, key=lambda x: (int(re.search(r"d(\d+)", x).group(1)), int(re.search(r"l(\d+)", x).group(1))))
    for k in keys:
        q = [r["client"]["mib_s"] for r in g.get(f"l-quic-{k}", []) if r["success"]]
        t = [r["client"]["mib_s"] for r in g.get(f"l-tcp-{k}", []) if r["success"]]
        l, d = re.match(r"l(\d+)-d(\d+)", k).groups()
        mq = st.median(q) if q else None; mt = st.median(t) if t else None
        print(f"| {l}% | +{d} | {fmt(mq)} [{rng(q)}] (n={len(q)}) | {fmt(mt)} [{rng(t)}] (n={len(t)}) | {fmt(mq/mt*100,0)+'%' if mq and mt else '-'} |")
