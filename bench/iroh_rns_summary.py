#!/usr/bin/env python3
"""Сводка results/iroh-rns/sw-*.json: пережил ли RNS Link смену пути, пауза, скорость по фазам, overhead."""
import glob, json, re, statistics as st
from collections import defaultdict
from pathlib import Path
HERE = Path(__file__).resolve().parent
LABEL = {"def": "по умолчанию (15 с / 5 с)", "t8": "8 с / 2 с", "t3": "3 с / 1 с", "t15": "1,5 с / 0,5 с"}
groups = defaultdict(list)
for p in sorted(glob.glob(str(HERE / "results/iroh-rns/sw-*-r[0-9].json"))):
    m = re.fullmatch(r".*/sw-(def|t8|t3|t15)-r\d\.json", p)
    if m: groups[m.group(1)].append(json.load(open(p)))
print("| Таймер простоя / keep-alive пути QUIC | n | RNS Link выжил | Resource без сбоев | макс. пауза, с (по прогонам) | MiB/с до блокировки | MiB/с через relay | MiB/с после возврата на direct | Данные проверены (SHA-256) |")
print("|---|---|---|---|---|---|---|---|---|")
for key in ("def", "t8", "t3", "t15"):
    rows = groups.get(key, [])
    if not rows: continue
    survived = sum(1 for r in rows if r["client"].get("link_closed") is False)
    clean = sum(1 for r in rows if r["success"])
    verified = sum(1 for r in rows if r.get("payload_verified"))
    gaps = []
    ph = {"before": [], "relay": [], "after": []}
    for r in rows:
        tl = r["client"]["transfer"].get("timeline", [])
        go = [e["unix"] for e in r["events"] if e["event"] == "go"][0]
        ends = [x["t_end"] for x in tl if x["ok"]]
        gaps.append(max([b - a for a, b in zip(ends, ends[1:])] or [0]))
        pl = [(t, p) for t, p in r.get("path_log", [])]
        t_relay = next((t for t, p in pl if p == "relay" and t > go), None)
        t_back = next((t for t, p in pl if p == "direct" and t_relay and t > t_relay), None)
        blk = [e["unix"] for e in r["events"] if "BLOCKED" in e["event"]]
        def rate(a, b):
            if a is None or b is None or b <= a: return None
            nb = sum(x["bytes"] for x in tl if x["ok"] and a <= x["t_end"] < b)
            return nb / 1048576 / (b - a)
        end_run = max((x["t_end"] for x in tl), default=go)
        if blk: ph["before"].append(rate(go + 1, blk[0]))
        if t_relay:
            ph["relay"].append(rate(t_relay + 1, t_back - 1 if t_back else end_run))
        if t_back: ph["after"].append(rate(t_back + 1, end_run))
    fmt = lambda v: "-" if not [x for x in v if x] else f"{st.median(x for x in v if x):.1f}"
    print(f"| {LABEL[key]} | {len(rows)} | {survived}/{len(rows)} | {clean}/{len(rows)} | {', '.join(f'{g:.1f}' for g in gaps)} | {fmt(ph['before'])} | {fmt(ph['relay'])} | {fmt(ph['after'])} | {verified}/{len(rows)} |")
