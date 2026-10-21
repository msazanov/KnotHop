#!/usr/bin/env python3
"""Сводка results/lev-iroh/*.json (leviculum + iroh, нативный адаптер)."""
import glob, json, re, statistics as st, sys
from collections import defaultdict
from pathlib import Path
HERE = Path(__file__).resolve().parent
g = defaultdict(list)
for p in sorted(glob.glob(str(HERE / "results/lev-iroh/*-r[0-9].json"))):
    m = re.fullmatch(r".*/(.+)-r\d\.json", p)
    g[m.group(1)].append(json.load(open(p)))
def med(v): return f"{st.median(v):.1f}" if v else "-"
def rng(v): return f"{min(v):.1f}..{max(v):.1f}" if v else "-"
LAB = {"sw-def": "по умолчанию (путь 15 с)", "sw-t3": "путь 3 с / keep-alive 1 с",
       "hop-naive": "без контроллера (QUIC-соединение 4 с)", "hop-ctl4": "контроллер, QUIC-соединение 4 с",
       "hop-ctl2": "контроллер, QUIC-соединение 2 с"}
def title(s): print(f"\n### {s}\n")
title("Потеря прямого пути, relay доступен (RNS видит один интерфейс)")
print("| Настройка | n | данные проверены | Link закрывался | Resource со сбоем (медиана) | пауза макс., с (по прогонам) | MiB/с (медиана) |")
print("|---|---|---|---|---|---|---|")
for k in ("sw-def", "sw-t3"):
    rows = g.get(k, [])
    if not rows: continue
    c = lambda r: r["client"]
    closed = sum(1 for r in rows if any(x["kind"] == "new_link" for x in c(r)["relinks"]))
    fails = [c(r)["resources_total"] - c(r)["resources_ok"] for r in rows]
    print(f"| {LAB[k]} | {len(rows)} | {sum(1 for r in rows if r['verified'])}/{len(rows)} | {closed}/{len(rows)} | {med(fails)} | {', '.join(str(r['max_gap_s']) for r in rows)} | {med([c(r)['bytes_ok']/1048576/c(r)['seconds'] for r in rows])} |")
title("Смена RNS-узла: C→E напрямую, затем C→A→E (relay нет), прямой путь блокируется на 10–40 с")
print("| Режим | n | данные проверены | новый Link понадобился | время поднятия нового Link, мс | пауза макс., с (по прогонам) |")
print("|---|---|---|---|---|---|")
for k in ("hop-naive", "hop-ctl4", "hop-ctl2"):
    rows = g.get(k, [])
    if not rows: continue
    nl = [x["recovered_after_ms"] for r in rows for x in r["client"]["relinks"] if x["kind"] == "new_link"]
    print(f"| {LAB[k]} | {len(rows)} | {sum(1 for r in rows if r['verified'])}/{len(rows)} | {len(nl)}/{len(rows)} | {', '.join(str(x) for x in nl) or '-'} | {', '.join(str(r['max_gap_s']) for r in rows)} |")
title("Скорость и overhead, прямой путь, без блокировок")
print("| Размер Resource | n | MiB/с медиана | min..max | CPU клиент / выход, % ядра | байты eth0 / payload |")
print("|---|---|---|---|---|---|")
for k, lab in (("sp-64k", "64 КиБ"), ("sp-256k", "256 КиБ"), ("sp-1m", "1 МиБ (хеш Resource не сверяется: делится на 2 сегмента)"),
               ("spm-256k", "192 КиБ, **HW_MTU 16384 (локальный патч)**"), ("spm-1024k", "960 КиБ, **HW_MTU 16384 (локальный патч)**")):
    rows = g.get(k, [])
    if not rows: continue
    v = [r["client"]["bytes_ok"] / 1048576 / r["client"]["seconds"] for r in rows]
    ov = [(r["client_nic_delta"]["rx_bytes"] + r["client_nic_delta"]["tx_bytes"]) / r["client"]["bytes_ok"] for r in rows]
    cpu = lambda role: med([r["cpu_percent_one_core"][role] for r in rows])
    print(f"| {lab} | {len(rows)} | {med(v)} | {rng(v)} | {cpu('c')} / {cpu('e')} | {st.median(ov):.3f} |")
