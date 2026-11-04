#!/usr/bin/env python3
"""Таблица первых записей после Finished клиента (53): направление+размер тела, по сессиям. Использование: mimic_table.py FILE.tsv [N]
(формат recsniff.py: conn t dir type len chunk). Показывает только полные сессии (есть app-записи клиента кроме Finished)."""
import sys, collections
n = int(sys.argv[2]) if len(sys.argv) > 2 else 16
conns = collections.defaultdict(list)
for l in open(sys.argv[1]):
    c, t, d, ty, ln, _ = l.split("\t"); conns[int(c)].append((float(t), d[0], int(ty), int(ln)))
for c in sorted(conns):
    rs = conns[c]
    if sum(1 for r in rs if r[1] == "c" and r[2] == 23) < 3: continue
    # после Finished клиента: всё app (23) кроме первого клиентского 53; серверные перелёт/билеты (до s: 266,266 включительно) пропускаем
    out = []; seen_fin = False; skip_tick = 0
    for t, d, ty, ln in rs:
        if ty != 23: continue
        if d == "c" and not seen_fin: seen_fin = True; continue
        if not seen_fin: continue
        out.append(f"{d}{ln}")
    print(f"conn {c:2d}: " + " ".join(out[:n]))
