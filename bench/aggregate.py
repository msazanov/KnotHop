#!/usr/bin/env python3
"""Сводка results/raw/m-<set>-*.json -> markdown-таблицы (stdout) и results/summary-<set>.csv.

Для каждой ячейки (iface, mtu_mode, hops, loss) по повторам: медиана и разброс (min..max;
IQR при n>=4). Прогон считается недействительным для throughput, если передача не завершилась
или загрузка любого узла >= CPU_LIMIT процентов одного ядра (CPU-bound); такие прогоны
не удаляются, а помечаются.
"""
import csv, glob, json, os, statistics, sys
from collections import defaultdict

CPU_LIMIT = 90.0
HERE = os.path.dirname(os.path.abspath(__file__))
SET = sys.argv[1] if len(sys.argv) > 1 else "main"
MIB = 1048576.0


def q(vals, p):
    s = sorted(vals)
    if len(s) == 1:
        return s[0]
    k = (len(s) - 1) * p
    f = int(k); c = min(f + 1, len(s) - 1)
    return s[f] + (s[c] - s[f]) * (k - f)


def spread(vals):
    if not vals:
        return "-"
    if len(vals) >= 4:
        return "IQR %.2f..%.2f" % (q(vals, .25), q(vals, .75))
    return "min..max %.2f..%.2f" % (min(vals), max(vals))


cells = defaultdict(list)
for path in sorted(glob.glob(os.path.join(HERE, "results", "raw", "m-%s-*.json" % SET))):
    d = json.load(open(path))
    cell = d["cell"]; c = d["client"]; t = c.get("transfer") or {}
    key = (cell["iface"], cell["mtu_mode"], cell["hops_requested"], cell["loss_pct"])
    row = {"tag": d["tag"], "ok": bool(t.get("ok")), "error": c.get("error")}
    if t:
        cnt = t["counters"]; pay = t["payload_bytes"]; sec = t["seconds"]
        cpus = (d.get("cpu") or {}).get("cpu_percent_of_one_core_by_node") or {}
        row.update(
            mib_s=pay / MIB / sec, mbit_s=pay * 8 / 1e6 / sec, sec=sec, payload=pay,
            wire=(cnt["tx_bytes"] + cnt["rx_bytes"]), rns=(cnt["rns_tx_bytes"] + cnt["rns_rx_bytes"]),
            cpu_max=max(cpus.values()) if cpus else None, cpu_by_node=cpus,
            link_mtu=c.get("link_mtu"), rns_hops=c.get("hops"),
            echo_p50=(c.get("echo") or {}).get("p50_ms"), echo_p95=(c.get("echo") or {}).get("p95_ms"),
            echo_lost=(c.get("echo") or {}).get("lost"), echo_n=(c.get("echo") or {}).get("n"),
            rtt_link_ms=(c.get("link_rtt_s") or 0) * 1000, t_path=c.get("t_path_s"), t_link=c.get("t_link_s"),
        )
        idle = c.get("idle") or {}
        row.update(idle_s=idle.get("seconds"), idle_rns=(idle.get("rns_rx_bytes") or 0) + (idle.get("rns_tx_bytes") or 0),
                   idle_wire_rns=idle.get("rns_port_wire_bytes"), idle_pkts=idle.get("rns_port_wire_packets"))
        row["cpu_bound"] = row["cpu_max"] is not None and row["cpu_max"] >= CPU_LIMIT
    cells[key].append(row)


def med(rows, k):
    v = [r[k] for r in rows if r.get(k) is not None]
    return statistics.median(v) if v else None


def f(x, n=2):
    return "-" if x is None else ("%.*f" % (n, x))


order = sorted(cells, key=lambda k: (k[3], k[0], k[1], k[2]))
out = []
out.append("### Пропускная способность и overhead (набор `%s`)\n" % SET)
out.append("Goodput = полезные байты Resource / время от старта до подтверждения получателя. "
           "overhead RNS = байты RNS-интерфейса клиента (rx+tx, с HDLC) / payload; "
           "overhead L2-L4 = байты veth клиента (rx+tx) / байты RNS; полный = байты veth / payload. "
           "Столбец n = (всего / действительных) прогонов; действительный = завершён и CPU узлов < %d%% ядра.\n" % CPU_LIMIT)
out.append("| iface | MTU-режим | transport-узлов | потери | link MTU | n | goodput МиБ/с (медиана) | разброс | Мбит/с | overhead RNS | overhead L2-L4 | overhead полный | CPU макс % | RTT p50 / p95 мс (эхо 32 Б) |")
out.append("|---|---|---|---|---|---|---|---|---|---|---|---|---|---|")
csvrows = []
for key in order:
    rows = cells[key]
    good = [r for r in rows if r["ok"] and not r.get("cpu_bound")]
    ok_all = [r for r in rows if r["ok"]]
    use = good if good else ok_all
    if not use:
        out.append("| %s | %s | %d | %s%% | - | %d/0 | сбой: %s |" % (key[0], key[1], key[2], key[3], len(rows), rows[0].get("error")))
        continue
    mib = [r["mib_s"] for r in use]
    ov_rns = med(use, "rns") / med(use, "payload")
    ov_l2 = med(use, "wire") / med(use, "rns")
    ov_full = med(use, "wire") / med(use, "payload")
    mark = "" if good else " (CPU-bound)"
    out.append("| %s | %s | %d | %s%% | %s | %d/%d | %s%s | %s | %s | %.3f | %.3f | %.3f | %s | %s / %s |" % (
        key[0], key[1], key[2], key[3], use[0].get("link_mtu"), len(rows), len(good), f(statistics.median(mib)), mark,
        spread(mib), f(med(use, "mbit_s"), 1), ov_rns, ov_l2, ov_full, f(med(use, "cpu_max"), 0),
        f(med(use, "echo_p50")), f(med(use, "echo_p95"))))
    csvrows.append(dict(iface=key[0], mtu_mode=key[1], transports=key[2], loss=key[3], n=len(rows), n_valid=len(good),
                        link_mtu=use[0].get("link_mtu"), goodput_mib_s=statistics.median(mib),
                        overhead_rns=ov_rns, overhead_l2_l4=ov_l2, overhead_full=ov_full,
                        cpu_max=med(use, "cpu_max"), echo_p50_ms=med(use, "echo_p50"), echo_p95_ms=med(use, "echo_p95"),
                        rns_hops=use[0].get("rns_hops")))

out.append("\n### Установление и простой\n")
out.append("| iface | MTU-режим | transport-узлов | RNS hops | path, мс | link, мс | RTT link, мс | простой: RNS Б/с | простой: проводной RNS-трафик Б/с (пакетов/с) |")
out.append("|---|---|---|---|---|---|---|---|---|")
for key in order:
    use = [r for r in cells[key] if r["ok"]]
    if not use:
        continue
    secs = med(use, "idle_s") or 1
    out.append("| %s | %s | %d | %s | %s | %s | %s | %s | %s (%s) |" % (
        key[0], key[1], key[2], use[0].get("rns_hops"),
        f((med(use, "t_path") or 0) * 1000, 0), f((med(use, "t_link") or 0) * 1000, 1), f(med(use, "rtt_link_ms"), 2),
        f((med(use, "idle_rns") or 0) / secs, 1), f((med(use, "idle_wire_rns") or 0) / secs, 1),
        f((med(use, "idle_pkts") or 0) / secs, 2)))

print("\n".join(out))
if csvrows:
    with open(os.path.join(HERE, "results", "summary-%s.csv" % SET), "w", newline="") as fh:
        w = csv.DictWriter(fh, fieldnames=list(csvrows[0].keys())); w.writeheader(); w.writerows(csvrows)
