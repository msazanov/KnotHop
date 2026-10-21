#!/usr/bin/env python3
"""Нагрузочный стенд: нода adm при ~50 клиентах (модель 0013) поверх Docker-лаборатории lab13.py.

  python3 -I bench/android/load50.py [--clients 50] [--batch 10] [--batch-gap 5] [--join-timeout 180]
      [--duration 30] [--udp-mbit 5] [--cpus-adm 1] [--mem-adm 300m] [--out FILE.json] [--keep]

Фазы (каждая пишется в JSON с таймингом и счётчиками журнала adm):
  join          клиенты волнами (--batch, пауза --batch-gap); время от старта до рабочего туннеля
  lat_idle      ping -c 20 -i 0.2 до сайта через туннель у каждого клиента, без нагрузки
  tcp           iperf3 -c всех клиентов одновременно, --duration с; ping у каждого в середине нагрузки
  udp           iperf3 -u -b --udp-mbit на клиента одновременно; потери и джиттер
  stop1/restart1  одновременная остановка всех клиентов (docker stop), затем повторный старт волнами
  stop2/restart2  второй такой цикл (повторное подключение всех; рост памяти/потоков adm видно по снимкам)

Фон: docker stats (adm, хаб) и /proc/<rawgd>/status (Threads, VmRSS) adm каждые ~2 с, со снимками по фазам.

Нагрузочная точка: CPU/память adm ограничиваются docker update (по умолчанию 1 CPU, 300m - как CPUQuota=100% на узлах).
Проверка туннеля: ответ сайта должен прийти с адреса adm (you_are), а не с адреса клиента, иначе это прямой путь
по мосту лаборатории, а не через TUN. Приглашения lab13 пишет сам в файлы 0600; здесь они не читаются и не печатаются.
"""
import argparse
import hashlib
import json
import math
import os
import re
import signal
import statistics
import subprocess
import sys
import threading
import time
from datetime import datetime
from pathlib import Path

HERE = Path(__file__).resolve().parent
LAB13 = HERE / "lab13.py"
RELEASE_BIN = HERE.parent.parent / "deploy/dist/rawgd"
DEBUG_BIN = HERE.parent / "rns-iroh-node/target/debug/rawgd"
NET = "rawg-lab13"
ADM, HUB, SITE = "adm", "l13-hub", "l13-site"
SITE_IP = "172.29.98.50"
SITE_URL = f"http://{SITE_IP}/"
IPERF_PORT0 = 5201
PING_COUNT, PING_INTERVAL, PING_DELAY = 20, 0.2, 8  # PING_DELAY - сдвиг пинга в середину TCP-нагрузки (с)
STOP_WAIT = 10
SAMPLE_PERIOD = 2
LOG_KEYS = ("ошибка", "error", "panic", "отказ", "лимит", "refuse", "close link")
SECRET_RE = re.compile(r"rawg[0-9a-z]*-\S+")  # приглашения rawgi-…/rawg2-… не должны попасть в JSON и вывод
UNIT = {"B": 1, "KB": 1e3, "KIB": 1024, "MB": 1e6, "MIB": 2**20, "GB": 1e9, "GIB": 2**30}


def progress(msg):
    print(f"[{datetime.now():%H:%M:%S}] {msg}", file=sys.stderr, flush=True)


def sh(*args, timeout=120):
    try:
        return subprocess.run(args, capture_output=True, text=True, timeout=timeout)
    except subprocess.TimeoutExpired:
        return subprocess.CompletedProcess(args, 124, "", "timeout")


def err_text(r):
    return SECRET_RE.sub("<скрыто>", (r.stderr or r.stdout or "").strip()[-300:])


def lab(*args, timeout=180):
    return sh(sys.executable, str(LAB13), *args, timeout=timeout)


def pct(vals, p):
    """Перцентиль nearest-rank."""
    if not vals:
        return None
    s = sorted(vals)
    return round(s[max(0, math.ceil(p / 100 * len(s)) - 1)], 3)


def par(jobs):
    """jobs: [(key, callable)] в параллельных потоках; исключение одной задачи не валит остальные."""
    out = {}

    def work(k, f):
        try:
            out[k] = f()
        except Exception as e:  # noqa: BLE001 - результат ошибки попадает в JSON
            out[k] = {"ok": False, "error": SECRET_RE.sub("<скрыто>", str(e))[:200]}

    ths = [threading.Thread(target=work, args=(k, f), daemon=True) for k, f in jobs]
    for t in ths:
        t.start()
    for t in ths:
        t.join()
    return out


def sha256(path):
    h = hashlib.sha256()
    with open(path, "rb") as f:
        for chunk in iter(lambda: f.read(1 << 20), b""):
            h.update(chunk)
    return h.hexdigest()


def adm_ip():
    r = sh("docker", "inspect", "-f", '{{(index .NetworkSettings.Networks "rawg-lab13").IPAddress}}', ADM)
    ip = r.stdout.strip()
    if r.returncode or not ip:
        raise RuntimeError("adm не найден в сети rawg-lab13")
    return ip


def limit_adm(args):
    r = sh("docker", "update", "--cpus", str(args.cpus_adm), "--memory", args.mem_adm, "--memory-swap", args.mem_adm, ADM, timeout=60)
    if r.returncode:
        raise RuntimeError("docker update adm: " + err_text(r))


def to_mib(s):
    m = re.match(r"\s*([\d.]+)\s*([A-Za-z]+)", s or "")
    return round(float(m[1]) * UNIT.get(m[2].upper(), 1) / 2**20, 2) if m else None


def num(s):
    try:
        return float(str(s).rstrip("%"))
    except ValueError:
        return None


def docker_stats():
    r = sh("docker", "stats", "--no-stream", "--format", "{{.Name}}|{{.CPUPerc}}|{{.MemUsage}}|{{.PIDs}}", ADM, HUB, timeout=30)
    out = {}
    for line in r.stdout.splitlines():
        parts = line.split("|")
        if len(parts) != 4:
            continue
        name, cpu, mem, pids = parts
        out[name] = {"cpu": num(cpu), "mem_mib": to_mib(mem), "pids": int(pids) if pids.isdigit() else None}
    return out


# Процессы rawgd в adm: потоки и RSS (счётчики утечек). Без вывода содержимого файлов состояния.
PROC_CMD = ('for d in /proc/[0-9]*; do [ "$(cat $d/comm 2>/dev/null)" = rawgd ] && '
            '{ echo "PID ${d#/proc/}"; grep -E "^(Threads|VmRSS):" $d/status; }; done')


def rawgd_proc():
    r = sh("docker", "exec", ADM, "sh", "-c", PROC_CMD, timeout=20)
    pid = threads = rss = None
    for line in r.stdout.splitlines():
        if line.startswith("PID "):
            pid = line[4:].strip()
        elif line.startswith("Threads:"):
            threads = int(line.split()[1])
        elif line.startswith("VmRSS:"):
            rss = round(int(line.split()[1]) / 1024, 2)
    return {"pid": pid, "threads": threads, "rss_mib": rss}


def log_mark():
    r = sh("docker", "exec", ADM, "sh", "-c", "wc -l < /state/node.log 2>/dev/null || echo 0", timeout=20)
    try:
        return int(r.stdout.strip())
    except ValueError:
        return 0


def log_counts(start):
    """Число строк журнала adm с ключевыми словами, начиная со строки start (только счётчики, строки не печатаются)."""
    r = sh("docker", "exec", ADM, "sh", "-c", f"tail -n +{start + 1} /state/node.log 2>/dev/null", timeout=120)
    counts = {k: 0 for k in LOG_KEYS}
    for line in r.stdout.splitlines():
        low = line.lower()
        for k in LOG_KEYS:
            if k in low:
                counts[k] += 1
    return counts


def adm_state():
    """Записи прав и живые соседи adm. Число Link этим не получить: rawgd list его не печатает."""
    r = sh("docker", "exec", ADM, "rawgd", "list", "--state", "/state", timeout=60)
    text = r.stdout.split("таблица соседей")[0]
    m = re.search(r"приглашения \((\d+)\)", text)
    st = {"list_rc": r.returncode, "records": sum(1 for x in text.splitlines() if x.startswith("  корень ")),
          "pins": int(m[1]) if m else None}
    n = sh("docker", "exec", ADM, "cat", "/state/neighbors.json", timeout=20)
    try:
        st["exits_up"] = sum(1 for x in json.loads(n.stdout).get("exits", []) if x.get("s") == "up")
    except (ValueError, AttributeError):
        st["exits_up"] = None
    return st


class Sampler(threading.Thread):
    def __init__(self):
        super().__init__(daemon=True)
        self.phase = "init"
        self.samples = []
        self._halt = threading.Event()

    def run(self):
        while not self._halt.is_set():
            st = docker_stats()
            pr = rawgd_proc()
            a, h = st.get(ADM, {}), st.get(HUB, {})
            self.samples.append({"t": round(time.time(), 1), "phase": self.phase,
                                 "adm_cpu": a.get("cpu"), "adm_mem_mib": a.get("mem_mib"), "adm_pids": a.get("pids"),
                                 "adm_threads": pr.get("threads"), "adm_rss_mib": pr.get("rss_mib"),
                                 "hub_cpu": h.get("cpu"), "hub_mem_mib": h.get("mem_mib")})
            self._halt.wait(SAMPLE_PERIOD)

    def stop(self):
        self._halt.set()
        self.join(60)


def tunnel_ok(name, adm):
    """Сайт отвечает и видит адрес adm (NAT выхода), а не адрес клиента (прямой путь по мосту)."""
    r = sh("docker", "exec", name, "curl", "-s", "-m", "3", SITE_URL, timeout=15)
    if r.returncode:
        return False
    try:
        return json.loads(r.stdout).get("you_are") == adm
    except ValueError:
        return False


def connect_waves(names, adm, start, args):
    """Волны по --batch: старт (start(name) возвращает CompletedProcess), затем опрос туннеля в отдельном потоке."""
    res = {}
    threads = []

    def poll(n, t0):
        while True:
            el = round(time.monotonic() - t0, 2)
            if tunnel_ok(n, adm):
                res[n] = {"ok": True, "t_s": el}
                return
            if el > args.join_timeout:
                res[n] = {"ok": False, "t_s": None, "error": f"нет туннеля за {args.join_timeout} с"}
                return
            time.sleep(1)

    for i in range(0, len(names), args.batch):
        for n in names[i:i + args.batch]:
            t0 = time.monotonic()
            r = start(n)
            if r.returncode:
                res[n] = {"ok": False, "t_s": None, "error": err_text(r)}
                continue
            th = threading.Thread(target=poll, args=(n, t0), daemon=True)
            th.start()
            threads.append(th)
        if i + args.batch < len(names):
            time.sleep(args.batch_gap)
    for th in threads:
        th.join()
    return res


def join_summary(res):
    ok = [v["t_s"] for v in res.values() if v["ok"]]
    return {"ok": len(ok), "failed": len(res) - len(ok), "t_p50_s": pct(ok, 50), "t_p95_s": pct(ok, 95),
            "t_max_s": max(ok, default=None), "failed_names": sorted(n for n, v in res.items() if not v["ok"])}


def ping_client(n, delay=0):
    if delay:
        time.sleep(delay)
    r = sh("docker", "exec", n, "ping", "-c", str(PING_COUNT), "-i", str(PING_INTERVAL), "-W", "3", SITE_IP,
           timeout=PING_COUNT * PING_INTERVAL + 40)
    rtts = [float(x) for x in re.findall(r"time=([\d.]+) ms", r.stdout)]
    m = re.search(r"(\d+) packets transmitted, (\d+) (?:packets )?received", r.stdout)
    sent, recv = (int(m[1]), int(m[2])) if m else (PING_COUNT, len(rtts))
    out = {"sent": sent, "recv": recv, "loss_pct": round(100 * (1 - recv / sent), 1) if sent else None}
    if rtts:
        out.update(p50=pct(rtts, 50), p95=pct(rtts, 95), max=round(max(rtts), 3))
    else:
        out["error"] = err_text(r) or "нет ответов"
    return out


def lat_summary(per):
    ok = [v for v in per.values() if v.get("p50") is not None]
    losses = [v["loss_pct"] for v in per.values() if v.get("loss_pct") is not None]
    return {"clients_ok": len(ok), "p50_med_ms": pct([v["p50"] for v in ok], 50), "p95_med_ms": pct([v["p95"] for v in ok], 50),
            "p95_worst_ms": max((v["p95"] for v in ok), default=None), "max_worst_ms": max((v["max"] for v in ok), default=None),
            "loss_mean_pct": round(sum(losses) / len(losses), 2) if losses else None}


def lat_phase(names):
    per = par([(n, (lambda n=n: ping_client(n))) for n in names])
    return {"per_client": per, "summary": lat_summary(per)}


def parse_iperf(mode, r):
    try:
        j = json.loads(r.stdout)
    except ValueError:
        return {"ok": False, "error": err_text(r) or "нет JSON от iperf3"}
    if r.returncode or "error" in j:
        return {"ok": False, "error": SECRET_RE.sub("<скрыто>", str(j.get("error", err_text(r))))[:200]}
    end = j.get("end", {})
    if mode == "tcp":
        rcv, snd = end.get("sum_received", {}), end.get("sum_sent", {})
        return {"ok": True, "mbps": round(rcv.get("bits_per_second", 0) / 1e6, 2), "retransmits": snd.get("retransmits")}
    s = end.get("sum", {})
    return {"ok": True, "mbps": round(s.get("bits_per_second", 0) / 1e6, 2), "jitter_ms": s.get("jitter_ms"),
            "lost": s.get("lost_packets"), "packets": s.get("packets"), "lost_pct": s.get("lost_percent")}


def iperf_one(n, port, mode, args):
    cmd = ["iperf3", "-c", SITE_IP, "-p", str(port), "-t", str(args.duration), "-J", "--connect-timeout", "10000"]
    if mode == "udp":
        cmd += ["-u", "-b", f"{args.udp_mbit:g}M"]
    return parse_iperf(mode, sh("docker", "exec", n, *cmd, timeout=args.duration + 90))


def iperf_summary(mode, per):
    ok = {n: v for n, v in per.items() if v.get("ok")}
    mbps = [v["mbps"] for v in ok.values()]
    s = {"ok": len(ok), "failed": len(per) - len(ok),
         "errors": sorted({(v.get("error") or "")[:120] for v in per.values() if not v.get("ok")})[:5],
         "total_mbps": round(sum(mbps), 2), "client_mbps_p50": pct(mbps, 50), "client_mbps_p95": pct(mbps, 95),
         "client_mbps_min": min(mbps, default=None)}
    if mode == "tcp":
        s["retransmits_total"] = sum(v.get("retransmits") or 0 for v in ok.values())
    else:
        jit = [v["jitter_ms"] for v in ok.values() if v.get("jitter_ms") is not None]
        lost = sum(v.get("lost") or 0 for v in ok.values())
        pk = sum(v.get("packets") or 0 for v in ok.values())
        s.update(jitter_p50_ms=pct(jit, 50), jitter_p95_ms=pct(jit, 95), jitter_max_ms=max(jit, default=None),
                 lost_total=lost, packets_total=pk, lost_pct_total=round(100 * lost / pk, 3) if pk else None)
    return s


def iperf_servers_start(n):
    ports = " ".join(str(IPERF_PORT0 + i) for i in range(n))
    script = f"rm -f /tmp/iperf3.pids; for p in {ports}; do iperf3 -s -p $p >/dev/null 2>&1 & echo $! >> /tmp/iperf3.pids; done; wait"
    sh("docker", "exec", "-d", SITE, "sh", "-c", script, timeout=30)
    time.sleep(3)
    cnt = sh("docker", "exec", SITE, "sh", "-c", "wc -l < /tmp/iperf3.pids", timeout=20).stdout.strip()
    if cnt != str(n):
        raise RuntimeError(f"iperf3 -s на сайте: ожидалось {n} процессов, запущено {cnt or 0}")


def iperf_servers_stop():
    sh("docker", "exec", SITE, "sh", "-c", "[ -f /tmp/iperf3.pids ] && kill $(cat /tmp/iperf3.pids) 2>/dev/null; rm -f /tmp/iperf3.pids; true", timeout=30)


def iperf_phase(names, mode, args, with_ping):
    jobs = [(("iperf", n), (lambda n=n, i=i: iperf_one(n, IPERF_PORT0 + i, mode, args))) for i, n in enumerate(names)]
    if with_ping:
        delay = min(PING_DELAY, args.duration // 3)  # пинг попадает в середину нагрузки
        jobs += [(("ping", n), (lambda n=n: ping_client(n, delay))) for n in names]
    got = par(jobs)
    per = {n: got[("iperf", n)] for n in names}
    out = {"per_client": per, "summary": iperf_summary(mode, per)}
    if with_ping:
        pings = {n: got[("ping", n)] for n in names}
        out["ping_per_client"] = pings
        out["ping_summary"] = lat_summary(pings)
    return out


def stop_all(names):
    r = sh("docker", "stop", "-t", "2", *names, timeout=300)
    time.sleep(STOP_WAIT)
    return {"rc": r.returncode, "error": err_text(r) if r.returncode else None}


def phase(result, sampler, name, fn):
    sampler.phase = name
    log0 = log_mark()
    t0 = time.time()
    progress(f"фаза {name} ...")
    data = fn()
    rec = {"dur_s": round(time.time() - t0, 1), "log": log_counts(log0), "result": data}
    result["phases"][name] = rec
    progress(f"фаза {name}: {rec['dur_s']} с")
    return data


def snap(result, label):
    result["stability"]["snapshots"].append({"label": label, "t": round(time.time(), 1), "proc": rawgd_proc(),
                                             "state": adm_state(), "stats": docker_stats().get(ADM)})


def agg(vals):
    return (max(vals, default=None), round(statistics.fmean(vals), 1) if vals else None)


def res_by_phase(samples, phases):
    out = {}
    for ph in phases:
        s = [x for x in samples if x["phase"] == ph]
        cpu_max, cpu_avg = agg([x["adm_cpu"] for x in s if x["adm_cpu"] is not None])
        mem_max, mem_avg = agg([x["adm_mem_mib"] for x in s if x["adm_mem_mib"] is not None])
        hub_max, hub_avg = agg([x["hub_cpu"] for x in s if x["hub_cpu"] is not None])
        out[ph] = {"samples": len(s), "adm_cpu_max": cpu_max, "adm_cpu_avg": cpu_avg, "adm_mem_max_mib": mem_max,
                   "adm_mem_avg_mib": mem_avg, "adm_threads_max": max([x["adm_threads"] for x in s if x["adm_threads"] is not None], default=None),
                   "hub_cpu_max": hub_max, "hub_cpu_avg": hub_avg}
    return out


def run_all(args, names, result, sampler):
    lab_up = lab("up")
    if lab_up.returncode:
        raise RuntimeError("lab13 up: " + err_text(lab_up))
    adm = adm_ip()
    limit_adm(args)
    result["stability"] = {"snapshots": []}
    progress(f"adm: cpu={args.cpus_adm} mem={args.mem_adm}; клиентов {len(names)}")

    phase(result, sampler, "join", lambda: (lambda res: {"per_client": res, "summary": join_summary(res)})(
        connect_waves(names, adm, lambda n: lab("client", n, "--from", ADM), args)))
    phase(result, sampler, "lat_idle", lambda: lat_phase(names))

    iperf_servers_start(len(names))
    try:
        phase(result, sampler, "tcp", lambda: iperf_phase(names, "tcp", args, True))
        phase(result, sampler, "udp", lambda: iperf_phase(names, "udp", args, False))
    finally:
        iperf_servers_stop()

    restart = lambda n: sh("docker", "start", n, timeout=120)  # noqa: E731
    snap(result, "before_stop1")
    for k in (1, 2):
        phase(result, sampler, f"stop{k}", lambda: stop_all(names))
        snap(result, f"after_stop{k}")
        phase(result, sampler, f"restart{k}", lambda: (lambda res: {"per_client": res, "summary": join_summary(res)})(
            connect_waves(names, adm, restart, args)))
        snap(result, f"after_restart{k}")


def table_rows(result):
    P = result["phases"]
    rows = []
    if "join" in P:
        s = P["join"]["result"]["summary"]
        rows += [("join", "клиенты ok / fail", f"{s['ok']} / {s['failed']}"),
                 ("join", "до туннеля p50 / p95 / max, с", f"{s['t_p50_s']} / {s['t_p95_s']} / {s['t_max_s']}")]
    if "lat_idle" in P:
        s = P["lat_idle"]["result"]["summary"]
        rows.append(("lat_idle", "p50 мед / p95 мед / p95 худш. / max худш., мс",
                     f"{s['p50_med_ms']} / {s['p95_med_ms']} / {s['p95_worst_ms']} / {s['max_worst_ms']}"))
        rows.append(("lat_idle", "потери, % (среднее по клиентам)", s["loss_mean_pct"]))
    if "tcp" in P:
        r = P["tcp"]["result"]
        s = r["summary"]
        rows += [("tcp", "клиенты ok / fail", f"{s['ok']} / {s['failed']}"),
                 ("tcp", "Σ Мбит/с; на клиента p50 / p95 / min", f"{s['total_mbps']}; {s['client_mbps_p50']} / {s['client_mbps_p95']} / {s['client_mbps_min']}"),
                 ("tcp", "retransmits (Σ)", s["retransmits_total"]),
                 ("tcp", "пинг под нагрузкой p50 мед / p95 мед / потери %",
                  f"{r['ping_summary']['p50_med_ms']} / {r['ping_summary']['p95_med_ms']} / {r['ping_summary']['loss_mean_pct']}")]
    if "udp" in P:
        s = P["udp"]["result"]["summary"]
        rows += [("udp", "клиенты ok / fail", f"{s['ok']} / {s['failed']}"),
                 ("udp", "Σ Мбит/с", s["total_mbps"]),
                 ("udp", "потери Σ, %", s.get("lost_pct_total")),
                 ("udp", "джиттер p50 / p95 / max, мс", f"{s.get('jitter_p50_ms')} / {s.get('jitter_p95_ms')} / {s.get('jitter_max_ms')}")]
    for k in (1, 2):
        for ph in (f"restart{k}",):
            if ph in P:
                s = P[ph]["result"]["summary"]
                rows.append((ph, "клиенты ok / fail; до туннеля p50 / max, с",
                             f"{s['ok']} / {s['failed']}; {s['t_p50_s']} / {s['t_max_s']}"))
    for sn in result.get("stability", {}).get("snapshots", []):
        p = sn["proc"]
        rows.append(("снимок", f"{sn['label']}: потоки adm / RSS adm, МиБ / записи прав / выходы up (вкл. adm)",
                     f"{p['threads']} / {p['rss_mib']} / {sn['state'].get('records')} / {sn['state'].get('exits_up')}"))
    for ph, r in res_by_phase(result["samples"], P.keys()).items():
        rows.append((ph, "adm CPU max / avg, % (1 ядро=100); RAM max / avg, МиБ",
                     f"{r['adm_cpu_max']} / {r['adm_cpu_avg']}; {r['adm_mem_max_mib']} / {r['adm_mem_avg_mib']}"))
        rows.append((ph, "хаб CPU max / avg, %; потоки adm max", f"{r['hub_cpu_max']} / {r['hub_cpu_avg']}; {r['adm_threads_max']}"))
    for ph in P:
        nz = {k: v for k, v in P[ph]["log"].items() if v}
        rows.append((ph, "журнал adm: строки с ключевыми словами", nz or "нет"))
    return rows


def print_table(result, status):
    print(f"\nитог: {status}; параметры: клиентов {result['params']['clients']}, batch {result['params']['batch']}, "
          f"adm {result['params']['cpus_adm']} CPU / {result['params']['mem_adm']}")
    rows = table_rows(result)
    w0 = max(len(r[0]) for r in rows) if rows else 5
    w1 = max(len(r[1]) for r in rows) if rows else 5
    for a, b, c in rows:
        print(f"{a:<{w0}}  {b:<{w1}}  {c}")


def main():
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--clients", type=int, default=50)
    ap.add_argument("--batch", type=int, default=10, help="клиентов в волне")
    ap.add_argument("--batch-gap", type=float, default=5, help="пауза между волнами, с")
    ap.add_argument("--join-timeout", type=int, default=180, help="таймаут до рабочего туннеля, с")
    ap.add_argument("--duration", type=int, default=30, help="длительность iperf3 на клиента, с")
    ap.add_argument("--udp-mbit", type=float, default=5, help="скорость UDP на клиента, Мбит/с")
    ap.add_argument("--cpus-adm", type=float, default=1, help="docker update --cpus для adm")
    ap.add_argument("--mem-adm", default="300m", help="docker update --memory (и --memory-swap) для adm")
    ap.add_argument("--out", type=Path, help="JSON-результат (по умолчанию ~/.cache/rawg-bench/load50-<время>.json)")
    ap.add_argument("--keep", action="store_true", help="не убирать лабораторию в конце (lab13.py down вручную)")
    args = ap.parse_args()
    if not 1 <= args.clients <= 999:
        ap.error("--clients: от 1 до 999 (имена u001..u999)")
    if not 1 <= args.batch:
        ap.error("--batch должен быть >= 1")

    if "RAWGD_BIN" not in os.environ:
        os.environ["RAWGD_BIN"] = str(RELEASE_BIN if RELEASE_BIN.exists() else DEBUG_BIN)
    binp = Path(os.environ["RAWGD_BIN"])
    if not binp.is_file():
        sys.exit(f"нет бинаря {binp} (RAWGD_BIN); cargo build --bin rawgd в bench/rns-iroh-node")

    busy = sh("docker", "ps", "-a", "--filter", f"network={NET}", "--format", "{{.Names}}")
    if busy.returncode:
        sys.exit("docker недоступен: " + err_text(busy))
    if busy.stdout.strip():
        sys.exit("лаборатория rawg-lab13 уже поднята (" + " ".join(busy.stdout.split()[:5]) + "...): "
                 "сначала lab13.py down; стенд не трогает чужие контейнеры")

    names = [f"u{i:03d}" for i in range(1, args.clients + 1)]
    out_path = args.out or Path.home() / ".cache/rawg-bench" / f"load50-{datetime.now():%Y%m%d-%H%M%S}.json"
    params = {k: (str(v) if isinstance(v, Path) else v) for k, v in vars(args).items() if k != "out"}
    result = {"started": datetime.now().isoformat(timespec="seconds"), "params": params,
              "binary": {"path": str(binp), "sha256": sha256(binp)},
              "host": {"cpus": os.cpu_count(), "kernel": os.uname().release}, "phases": {}}
    sampler = Sampler()
    status = "interrupted"

    def on_term(signum, frame):
        raise SystemExit(143)

    signal.signal(signal.SIGTERM, on_term)
    sampler.start()
    try:
        run_all(args, names, result, sampler)
        status = "ok"
    except KeyboardInterrupt:
        status = "interrupted"
    except SystemExit:
        status = "interrupted"
    except Exception as e:  # noqa: BLE001
        status = "error: " + SECRET_RE.sub("<скрыто>", str(e))[:300]
    finally:
        sampler.stop()
        result["samples"] = sampler.samples
        result["status"] = status
        result["finished"] = datetime.now().isoformat(timespec="seconds")
        out_path.parent.mkdir(parents=True, exist_ok=True)
        tmp = out_path.with_suffix(".tmp")
        tmp.write_text(json.dumps(result, ensure_ascii=False, indent=1))
        os.replace(tmp, out_path)
        if args.keep:
            progress("--keep: лаборатория оставлена (lab13.py down убирает)")
        else:
            d = lab("down", timeout=300)
            progress("lab13 down: " + ("ок" if d.returncode == 0 else err_text(d)))
        try:
            print_table(result, status)
        except Exception as e:  # noqa: BLE001
            print("не удалось собрать таблицу:", e, file=sys.stderr)
        print(f"\nJSON: {out_path}")
    return 0 if status == "ok" else 1


if __name__ == "__main__":
    sys.exit(main())
