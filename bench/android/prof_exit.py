#!/usr/bin/env python3
"""Профиль CPU выхода knothopd в лаборатории lab13 (wall-clock сэмплер на eu-stack, как bench/stack_sampler.py).

  KNOTHOP_BIN=deploy/dist/knothopd python3 -I bench/android/prof_exit.py [--clients 1] [--samples 80] [--cpus 1] [--udp-mbit 0]

Поднимает lab13 (adm - выход), N клиентов, гонит iperf3 TCP (или UDP с --udp-mbit) клиентов к «сайту» через туннель и во время
передачи снимает стеки процесса knothopd в adm. Итог: доли состояний потоков и верхние «свои» кадры потоков, которые были в состоянии R.
Только локальная лаборатория. В конце lab13 down.
"""
import argparse, collections, json, os, re, subprocess, sys, time
from pathlib import Path

HERE = Path(__file__).resolve().parent
LAB = [sys.executable, str(HERE / "lab13.py")]   # без -I: lab13 импортирует соседний laptop.py
SITE = "172.29.98.50"
IDLE = re.compile(r"Condvar>::wait|Poll>::poll|park|epoll_wait|futex_wait|nanosleep|Inner>::park")
SKIP = re.compile(r"^(__|core::|alloc::|std::|tokio::|futures|<?tokio|<?core|<?alloc|<?std|parking_lot|syscall|epoll|clone|start_thread|_start|main$|\?\?)")


def sh(*a, timeout=120, check=False):
    r = subprocess.run(a, capture_output=True, text=True, timeout=timeout)
    if check and r.returncode:
        sys.exit(f"{a[:4]}: {(r.stderr or r.stdout)[-400:]}")
    return r


def frames_by_thread(pid):
    """Сырые адреса кадров по потокам и состояния потоков - одним docker exec (иначе выборок мало)."""
    cmd = (f"eu-stack -q -p {pid} 2>/dev/null; echo ===STAT; "
           f"for t in /proc/{pid}/task/*; do echo \"$(basename $t) $(cat $t/stat 2>/dev/null)\"; done")
    r = sh("docker", "exec", "--privileged", "adm", "sh", "-c", cmd, timeout=20)
    stack, _, stat = r.stdout.partition("===STAT")
    out, cur = {}, None
    for line in stack.splitlines():
        m = re.match(r"TID (\d+):", line)
        if m:
            cur = int(m.group(1)); out[cur] = []
            continue
        m = re.match(r"#\d+\s+(0x[0-9a-f]+)", line.strip())
        if m and cur is not None:
            out[cur].append(int(m.group(1), 16))
    st = {}
    for line in stat.splitlines():
        m = re.match(r"(\d+) \d+ \((.*)\) (\S)", line.strip())
        if m:
            st[int(m.group(1))] = (m.group(2), m.group(3))
    return out, st


def symbolizer(pid, binary):
    """Адрес процесса -> имя функции: смещение в файле по /proc/pid/maps и llvm-symbolizer по тому же бинарнику на хосте."""
    maps = sh("docker", "exec", "adm", "cat", f"/proc/{pid}/maps").stdout.splitlines()
    segs = []
    for l in maps:
        f = l.split()
        if len(f) >= 6 and f[5].endswith("/knothopd"):
            a, b = (int(x, 16) for x in f[0].split("-"))
            segs.append((a, b, int(f[2], 16)))
    cache = {}

    def resolve(addrs):
        need = [x for x in set(addrs) if x not in cache]
        offs = []
        for x in need:
            o = next((x - a + off for a, b, off in segs if a <= x < b), None)
            offs.append(o)
        q = [f"0x{o:x}" for o in offs if o is not None]
        names = []
        if q:
            r = subprocess.run(["llvm-symbolizer", "--obj", binary, "--functions=linkage", "--demangle", "--no-inlines", "--output-style=GNU"],
                               input="\n".join(q), capture_output=True, text=True, timeout=120)
            lines = r.stdout.splitlines()
            names = [lines[i] for i in range(0, len(lines), 2)]
        it = iter(names)
        for x, o in zip(need, offs):
            cache[x] = next(it, "??") if o is not None else "<не knothopd>"
        return [cache[x] for x in addrs]
    return resolve


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--clients", type=int, default=1)
    ap.add_argument("--samples", type=int, default=80)
    ap.add_argument("--cpus", default="1")
    ap.add_argument("--udp-mbit", type=int, default=0, help="0 - TCP; иначе UDP с этой скоростью на клиента")
    ap.add_argument("--duration", type=int, default=60)
    ap.add_argument("--out", default=str(Path.home() / f".cache/knothop-bench/prof-exit-{time.strftime('%Y%m%d-%H%M%S')}.json"))
    a = ap.parse_args()
    sh(*LAB, "down", timeout=120)
    try:
        sh(*LAB, "up", timeout=180, check=True)
        sh("docker", "update", "--cpus", a.cpus, "adm", check=True)
        names = [f"p{i:02d}" for i in range(1, a.clients + 1)]
        for n in names:
            sh(*LAB, "client", n, "--from", "adm", timeout=120, check=True)
        for _ in range(90):
            ok = all('"you_are": "172.29.98.11"' in sh("docker", "exec", n, "curl", "-s", "-m", "4", f"http://{SITE}/").stdout for n in names)
            if ok:
                break
            time.sleep(2)
        else:
            sys.exit("клиенты не подняли туннель")
        for i, _ in enumerate(names):
            sh("docker", "exec", "-d", "l13-site", "iperf3", "-s", "-p", str(5201 + i))
        time.sleep(1)
        pid = sh("docker", "exec", "adm", "sh", "-c", "pidof knothopd").stdout.split()[0]
        procs = []
        for i, n in enumerate(names):
            extra = ["-u", "-b", f"{a.udp_mbit}M"] if a.udp_mbit else []
            procs.append(subprocess.Popen(["docker", "exec", n, "iperf3", "-c", SITE, "-p", str(5201 + i), "-t", str(a.duration), "-J", *extra],
                                          stdout=subprocess.PIPE, stderr=subprocess.DEVNULL, text=True))
        time.sleep(5)
        states, top, top_r, comm_r = collections.Counter(), collections.Counter(), collections.Counter(), collections.Counter()
        idle, busy, chains, incl = collections.Counter(), collections.Counter(), collections.Counter(), collections.Counter()
        resolve = symbolizer(pid, os.environ.get("KNOTHOP_BIN", ""))
        t_end = time.time() + a.duration - 10
        n_s = 0
        raw = []
        while n_s < a.samples and time.time() < t_end:
            raw.append(frames_by_thread(pid))
            n_s += 1
        for fr, stt in raw:
            for tid, addrs in fr.items():
                comm, st = stt.get(tid, ("?", "?"))
                fs = [f for f in resolve(addrs[:40]) if f != "<не knothopd>"] or ["<вне knothopd: libc/ядро>"]
                states[(comm, st)] += 1
                # простой: поток ждёт (condvar, epoll, парковка) - в профиль работы не идёт
                if fs and IDLE.search(fs[0]):
                    idle[comm] += 1
                    continue
                busy[comm] += 1
                own = [f for f in fs if not SKIP.match(f)]
                chain = " <- ".join(x[:60] for x in fs[:4])
                chains[chain] += 1
                for f in set(own[:6]):
                    incl[f[:100]] += 1
                continue
                own = [f for f in fs if not SKIP.match(f)]
                if st == "R" and fs:
                    comm_r[comm] += 1
                    top_r[fs[0][:110]] += 1
                    if own:
                        top[own[0][:110]] += 1
        res = []
        for p in procs:
            out, _ = p.communicate(timeout=a.duration + 60)
            try:
                j = json.loads(out)
                e = j["end"]
                bps = (e.get("sum_received") or e.get("sum"))["bits_per_second"]
                res.append(round(bps / 1e6, 1))
            except (ValueError, KeyError, TypeError):
                res.append(None)
        stats = sh("docker", "stats", "--no-stream", "--format", "{{.CPUPerc}} {{.MemUsage}}", "adm").stdout.strip()
        doc = {"clients": a.clients, "cpus": a.cpus, "udp_mbit": a.udp_mbit, "samples": n_s, "mbit_per_client": res,
               "mbit_sum": round(sum(x for x in res if x), 1), "adm_stats_after": stats,
               "states": {f"{c}/{s}": v for (c, s), v in states.most_common(20)},
               "running_threads": comm_r.most_common(10), "top_own_frames_running": top.most_common(30),
               "top_frames_running": top_r.most_common(20), "idle": dict(idle), "busy": dict(busy),
               "busy_chains": chains.most_common(40), "busy_inclusive_own": incl.most_common(40)}
        Path(a.out).parent.mkdir(parents=True, exist_ok=True)
        Path(a.out).write_text(json.dumps(doc, ensure_ascii=False, indent=1))
        print(json.dumps({k: doc[k] for k in ("clients", "mbit_sum", "mbit_per_client", "samples", "adm_stats_after", "running_threads")}, ensure_ascii=False))
        print("потоки: занят", dict(busy), "простой", dict(idle))
        print("занятые цепочки (верх <- вызывающие):")
        for f, c in chains.most_common(22):
            print(f"{c:5d}  {f}")
        print("включительно свои функции (занятые выборки):")
        for f, c in incl.most_common(22):
            print(f"{c:5d}  {f}")
        print("JSON:", a.out)
    finally:
        sh(*LAB, "down", timeout=180)


if __name__ == "__main__":
    main()
