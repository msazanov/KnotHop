#!/usr/bin/env python3
"""A/B на телефоне: CPU приложения на гигабайт при одинаковой нагрузке (3 параллельных загрузки / 2 выгрузки) к sink_server в контейнере выхода.

  python3 phone_ab.py --configs "base:" "w2:--workers 2" --rounds 3 [--mb 150] [--dir down|up|both]

Конфигурации идут вперемешку по кругу (дрейф телефона и Wi-Fi). Метрика: cpu_s/GiB по /proc/<pid>/stat (utime+stime приложения), Мбит/с.
Телефон по adb; VPN-разрешение уже выдано (am start --ez auto true)."""
import argparse
import json
import re
import statistics as st
import subprocess
import sys
import time

PKG = "com.rawg.vpn"
HOST = "10.99.0.1:8099"


def sh(cmd, timeout=180):
    return subprocess.run(["adb", "shell", cmd], capture_output=True, text=True, timeout=timeout).stdout


def app_pid():
    return sh(f"pidof {PKG}").strip().split()[0] if sh(f"pidof {PKG}").strip() else ""


def jiffies(pid):
    f = sh(f"cat /proc/{pid}/stat").rsplit(")", 1)[1].split()
    return int(f[11]) + int(f[12])


def start(args):
    sh(f"am start -n {PKG}/.MainActivity --ez stop true >/dev/null"); time.sleep(4)
    sh(f"am force-stop {PKG}"); time.sleep(1)
    sh(f"am start -n {PKG}/.MainActivity --ez auto true --es args '{args}' >/dev/null")
    t0 = time.time()
    while time.time() - t0 < 25:
        time.sleep(1)
        if "1 received" in sh("ping -c 1 -W 1 10.99.0.1"):
            return True
    return False


def tun_bytes():
    """(rx, tx) байт интерфейса tun0 по /proc/net/dev (принято из туннеля в систему = загрузка телефона)."""
    for l in sh("cat /proc/net/dev").splitlines():
        if l.strip().startswith("tun0:"):
            f = l.split(":", 1)[1].split()
            return int(f[0]), int(f[8])
    return 0, 0


def cycles(secs):
    """simpleperf stat по приложению за secs секунд: циклы и инструкции, всего и в ядре. Работает без root для profileable-приложения."""
    out = sh(f"simpleperf stat --app {PKG} -e cpu-cycles,instructions,cpu-cycles:k,instructions:k --duration {secs} 2>&1", timeout=secs + 40)
    v = {}
    for ev, key in (("cpu-cycles:k", "cyc_k"), ("instructions:k", "ins_k"), ("cpu-cycles", "cyc"), ("instructions", "ins")):
        m = re.search(r"([\d,]+)\s+" + re.escape(ev) + r"\b", out)
        if m:
            v[key] = int(m.group(1).replace(",", ""))
    return v


def run_load(direction, mb, pid, window=8):
    """Нагрузка 14 с (3 загрузки или 2 выгрузки), окно измерения window с, начиная со 2-й секунды:
    циклы приложения (всего/ядро) на ГиБ по tun0, скорость по tun0, CPU-секунды по /proc."""
    n = 3 if direction == "down" else 2
    if direction == "up":
        sh(f"[ -f /data/local/tmp/up.bin ] || head -c {mb * 1024 * 1024} /dev/zero > /data/local/tmp/up.bin")
    if direction == "down":
        one = f"curl -s -m 14 -o /dev/null http://{HOST}/down?mb=2000"
    else:
        one = f"curl -s -m 14 -o /dev/null -X POST --data-binary @/data/local/tmp/up.bin http://{HOST}/up"
    import threading
    box = {}
    th = threading.Thread(target=lambda: box.update(out=sh("for i in " + " ".join(map(str, range(n))) + f"; do ({one}) & done; wait", timeout=60)))
    th.start()
    time.sleep(2.5)
    r0, t0b = tun_bytes()
    j0, t0 = jiffies(pid), time.time()
    cyc = cycles(window)
    wall = time.time() - t0
    j1 = jiffies(pid)
    r1, t1b = tun_bytes()
    th.join()
    nbytes = (r1 - r0) if direction == "down" else (t1b - t0b)
    cpu = (j1 - j0) / 100.0
    out = {"dir": direction, "bytes": nbytes, "wall_s": round(wall, 2), "mbit_s": round(nbytes * 8 / wall / 1e6, 1),
           "cpu_s": round(cpu, 2), "cpu_pct": round(100 * cpu / wall), "cpu_s_per_gib": round(cpu / (nbytes / 2**30), 2) if nbytes else None}
    if cyc.get("cyc") and nbytes:
        gib = nbytes / 2**30
        out.update(gcyc_per_gib=round(cyc["cyc"] / 1e9 / gib, 2), gcyc_k_per_gib=round(cyc.get("cyc_k", 0) / 1e9 / gib, 2),
                   gcyc_u_per_gib=round((cyc["cyc"] - cyc.get("cyc_k", 0)) / 1e9 / gib, 2), ipc=round(cyc["ins"] / cyc["cyc"], 2))
    return out


def main():
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--configs", nargs="+", required=True, help="имя:аргументы (аргументы после двоеточия)")
    ap.add_argument("--rounds", type=int, default=3)
    ap.add_argument("--mb", type=int, default=150)
    ap.add_argument("--dir", default="down", choices=["down", "up", "both"])
    ap.add_argument("--out", default="")
    a = ap.parse_args()
    cfgs = [c.split(":", 1) for c in a.configs]
    dirs = ["down", "up"] if a.dir == "both" else [a.dir]
    res = []
    for r in range(a.rounds):
        for name, args in cfgs:
            if not start(args):
                print(f"[{name}] туннель не поднялся", flush=True); continue
            time.sleep(3)
            pid = app_pid()
            sh(f"curl -s -m 20 -o /dev/null http://{HOST}/down?mb=8")  # прогрев
            for d in dirs:
                m = run_load(d, a.mb, pid)
                m.update(cfg=name, round=r, args=args)
                res.append(m)
                print(json.dumps(m, ensure_ascii=False), flush=True)
    print("\nмедианы:")
    for d in dirs:
        for name, _ in cfgs:
            v = [x for x in res if x["cfg"] == name and x["dir"] == d and x.get("gcyc_per_gib")]
            if v:
                print(f"{d:5s} {name:12s} n={len(v)}  {st.median(x['mbit_s'] for x in v):7.1f} Мбит/с  {st.median(x['gcyc_per_gib'] for x in v):6.1f} Гцикл/ГиБ "
                      f"(ядро {st.median(x['gcyc_k_per_gib'] for x in v):.1f}, польз. {st.median(x['gcyc_u_per_gib'] for x in v):.1f}; разброс {min(x['gcyc_per_gib'] for x in v):.0f}-{max(x['gcyc_per_gib'] for x in v):.0f})  cpu {st.median(x['cpu_s_per_gib'] for x in v):.0f} с/ГиБ")
    if a.out:
        open(a.out, "w").write(json.dumps(res, indent=1, ensure_ascii=False))


if __name__ == "__main__":
    main()
