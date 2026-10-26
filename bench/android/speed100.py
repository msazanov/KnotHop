#!/usr/bin/env python3
"""Бенч R10 (0014): скорость и блокировка DPI через VPN-туннель телефона, по каждому выходу.

Для каждого выхода из exits.txt: выбрать его интентом (--es select), дождаться подтверждения в logcat,
проверить внешний IP через туннель, скачать --bytes по HTTP (toybox nc на телефоне, в фоне),
раз в секунду снимать размер файла. Итог: таблица в stdout и JSON в --out.

Только стандартная библиотека. Все вызовы adb с таймаутом. Ctrl+C: остановить загрузку,
вернуть select auto, удалить файл. Загрузка на телефоне ограничена `toybox timeout`,
поэтому зависший nc сам завершается.
"""
import argparse
import datetime
import json
import os
import re
import subprocess
import sys
import time
import urllib.parse

ACTIVITY = "com.knothop.vpn/.MainActivity"
DEV_FILE = "/data/local/tmp/speed100.bin"
DEV_RC = "/data/local/tmp/speed100.rc"
DEV_PID = "/data/local/tmp/speed100.pid"
DEFAULT_URL = "http://speedtest.tele2.net/100MB.zip"
DEFAULT_BYTES = 100000000
SELECT_WAIT_S = 40
NO_DATA_ABORT_S = 30
STALL_ABORT_S = 60
SLOW_MBPS = 1.0
ADB_TIMEOUT = 30
IP_HOST = "ifconfig.me"
EXITS_FILE = os.path.join(os.path.dirname(os.path.abspath(__file__)), "exits.txt")
SAFE = re.compile(r"[A-Za-z0-9._~/%?=&+:-]+")
RE_CUR = re.compile(r"текущий выход: (.+?) \(([0-9a-f]{8})\)")
RE_STAT = re.compile(r"STATUS состояние: up \| выход: (.+?) \(([0-9a-f]{8})\)")
RE_ACC = re.compile(r"выход (.+?) принял клиента за (\d+) мс \(хопов (Some\((\d+)\)|None)\)")


def adb(serial, *args, timeout=ADB_TIMEOUT):
    cmd = ["adb"] + (["-s", serial] if serial else []) + list(args)
    p = subprocess.run(cmd, capture_output=True, timeout=timeout, encoding="utf-8", errors="replace")
    return p.returncode, p.stdout, p.stderr


def sh(serial, cmd, timeout=ADB_TIMEOUT):
    return adb(serial, "shell", cmd, timeout=timeout)[1]


def select(serial, value):
    rc, out, err = adb(serial, "shell", f"am start -n {ACTIVITY} --es select {value}")
    if rc != 0 or "Error" in out + err:
        raise RuntimeError(f"am start не сработал: {(out + err).strip()[:200]}")


def choose(serial, dest):
    """Выбрать выход, дождаться строки «текущий выход» с его dest[:8]. Возвращает (имя, хопы, примечание)."""
    dest8 = dest[:8]
    adb(serial, "logcat", "-c")
    try:
        select(serial, dest)
    except RuntimeError as e:
        return None, None, str(e)
    deadline = time.monotonic() + SELECT_WAIT_S
    while True:
        try:
            out = adb(serial, "logcat", "-d", "-s", "knothopui")[1]
        except subprocess.TimeoutExpired:
            out = ""
        cur = [m for m in RE_CUR.finditer(out) if m.group(2) == dest8]
        if not cur and "состояние: up" in out:
            # выход уже был текущим: смены нет, строки «текущий выход» не будет - берём строку состояния
            st = [m for m in RE_STAT.finditer(out) if m.group(2) == dest8]
            if st:
                return st[-1].group(1), None, "уже был текущим (хопы неизвестны)"
        if cur:
            name = cur[-1].group(1)
            acc = [m for m in RE_ACC.finditer(out) if m.group(1) == name]
            hops = int(acc[-1].group(4)) if acc and acc[-1].group(4) else None
            return name, hops, "" if acc else "нет строки «принял клиента»"
        if time.monotonic() >= deadline:
            return None, None, f"нет «текущий выход» с {dest8} за {SELECT_WAIT_S} с"
        time.sleep(2)


def check_ip(serial, expected):
    cmd = (f"(printf 'GET / HTTP/1.0\\r\\nHost: {IP_HOST}\\r\\nUser-Agent: curl\\r\\n\\r\\n' "
           f"| toybox nc -w 8 {IP_HOST} 80) 2>&1 | tail -1")
    try:
        out = sh(serial, cmd, timeout=30).strip()
    except subprocess.TimeoutExpired:
        out = ""
    seen = out.splitlines()[-1].strip() if out else ""
    return seen, seen == expected


def sample(serial):
    """Размер файла на телефоне и rc загрузки (если уже завершилась) одним adb-вызовом."""
    out = sh(serial, f"echo S$(stat -c %s {DEV_FILE} 2>/dev/null); echo R$(cat {DEV_RC} 2>/dev/null)", timeout=15)
    size, rc = 0, None
    for line in out.splitlines():
        line = line.strip()
        if line.startswith("S") and line[1:].isdigit():
            size = int(line[1:])
        elif line.startswith("R") and line[1:].strip().isdigit():
            rc = int(line[1:])
    return size, rc


def cleanup(serial, kill=True):
    k = f"kill $(cat {DEV_PID}) 2>/dev/null; " if kill else ""
    sh(serial, f"{k}rm -f {DEV_FILE} {DEV_RC} {DEV_PID}; true", timeout=15)


def run_download(serial, url, total, stall_s, timeout_s):
    host, port, path = url
    cleanup(serial, kill=False)
    # Загрузка в фоне; toybox timeout ограничивает nc, pid timeout-процесса - для аварийного kill
    # вход nc держим открытым (sleep): иначе nc сразу закрывает отправку, и часть серверов (Cloudflare) молча закрывает соединение
    inner = (f"(printf \"GET {path} HTTP/1.0\\r\\nHost: {host}\\r\\nUser-Agent: curl\\r\\n\\r\\n\"; sleep {int(timeout_s) + 20}) | "
             f"toybox timeout {int(timeout_s) + 20} toybox nc -w 30 {host} {port} > {DEV_FILE} & "
             f"echo $! > {DEV_PID}; wait $!; echo $? > {DEV_RC}")
    sh(serial, f"nohup sh -c '{inner}' >/dev/null 2>&1 &", timeout=15)

    t0 = time.monotonic()
    series, stalls = [], []
    first_t = last_growth = None
    prev, done, abort, nxt = 0, False, None, 0.0
    now = 0.0
    while True:
        now = time.monotonic() - t0
        try:
            size, rc = sample(serial)
        except subprocess.TimeoutExpired:
            size, rc = None, None
        if size is not None:
            series.append([round(now, 1), size])
            if size > prev:
                if first_t is None:
                    first_t = last_growth = now
                else:
                    gap = now - last_growth
                    if gap >= stall_s:
                        stalls.append(round(gap, 1))
                    last_growth = now
                prev = size
            if size >= total:
                done = True
                break
            if rc is not None:
                abort = f"загрузка завершилась на {size} байтах (rc {rc})"
                break
        if now >= timeout_s:
            abort = "таймаут"
            break
        if first_t is None and now >= NO_DATA_ABORT_S:
            abort = f"ноль байт за {NO_DATA_ABORT_S} с"
            break
        if first_t is not None and now - last_growth >= STALL_ABORT_S:
            abort = f"остановка дольше {STALL_ABORT_S} с"
            break
        nxt += 1.0
        time.sleep(max(0.0, nxt - (time.monotonic() - t0)))

    if abort and first_t is not None and now - last_growth >= stall_s:
        stalls.append(round(now - last_growth, 1))
    seconds = round(now - first_t, 2) if first_t is not None else None
    mbps = round(prev / 1e6 / seconds, 3) if seconds else None
    cleanup(serial, kill=not done)
    return {
        "bytes": prev, "seconds": seconds, "mbps": mbps,
        "ttfb": round(first_t, 2) if first_t is not None else None,
        "stalls": stalls, "stall_total": round(sum(stalls), 1),
        "abort": abort, "done": done, "series": series,
    }


def run_exit(serial, ex, url, args):
    r = {"label": ex["label"], "dest8": ex["dest"][:8], "expected_ip": ex["ip"], "name": None, "select_ok": False,
         "hops": None, "ip_seen": None, "ip_ok": None, "bytes": 0, "seconds": None, "mbps": None, "ttfb": None,
         "stalls": [], "stall_total": 0, "verdict": "unavailable", "note": "", "series": []}
    name, hops, note = choose(serial, ex["dest"])
    if name is None:
        r["note"] = note
        return r
    r.update(name=name, select_ok=True, hops=hops, note=note)
    r["ip_seen"], ip_ok = check_ip(serial, ex["ip"]) if ex["ip"] != "-" else (None, None)
    r["ip_ok"] = ip_ok
    d = run_download(serial, url, args.bytes, args.stall, args.timeout)
    r.update(d)
    if d["abort"]:
        r["verdict"] = "blocked"
        r["note"] = (note + "; " if note else "") + d["abort"]
    elif d["stalls"]:
        r["verdict"] = "stalled"
    elif d["mbps"] is not None and d["mbps"] < SLOW_MBPS:
        r["verdict"] = "slow"
    else:
        r["verdict"] = "ok"
    return r


def load_exits(path):
    exits = []
    with open(path, encoding="utf-8") as f:
        for n, line in enumerate(f, 1):
            line = line.strip()
            if not line or line.startswith("#"):
                continue
            parts = line.split()
            if len(parts) != 3 or not re.fullmatch(r"[0-9a-f]{32}", parts[1]):
                raise SystemExit(f"{path}:{n}: нужны 3 поля: метка dest(32 hex) ожидаемый_IP")
            exits.append({"label": parts[0], "dest": parts[1], "ip": parts[2]})
    return exits


def parse_url(url):
    u = urllib.parse.urlsplit(url)
    if u.scheme != "http" or not u.hostname:
        raise SystemExit("--url: нужен http://host[:port]/path (без TLS)")
    path = (u.path or "/") + (("?" + u.query) if u.query else "")
    if not SAFE.fullmatch(u.hostname) or not SAFE.fullmatch(path):
        raise SystemExit("--url: недопустимые символы в host или пути")
    return u.hostname, u.port or 80, path


def _num(v, spec):
    return "-" if v is None else format(v, spec)


def print_table(results):
    print(f"{'метка':<5} {'dest':<8} {'хопы':>4} {'ip':<3} {'байт':>11} {'сек':>7} {'МБ/с':>7} "
          f"{'ttfb':>6} {'остан.':>12}  вердикт")
    for r in results:
        hops = _num(r["hops"], "d")
        ip = {True: "ok", False: "нет", None: "-"}[r["ip_ok"]]
        stalls = f"{len(r['stalls'])}/{r['stall_total']:g}с" if r["select_ok"] else "-"
        print(f"{r['label']:<5} {r['dest8']:<8} {hops:>4} {ip:<3} {r['bytes']:>11} {_num(r['seconds'], '7.1f'):>7} "
              f"{_num(r['mbps'], '7.2f'):>7} {_num(r['ttfb'], '6.1f'):>6} {stalls:>12}  {r['verdict']}"
              + (f"  ({r['note']})" if r["note"] else ""))


def main():
    ap = argparse.ArgumentParser(description="Бенч 100 МБ по выходам через VPN телефона (R10, 0014)")
    ap.add_argument("--serial", help="серийный номер adb (по умолчанию единственное устройство)")
    ap.add_argument("--exits", default="", help="подмножество меток через запятую (по умолчанию все из exits.txt)")
    ap.add_argument("--url", default=DEFAULT_URL, help="только http")
    ap.add_argument("--bytes", type=int, default=DEFAULT_BYTES, help="сколько байт скачать")
    ap.add_argument("--stall", type=float, default=10, help="секунд без прироста = остановка")
    ap.add_argument("--timeout", type=float, default=300, help="секунд на выход")
    ap.add_argument("--out", help="JSON с результатами (по умолчанию ~/.cache/knothop-bench/speed100-<время>.json)")
    args = ap.parse_args()
    if args.bytes <= 0 or args.stall <= 0 or args.timeout <= 0:
        ap.error("--bytes, --stall и --timeout должны быть > 0")

    url = parse_url(args.url)
    exits = load_exits(EXITS_FILE)
    if args.exits:
        wanted = [x.strip() for x in args.exits.split(",") if x.strip()]
        known = {e["label"] for e in exits}
        unknown = [w for w in wanted if w not in known]
        if unknown:
            ap.error(f"нет в exits.txt: {', '.join(unknown)}")
        exits = [e for e in exits if e["label"] in wanted]

    stamp = datetime.datetime.now().strftime("%Y%m%d-%H%M%S")
    out_path = args.out or os.path.join(os.path.expanduser("~/.cache/knothop-bench"), f"speed100-{stamp}.json")
    results, interrupted = [], False
    try:
        for ex in exits:
            print(f"== {ex['label']} {ex['dest'][:8]}", file=sys.stderr, flush=True)
            results.append(run_exit(args.serial, ex, url, args))
    except KeyboardInterrupt:
        interrupted = True
        print("прервано: останавливаю загрузку, возврат на auto", file=sys.stderr)
    finally:
        for step in (lambda: cleanup(args.serial), lambda: select(args.serial, "auto")):
            try:
                step()
            except Exception as e:  # очистка не должна маскировать исходную причину
                print(f"очистка: {e}", file=sys.stderr)

    os.makedirs(os.path.dirname(out_path), exist_ok=True)
    tmp = out_path + ".tmp"
    with open(tmp, "w", encoding="utf-8") as f:
        json.dump({"started": stamp, "url": args.url, "bytes": args.bytes, "stall_s": args.stall,
                   "timeout_s": args.timeout, "interrupted": interrupted, "results": results},
                  f, ensure_ascii=False, indent=1)
    os.replace(tmp, out_path)
    print_table(results)
    print(f"JSON: {out_path}")
    return 130 if interrupted else 0


if __name__ == "__main__":
    sys.exit(main())
