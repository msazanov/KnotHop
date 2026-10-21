#!/usr/bin/env python3
"""Ручной последовательный driver BENCH_RESULT для выбранных Android-выходов."""
import argparse
import datetime as dt
import json
import os
from pathlib import Path
import re
import subprocess
import sys
import time

ACTIVITY = "com.rawg.vpn/.MainActivity"
HERE = Path(__file__).resolve().parent
EXITS_FILE = HERE / "exits.txt"
MB = 100
SELECT_TIMEOUT = 45
BENCH_TIMEOUT = 180
ADB_CALL_TIMEOUT = 15
HEX32 = re.compile(r"[0-9a-fA-F]{32}")
LOG_TIME = re.compile(r"^\s*(\d{4}-\d\d-\d\d\s+\d\d:\d\d:\d\d\.\d+|\d{9,}(?:\.\d+)?)\s+")
RESULT = re.compile(r"BENCH_RESULT\s+(\{.*\})")
QUEUED = re.compile(r"BENCH queued\s+to=([0-9a-fA-F]{32})\s+mb=100")
CURRENT = re.compile(r"текущий выход:\s*(.*?)\s*\(([0-9a-fA-F]{8})\)")
STATUS = re.compile(r"STATUS состояние:\s*up\s*\|\s*выход:\s*(.*?)\s*\(([0-9a-fA-F]{8})\)")


def adb(serial, *args, timeout=ADB_CALL_TIMEOUT):
    cmd = ["adb"] + (["-s", serial] if serial else []) + list(args)
    p = subprocess.run(cmd, capture_output=True, timeout=timeout,
                       encoding="utf-8", errors="replace")
    return p.returncode, p.stdout, p.stderr


def log_epoch(line):
    m = LOG_TIME.match(line)
    if not m:
        return None
    if m.group(1)[0].isdigit() and len(m.group(1).split(".", 1)[0]) >= 9:
        try:
            return float(m.group(1))
        except ValueError:
            return None
    try:
        return dt.datetime.strptime(m.group(1), "%Y-%m-%d %H:%M:%S.%f").timestamp()
    except ValueError:
        return None


def find_current(text, dest8):
    """Match fresh current-output/STATUS records, requiring STATUS to say up."""
    found = []
    for line in text.splitlines():
        m = CURRENT.search(line) or STATUS.search(line)
        if m and m.group(2).lower() == dest8.lower():
            if CURRENT.search(line) or "состояние: up" in line:
                found.append(m.group(1).strip())
    return found[-1] if found else None


def parse_result_logs(text, dest, after_epoch, expected_name=None):
    """Accept only JSON preceded by a matching, timestamped BENCH queued marker."""
    queued_epoch = None
    result = None
    for line in text.splitlines():
        stamp = log_epoch(line)
        payload = line.split("rawgui", 1)[-1]
        q = QUEUED.search(payload)
        if q and q.group(1).lower() == dest.lower() and stamp is not None and stamp >= after_epoch:
            queued_epoch = stamp
            continue
        m = RESULT.search(payload)
        if not m or queued_epoch is None or stamp is None or stamp < max(after_epoch, queued_epoch):
            continue
        try:
            item = json.loads(m.group(1))
        except (ValueError, TypeError):
            continue
        # Rust пишет в `to` имя текущего выхода, не обязательно destination.
        targets = {dest.lower()}
        if expected_name:
            targets.add(expected_name.lower())
        if isinstance(item, dict) and str(item.get("to", "")).lower() in targets:
            result = item
    return result


def load_exits(path=EXITS_FILE):
    records = {}
    with open(path, encoding="utf-8", errors="replace") as f:
        for n, line in enumerate(f, 1):
            line = line.strip()
            if not line or line.startswith("#"):
                continue
            fields = line.split()
            if len(fields) != 3 or not HEX32.fullmatch(fields[1]):
                raise ValueError(f"{path}:{n}: ожидаются метка dest(32 hex) IP")
            records[fields[0].upper()] = {"label": fields[0].upper(), "dest": fields[1].lower(), "ip": fields[2]}
    return records


def atomic_save(path, doc):
    path = Path(path).expanduser()
    path.parent.mkdir(parents=True, exist_ok=True)
    tmp = path.with_name(path.name + ".tmp")
    with tmp.open("w", encoding="utf-8") as f:
        json.dump(doc, f, ensure_ascii=False, indent=2)
        f.write("\n")
        f.flush()
        os.fsync(f.fileno())
    os.replace(tmp, path)


def shell(serial, command, timeout=ADB_CALL_TIMEOUT):
    return adb(serial, "shell", command, timeout=timeout)


def select_exit(serial, dest):
    rc, out, err = adb(serial, "shell", "am", "start", "-n", ACTIVITY, "--es", "select", dest)
    return rc == 0 and "Error" not in out + err, (out + err).strip()[-400:]


def check_ip(serial, expected):
    # Keep stdin open briefly: Android toybox nc may otherwise see EOF immediately.
    cmd = "(printf 'GET / HTTP/1.0\\r\\nHost: ifconfig.me\\r\\nConnection: close\\r\\n\\r\\n'; sleep 2) | toybox nc -w 5 ifconfig.me 80"
    try:
        rc, out, err = shell(serial, cmd, timeout=12)
    except (subprocess.TimeoutExpired, OSError) as e:
        return {"seen": None, "ok": None, "error": str(e)}
    candidates = re.findall(r"(?m)^\s*((?:\d{1,3}\.){3}\d{1,3})\s*$", out)
    seen = candidates[-1] if candidates else None
    return {"seen": seen, "ok": seen == expected if seen else False,
            "error": (err.strip()[-200:] if rc and not seen else None)}


def last_edges(text):
    rows = [line.strip() for line in text.splitlines() if "EDGES " in line]
    if not rows:
        return None
    line = rows[-1]
    # Keep only compact edge state, not unrelated logcat content.
    m = re.search(r"EDGES\s+.*", line)
    return m.group(0)[:500] if m else None


def print_table(results):
    print(f"{'exit':<5} {'dest':<8} {'МБ/с':>8} {'пак/с':>9} {'потеряно':>9} {'RTT idle':>9} {'вердикт'}")
    for r in results:
        b = r.get("bench_result") or {}
        fmt = lambda v: "—" if v is None else str(v)
        print(f"{r['label']:<5} {r['dest'][:8]:<8} {fmt(b.get('mbps')):>8} {fmt(b.get('pps')):>9} "
              f"{fmt(b.get('pkts_lost')):>9} {fmt(b.get('rtt_ms_idle')):>9} {r['verdict']}")


def main(argv=None):
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--run", action="store_true", help="явно подтвердить запуск ручного теста 100 МБ на каждом выбранном выходе")
    ap.add_argument("--exits", default="RU", help="метки через запятую (по умолчанию только RU)")
    ap.add_argument("--serial", help="adb serial; без него adb должен видеть ровно одно устройство")
    ap.add_argument("--out", help="JSON; по умолчанию ~/.cache/rawg-bench/mesh-<время>.json")
    ap.add_argument("--check-ip", action="store_true", help="перед тестом проверить внешний IPv4 через ifconfig.me")
    args = ap.parse_args(argv)
    try:
        catalog = load_exits()
    except (OSError, ValueError) as e:
        ap.error(str(e))
    names = [x.strip().upper() for x in args.exits.split(",") if x.strip()]
    if not names or len(set(names)) != len(names):
        ap.error("--exits должен содержать уникальные метки")
    unknown = [n for n in names if n not in catalog]
    if unknown:
        ap.error("неизвестные выходы: " + ", ".join(unknown))
    exits = [catalog[n] for n in names]
    stamp = dt.datetime.now().strftime("%Y%m%d-%H%M%S")
    out = args.out or str(Path.home() / ".cache/rawg-bench" / f"mesh-{stamp}.json")
    doc = {"started": dt.datetime.now().astimezone().isoformat(), "mode": "run" if args.run else "dry-run",
           "requested_mb_each": MB, "planned_mb": MB * len(exits), "serial": args.serial,
           "results": []}
    print(f"План: {MB} МБ × {len(exits)} выход(а) = {doc['planned_mb']} МБ" +
          ("; запуск разрешён флагом --run." if args.run else "; dry-run: интенты не отправляются."))
    if not args.run:
        print("Для реального кнопочного теста 100 МБ повторите команду с --run.")
        atomic_save(out, doc)
        print(f"JSON: {out}")
        return 0

    interrupted = False
    try:
        for ex in exits:
            row = {"label": ex["label"], "dest": ex["dest"], "expected_ip": ex["ip"],
                   "verdict": "unavailable", "started": dt.datetime.now().astimezone().isoformat(), "vis": None}
            doc["results"].append(row)
            atomic_save(out, doc)
            try:
                rc, _, _ = adb(args.serial, "logcat", "-c", timeout=10)
                if rc:
                    row["error"] = "logcat -c failed"
                    continue
                ok, detail = select_exit(args.serial, ex["dest"])
                if not ok:
                    row["error"] = "select intent failed: " + detail
                    continue
                deadline = time.monotonic() + SELECT_TIMEOUT
                selected = False
                selected_name = None
                while time.monotonic() < deadline:
                    _, logs, _ = adb(args.serial, "logcat", "-d", "-v", "epoch", "-s", "rawgui",
                                     timeout=min(10, max(1, deadline - time.monotonic())))
                    row["vis"] = last_edges(logs)
                    selected_name = find_current(logs, ex["dest"][:8])
                    if selected_name:
                        selected = True
                        break
                    time.sleep(1)
                if not selected:
                    row["error"] = f"current output {ex['dest'][:8]} not confirmed within {SELECT_TIMEOUT}s"
                    continue
                row["selected"] = True
                atomic_save(out, doc)
                if args.check_ip:
                    row["ip_check"] = check_ip(args.serial, ex["ip"])
                    atomic_save(out, doc)
                    if row["ip_check"]["ok"] is not True:
                        row["verdict"] = "ip-mismatch"
                        row["error"] = "external IP not confirmed; test skipped"
                        continue

                # Clear logs immediately before intent; queued marker must then precede result.
                rc, _, _ = adb(args.serial, "logcat", "-c", timeout=10)
                if rc:
                    row["error"] = "logcat -c before bench failed"
                    continue
                # logcat использует часы телефона: часы ноутбука могут отличаться.
                rc, device_epoch, _ = adb(args.serial, "shell", "date", "+%s", timeout=10)
                if rc or not device_epoch.strip().isdigit():
                    row["error"] = "cannot read device clock; test skipped"
                    continue
                started_epoch = int(device_epoch.strip())
                row["bench_started_epoch"] = started_epoch
                atomic_save(out, doc)
                rc, stdout, stderr = adb(args.serial, "shell", "am", "start", "-n", ACTIVITY,
                                         "--ei", "bench_mb", "100", timeout=20)
                if rc or "Error" in stdout + stderr:
                    row["verdict"] = "intent-failed"
                    row["error"] = (stdout + stderr).strip()[-400:]
                    continue
                deadline = time.monotonic() + BENCH_TIMEOUT
                while time.monotonic() < deadline:
                    _, logs, _ = adb(args.serial, "logcat", "-d", "-v", "epoch", "-s", "rawgui",
                                     timeout=min(10, max(1, deadline - time.monotonic())))
                    row["vis"] = last_edges(logs) or row["vis"]
                    low = logs.lower()
                    if "bench rejected" in low:
                        row["verdict"] = "rejected"
                        row["error"] = next((x.strip() for x in logs.splitlines() if "bench rejected" in x.lower()), "lab rejected")
                        break
                    result = parse_result_logs(logs, ex["dest"], started_epoch, selected_name)
                    if result is not None:
                        row["bench_result"] = result
                        row["verdict"] = str(result.get("verdict", "complete"))
                        break
                    time.sleep(2)
                else:
                    row["verdict"] = "timeout"
                    row["error"] = f"no fresh BENCH_RESULT within {BENCH_TIMEOUT}s; app's test timeout is internal"
            except (subprocess.TimeoutExpired, OSError) as e:
                row["error"] = f"adb error: {e}"
            finally:
                row["finished"] = dt.datetime.now().astimezone().isoformat()
                atomic_save(out, doc)
    except KeyboardInterrupt:
        interrupted = True
        doc["interrupted"] = True
        try:
            select_exit(args.serial, "auto")
        except (subprocess.TimeoutExpired, OSError):
            pass
    finally:
        try:
            select_exit(args.serial, "auto")
        except (subprocess.TimeoutExpired, OSError):
            pass
        doc["finished"] = dt.datetime.now().astimezone().isoformat()
        doc["interrupted"] = interrupted
        atomic_save(out, doc)
    print_table(doc["results"])
    print(f"JSON: {out}")
    return 130 if interrupted else 0


if __name__ == "__main__":
    sys.exit(main())
