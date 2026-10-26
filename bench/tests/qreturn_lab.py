#!/usr/bin/env python3
"""Измерение возврата TCP -> QUIC (этапы A/B make-before-break) в изолированной Docker-лаборатории lab13.

Только локально: своя --internal сеть, публичная RNS не затрагивается. Бинарники берутся как есть (bind-mount), ничего не собирается и не копируется.

  qreturn_lab.py run --server BIN --client BIN --mode clean|loss50 --tag NAME [--secs N]

Сценарий: клиент соединён с выходом по QUIC; на клиенте UDP до выхода режется целиком (монитор переводит на TCP); через `--unblock-at` секунд
UDP возвращается (clean) или остаётся с потерей 50% (loss50). Всё время идёт размеренный UDP-поток 50 пакетов/с по 200 Б клиент -> «сайт» -> клиент
через туннель (не burst). Результат: потери, RTT, самый длинный разрыв между ответами в окне возврата, строки журнала клиента о возврате.
"""
import argparse
import json
import os
import subprocess
import sys
import time
from pathlib import Path

HERE = Path(__file__).resolve().parent
LAB13 = HERE.parent / "android/lab13.py"
PREFIX = "qret"
NET = f"{PREFIX}-net"
SUBNET = "172.29.98.0/24"
ADM_IP = "172.29.98.11"
SITE_IP = "172.29.98.50"
# Выход требует host-acl.json; частные адреса ACL закрыты, поэтому «интернет» - публичный адрес на lo контейнера сайта (как в lxmf_host_access_e2e)
INET = "1.1.1.1"
NODE_PRE = ("printf '%s' '{\"version\":1,\"aliases\":[],\"allow\":[]}' > /state/host-acl.json; chmod 600 /state/host-acl.json; "
            f"ip route replace {INET}/32 via {SITE_IP}; ")
ROOT = Path.home() / ".cache/knothop-qret-lab"
PPS, SIZE = 50, 200

ECHO = r'''
import socket
s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
s.bind(("1.1.1.1", 9000))
while True:
    d, a = s.recvfrom(2048)
    s.sendto(d, a)
'''

STREAM = r'''
import json, socket, struct, sys, threading, time
site, pps, size, secs = sys.argv[1], int(sys.argv[2]), int(sys.argv[3]), float(sys.argv[4])
s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
s.bind(("0.0.0.0", 0))
s.settimeout(0.2)
sent, got = {}, {}
stop = False
def rx():
    while not stop:
        try:
            d, _ = s.recvfrom(2048)
        except socket.timeout:
            continue
        except OSError:
            return
        if len(d) >= 16:
            seq, ts = struct.unpack("!Qd", d[:16])
            got.setdefault(seq, (time.time(), ts))
t = threading.Thread(target=rx, daemon=True); t.start()
t0 = time.time(); n = 0
while time.time() - t0 < secs:
    now = time.time()
    s.sendto(struct.pack("!Qd", n, now).ljust(size, b"x"), (site, 9000))
    sent[n] = now; n += 1
    nxt = t0 + n / pps
    time.sleep(max(0, nxt - time.time()))
time.sleep(2); stop = True
json.dump({"sent": n, "t0": t0, "rx": [[q, v[0], (v[0] - v[1]) * 1000] for q, v in sorted(got.items())]}, open("/state/udp.json", "w"))
'''


def sh(*a, env=None, check=True, inp=None):
    r = subprocess.run(a, capture_output=True, text=True, env=env, input=inp)
    if check and r.returncode:
        sys.exit(f"{' '.join(a[:6])}: {(r.stderr or r.stdout).strip()[-600:]}")
    return r


def lab(args, bin_path, client_env=""):
    env = dict(os.environ, LAB_CLIENT_ENV=client_env, LAB_NODE_ENV=NODE_PRE, LAB13_PREFIX=PREFIX, LAB13_ROOT=str(ROOT / "state"), LAB13_SUBNET=SUBNET, KNOTHOP_BIN=str(bin_path))
    return sh(sys.executable, str(LAB13), *args, env=env)


def dx(name, *cmd, **kw):
    return sh("docker", "exec", *kw.pop("opts", []), f"{PREFIX}-{name}" if name in ("hub", "site", "adm") else name, *cmd, **kw)


def clog(name="cl"):
    r = sh("docker", "exec", name, "cat", "/state/client.log", check=False)
    return r.stdout.splitlines()


def teardown():
    names = sh("docker", "ps", "-a", "--filter", f"network={NET}", "--format", "{{.Names}}", check=False).stdout.split()
    for n in names:
        sh("docker", "rm", "-f", n, check=False)
    sh("docker", "network", "rm", NET, check=False)
    # state лаборатории создан этим скриптом: удаляем из контейнера (владелец root), каталоги вне ROOT не трогаем
    if (ROOT / "state").exists():
        sh("docker", "run", "--rm", "-v", f"{ROOT}:/l", "--entrypoint", "rm", "knothop-bench:l3", "-rf", "/l/state")


def stats(d, win):
    rx = d["rx"]
    sent = d["sent"]
    t0 = d["t0"]
    res = {"sent": sent, "received": len(rx), "loss_pct": round(100 * (1 - len(rx) / max(sent, 1)), 2)}
    rtt = sorted(r[2] for r in rx)
    if rtt:
        res["rtt_ms"] = {"p50": round(rtt[len(rtt) // 2], 1), "p99": round(rtt[int(len(rtt) * 0.99)], 1), "max": round(rtt[-1], 1)}
    if win:
        a, b = win
        sel = [r for r in rx if a <= r[1] <= b]
        gaps = sorted(((y[1] - x[1]), x[1] - t0) for x, y in zip(sel, sel[1:]))
        exp = int((b - a) * PPS)
        res["window"] = {"secs": round(b - a, 1), "expected_pkts": exp, "received": len(sel), "loss_pct": round(100 * (1 - len(sel) / max(exp, 1)), 2),
                         "max_gap_s": round(gaps[-1][0], 3) if gaps else None, "max_gap_at_s": round(gaps[-1][1], 1) if gaps else None}
    return res


def main():
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    sp = ap.add_subparsers(dest="c", required=True)
    r = sp.add_parser("run")
    r.add_argument("--server", required=True, type=Path)
    r.add_argument("--client", required=True, type=Path)
    r.add_argument("--mode", choices=("clean", "loss50"), default="clean")
    r.add_argument("--tag", required=True)
    r.add_argument("--client-env", default="", help="префикс окружения клиента, например KNOTHOP_LAB_RET_B_FAIL=1 (лабораторный отказ B)")
    r.add_argument("--secs", type=int, default=480)
    r.add_argument("--block-at", type=int, default=20)
    r.add_argument("--kill-quic-at-b", action="store_true", help="как только клиент начал перенос B, снова резать UDP до выхода (QUIC умирает во время B)")
    r.add_argument("--unblock-at", type=int, default=75)
    sp.add_parser("down")
    a = ap.parse_args()
    if a.c == "down":
        teardown()
        return
    for p in (a.server, a.client):
        if not p.exists():
            sys.exit(f"нет {p}")
    ROOT.mkdir(parents=True, exist_ok=True)
    os.chmod(ROOT, 0o700)
    teardown()
    sh("docker", "network", "create", "--internal", "--subnet", SUBNET, "--label", "knothop.qret=1", NET)
    try:
        lab(["up"], a.server)
        sh("docker", "exec", f"{PREFIX}-site", "ip", "addr", "add", f"{INET}/32", "dev", "lo")
        # клиент с другим бинарём (старый сервер + новый клиент и наоборот)
        lab(["client", "cl", "--from", f"{PREFIX}-adm"], a.client, client_env=(a.client_env + " ") if a.client_env else "")
        deadline = time.time() + 90
        while time.time() < deadline:
            if sh("docker", "exec", "cl", "ip", "link", "show", "tun0", check=False).returncode == 0:
                sh("docker", "exec", "cl", "ip", "route", "replace", f"{INET}/32", "dev", "tun0")
                if sh("docker", "exec", "cl", "curl", "-s", "-m", "3", f"http://{INET}/", check=False).stdout.strip():
                    break
            time.sleep(1)
        else:
            sys.exit("туннель не поднялся за 90 с")
        (ROOT / "echo.py").write_text(ECHO)
        sh("docker", "cp", str(ROOT / "echo.py"), f"{PREFIX}-site:/tmp/echo.py")
        sh("docker", "exec", "-d", f"{PREFIX}-site", "python3", "/tmp/echo.py")
        (ROOT / "stream.py").write_text(STREAM)
        sh("docker", "cp", str(ROOT / "stream.py"), "cl:/tmp/stream.py")
        t0 = time.time()
        sh("docker", "exec", "-d", "cl", "python3", "/tmp/stream.py", INET, str(PPS), str(SIZE), str(a.secs))
        print(f"[{a.tag}] поток запущен, {a.secs} с", flush=True)
        time.sleep(a.block_at)
        blk = ["iptables", "-I", "OUTPUT", "-p", "udp", "-d", ADM_IP, "-j", "DROP"]
        sh("docker", "exec", "cl", *blk)
        tb = time.time()
        print(f"[{a.tag}] UDP заблокирован (t={tb - t0:.0f} с)", flush=True)
        time.sleep(max(0, a.unblock_at - a.block_at))
        sh("docker", "exec", "cl", "iptables", "-D", "OUTPUT", "-p", "udp", "-d", ADM_IP, "-j", "DROP")
        tu = time.time()
        if a.mode == "loss50":
            sh("docker", "exec", "cl", "iptables", "-I", "OUTPUT", "-p", "udp", "-d", ADM_IP, "-m", "statistic", "--mode", "random", "--probability", "0.5", "-j", "DROP")
        print(f"[{a.tag}] UDP открыт ({a.mode}) (t={tu - t0:.0f} с)", flush=True)
        if a.kill_quic_at_b:
            end = t0 + a.secs - 20
            while time.time() < end:
                if any("проверка выхода: возврат на QUIC" in l for l in clog()):
                    sh("docker", "exec", "cl", *blk)
                    print(f"[{a.tag}] B начат, UDP снова заблокирован (t={time.time() - t0:.0f} с)", flush=True)
                    break
                time.sleep(0.2)
        time.sleep(max(0, a.secs + 6 - (time.time() - t0)))
        out = sh("docker", "exec", "cl", "cat", "/state/udp.json", check=False).stdout
        if not out:
            sys.exit("нет udp.json")
        d = json.loads(out)
        log = clog()
        key = ("зонд QUIC", "возврат", "восстанов", "лаборатор", "перенос", "Link поднят на QUIC", "QUIC", "TCP", "carrier", "носител")
        rel = [l for l in log if any(k in l for k in key)]
        res = {"tag": a.tag, "server": str(a.server), "client": str(a.client), "mode": a.mode, "secs": a.secs, "pps": PPS, "size": SIZE,
               "t_block_s": round(tb - t0, 1), "t_unblock_s": round(tu - t0, 1), "overall": stats(d, None), "log": rel[-60:]}
        # окно возврата: определяется по журналу ниже (после разбора); по умолчанию - всё время после открытия UDP
        res["after_unblock"] = stats(d, (d["t0"] + res["t_unblock_s"], d["t0"] + a.secs))
        ROOT.joinpath(f"result-{a.tag}.json").write_text(json.dumps(res, ensure_ascii=False, indent=1))
        ROOT.joinpath(f"udp-{a.tag}.json").write_text(out)
        print(json.dumps({k: v for k, v in res.items() if k != "log"}, ensure_ascii=False, indent=1))
        print("\n".join(rel[-40:]))
    finally:
        pass


if __name__ == "__main__":
    main()
