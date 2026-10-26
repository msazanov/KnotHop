#!/usr/bin/env python3
"""Диагностика пилота knothopd на живых узлах (только чтение, по ssh).

  diag.py [--hosts FILE] state          сервис, соседи, статус, слушатель UDP, счётчики nft, нагрузка, свежий журнал
  diag.py paths                         качество UDP/ICMP между всеми парами узлов: потери и RTT (пинг и пакеты на порт пилота не отправляются, только ICMP)
  diag.py journal [--n 60] [--grep RE]  журнал knothopd со всех узлов
  diag.py udp A B [--secs 20] [--pps 50]  АКТИВНАЯ проба UDP A->B->A по размерам пакетов (на B на ~30 с поднимается эхо на порту 47099; файлов и правил нет)
  diag.py cmd 'КОМАНДА'                 произвольная команда только чтения на всех узлах (проверяется список разрешённых начал)

Список узлов - JSON-файл вне репозитория (по умолчанию ~/.cache/knothop-lab/diag_hosts.json): {"имя": {"ssh": "user@host", "pub": "адрес для пинга", "sudo": "sudo -n "}}.
Ничего не меняет на узлах: никаких записей, рестартов, правил.
"""
import argparse
import json
import re
import subprocess
import sys
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path

SAFE = ("sha256sum /opt/knothop", "systemctl is-active", "systemctl status", "journalctl", "ss ", "cat /opt/knothop/state/", "nft list", "ip ", "uptime", "ping ", "mtr ", "df ", "free ", "uname", "ps ", "top -bn1")


def ssh(h, cmd, t=40):
    r = subprocess.run(["ssh", "-o", "BatchMode=yes", "-o", "ConnectTimeout=8", "-o", "ServerAliveInterval=5", *h["ssh"].split(), cmd], capture_output=True, text=True, timeout=t)
    return (r.stdout + r.stderr).strip()


def load(a):
    return json.loads(Path(a.hosts).expanduser().read_text())


def par(hosts, fn):
    with ThreadPoolExecutor(len(hosts)) as ex:
        return dict(zip(hosts, ex.map(lambda n: fn(n, hosts[n]), hosts)))


def cmd_state(a):
    hosts = load(a)
    st = "/opt/knothop/state"

    def one(n, h):
        s = h["sudo"]
        script = (f"echo '[unit]'; systemctl is-active knothopd; systemctl show knothopd -p NRestarts -p ActiveEnterTimestamp -p MemoryCurrent | tr '\\n' ' '; echo; "
                  f"echo '[udp]'; {s}ss -ulpn 2>/dev/null | grep -E ':47001\\b' | head -3; "
                  f"echo '[load]'; uptime; {s}ps -o pcpu,rss,etime,cmd -C knothopd | cut -c1-110; "
                  f"echo '[neighbors]'; {s}cat {st}/neighbors.json 2>&1 | head -c 3000; echo; "
                  f"echo '[status]'; {s}cat {st}/status.json 2>&1 | head -c 600; echo; "
                  f"echo '[nft knothop]'; {s}nft list table inet knothop 2>&1 | grep -E 'counter|packets' | head; {s}nft list table ip knothop_nat 2>&1 | grep -E 'packets|masq' | head -3; "
                  f"echo '[journal]'; {s}journalctl -u knothopd -n 14 --no-pager -o cat 2>&1 | cut -c1-170")
        return ssh(h, script)

    for n, out in par(hosts, one).items():
        print(f"\n################ {n} ################")
        parts = re.split(r"^\[(.+?)\]$", out, flags=re.M)
        if len(parts) > 1:
            d = dict(zip(parts[1::2], parts[2::2]))
            for k in ("unit", "udp", "load"):
                print(f"[{k}]", d.get(k, "").strip())
            try:
                t = json.loads(d["neighbors"])
                for e in t["exits"]:
                    r = e.get("r")
                    print(f"   сосед {e['n'][:28]:28s} {e['s']:4s} хопов {e['h']} rtt {r if r is None else round(r,1)} мс, анонс {e.get('age_s')} с назад, ответ {e.get('heard_s')} с назад")
            except Exception:
                print("[neighbors]", d.get("neighbors", "").strip()[:300])
            print("[status]", d.get("status", "").strip()[:500])
            print("[nft]", d.get("nft knothop", "").strip())
            print("[journal]\n" + d.get("journal", "").rstrip())
        else:
            print(out)


def cmd_paths(a):
    hosts = load(a)
    pairs = [(x, y) for x in hosts for y in hosts if x != y]

    def one(n, h):
        res = {}
        for y in hosts:
            if y == n:
                continue
            o = ssh(h, f"ping -c 20 -i 0.2 -W 2 -q {hosts[y]['pub']} 2>&1 | tail -3", t=60)
            m = re.search(r"(\d+(?:\.\d+)?)% packet loss", o)
            r = re.search(r"= ([\d.]+)/([\d.]+)/([\d.]+)/([\d.]+)", o)
            res[y] = (m.group(1) + "% потерь" if m else "нет ответа") + (f", rtt min/avg/max {r.group(1)}/{r.group(2)}/{r.group(3)} мс" if r else "")
        return res

    for n, res in par(hosts, one).items():
        for y, v in res.items():
            print(f"{n:4s} -> {y:4s}  ICMP: {v}")
    print("\n(UDP-потери на порту пилота показывает сам knothopd: RTT соседей в neighbors.json; ICMP только ориентир: DPI режет по портам)")


def cmd_journal(a):
    hosts = load(a)
    g = f" | grep -E {json.dumps(a.grep)}" if a.grep else ""
    for n, o in par(hosts, lambda n, h: ssh(h, f"{h['sudo']}journalctl -u knothopd -n {a.n} --no-pager -o cat 2>&1{g} | cut -c1-200")).items():
        print(f"\n################ {n} ################\n{o}")


ECHO = r"""
import socket,sys,time
s=socket.socket(socket.AF_INET6 if ':' in sys.argv[1] else socket.AF_INET,socket.SOCK_DGRAM); s.bind((sys.argv[1],int(sys.argv[2]))); s.settimeout(1); t=time.time()+float(sys.argv[3])
while time.time()<t:
    try: d,a=s.recvfrom(2000); s.sendto(d,a)
    except socket.timeout: pass
"""
SEND = r"""
import socket,sys,time,struct,json
host,port,secs,pps=sys.argv[1],int(sys.argv[2]),float(sys.argv[3]),int(sys.argv[4]); res={}
for size in (100,600,1200,1400,1452):
    s=socket.socket(socket.AF_INET,socket.SOCK_DGRAM); s.settimeout(0.001); s.connect((host,port)); sent={}; rtts=[]; n=0; t0=time.time(); nxt=t0
    pad=b'x'*(size-12)
    while time.time()-t0<secs/5:
        now=time.time()
        if now>=nxt:
            s.send(struct.pack('!Id',n,now)+pad); sent[n]=now; n+=1; nxt+=1.0/pps
        try:
            d=s.recv(2000); q,ts=struct.unpack('!Id',d[:12]); rtts.append(time.time()-ts)
        except Exception: pass
    end=time.time()+1.5
    while time.time()<end:
        try:
            d=s.recv(2000); q,ts=struct.unpack('!Id',d[:12]); rtts.append(time.time()-ts)
        except Exception: pass
    rtts.sort(); k=len(rtts)
    res[size]={'sent':n,'got':k,'loss':round(100*(n-k)/max(n,1),1),'p50':round(rtts[k//2]*1000,1) if k else None,'p95':round(rtts[int(k*.95)-1]*1000,1) if k>1 else None,'max':round(rtts[-1]*1000,1) if k else None}
print(json.dumps(res))
"""


def cmd_udp(a):
    hosts = load(a)
    A, B = hosts[a.a], hosts[a.b]
    port = 47099
    srv = subprocess.Popen(["ssh", "-o", "BatchMode=yes", B["ssh"], f"python3 - 0.0.0.0 {port} {a.secs + 12}"], stdin=subprocess.PIPE, text=True, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    srv.stdin.write(ECHO); srv.stdin.close()
    import time; time.sleep(3)
    out = ssh(A, f"python3 - {B['pub']} {port} {a.secs} {a.pps} <<'PYEOF'\n{SEND}\nPYEOF", t=a.secs + 40)
    srv.wait(timeout=30)
    try:
        r = json.loads(out.splitlines()[-1])
    except Exception:
        print("нет результата:", out[-300:]); return
    print(f"{a.a} -> {a.b} -> {a.a}, {a.pps} пак/с, порт {port}/udp")
    for size, v in r.items():
        print(f"  {size:>5} Б: отправлено {v['sent']:4d}, вернулось {v['got']:4d}, потери {v['loss']:5.1f}%, RTT p50 {v['p50']} p95 {v['p95']} max {v['max']} мс")


TSRV = r"""
import socket,sys,time
s=socket.socket(); s.setsockopt(socket.SOL_SOCKET,socket.SO_REUSEADDR,1); s.bind((sys.argv[1],int(sys.argv[2]))); s.listen(4); s.settimeout(1); t=time.time()+float(sys.argv[3])
while time.time()<t:
    try: c,_=s.accept()
    except socket.timeout: continue
    c.settimeout(10); n=0
    try:
        while True:
            d=c.recv(65536)
            if not d: break
            n+=len(d)
    except Exception: pass
    c.close()
"""
TCLI = r"""
import socket,sys,time,json
t0=time.time(); s=socket.create_connection((sys.argv[1],int(sys.argv[2])),timeout=8); conn=time.time()-t0
buf=b'x'*65536; n=0; t1=time.time()
while time.time()-t1<float(sys.argv[3]): s.sendall(buf); n+=len(buf)
s.shutdown(socket.SHUT_WR); dt=time.time()-t1
print(json.dumps({'connect_ms':round(conn*1000),'mbit':round(n*8/dt/1e6,1),'secs':round(dt,1)}))
"""


def cmd_tcp(a):
    hosts = load(a)
    A, B = hosts[a.a], hosts[a.b]
    port = 47099
    srv = subprocess.Popen(["ssh", "-o", "BatchMode=yes", B["ssh"], f"python3 - 0.0.0.0 {port} {a.secs + 12}"], stdin=subprocess.PIPE, text=True, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    srv.stdin.write(TSRV); srv.stdin.close()
    import time; time.sleep(3)
    out = ssh(A, f"python3 - {B['pub']} {port} {a.secs} <<'PYEOF'\n{TCLI}\nPYEOF", t=a.secs + 40)
    srv.wait(timeout=30)
    print(f"TCP {a.a} -> {a.b}: {out.splitlines()[-1] if out else 'нет результата'}")


def cmd_cmd(a):
    if not a.command.startswith(SAFE):
        sys.exit("команда не из списка только-чтение: " + ", ".join(SAFE))
    if re.search(r"[;&|`$><]", a.command.split("|")[0]) and "|" not in a.command:
        sys.exit("без составных команд")
    hosts = load(a)
    for n, o in par(hosts, lambda n, h: ssh(h, h["sudo"] + a.command)).items():
        print(f"\n################ {n} ################\n{o}")


ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
ap.add_argument("--hosts", default="~/.cache/knothop-lab/diag_hosts.json")
sp = ap.add_subparsers(dest="c", required=True)
sp.add_parser("state").set_defaults(f=cmd_state)
x = sp.add_parser("tcp"); x.add_argument("a"); x.add_argument("b"); x.add_argument("--secs", type=int, default=8); x.set_defaults(f=cmd_tcp)
sp.add_parser("paths").set_defaults(f=cmd_paths)
x = sp.add_parser("udp"); x.add_argument("a"); x.add_argument("b"); x.add_argument("--secs", type=int, default=20); x.add_argument("--pps", type=int, default=50); x.set_defaults(f=cmd_udp)
x = sp.add_parser("journal"); x.add_argument("--n", type=int, default=60); x.add_argument("--grep", default=""); x.set_defaults(f=cmd_journal)
x = sp.add_parser("cmd"); x.add_argument("command"); x.set_defaults(f=cmd_cmd)
a = ap.parse_args()
a.f(a)
