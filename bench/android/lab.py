#!/usr/bin/env python3
"""Лабораторная сеть из нескольких узлов rawg перед деплоем (всё в Docker на этом ноутбуке).

  lab.py up [--nodes 3]     хаб («публичная сеть RNS»), серверы n1..nN одной группы, «сайт»; серверы находят друг друга по тегу группы
  lab.py pair [--push]      выдать профиль клиента с n1 (строка rawg1-...), сохранить в ~/.cache/rawg-lab/phone.profile; --push - отправить в приложение по adb
  lab.py status             таблицы соседей всех узлов и реестр клиентов
  lab.py stop NAME / start NAME   остановить / запустить узел (проверка «потерявшийся узел забывается»)
  lab.py down               убрать всё

Топология: клиент (телефон) подключается к серверам по LAN-адресу ноутбука (опубликованные UDP-порты 47011..), серверы между собой - по
сети Docker `rawg-lab`. Хаб стоит между ними только для анонсов и первичной связности; клиентский трафик идёт мимо него.
В каждом сервере: выход в интернет (TUN + NAT), http://10.99.0.1:8080 (кто обслужил) и «сайт» 172.29.99.50 (виден с адреса выхода).
"""
import argparse
import json
import os
import subprocess
import sys
import time
from pathlib import Path

import laptop

HERE = Path(__file__).resolve().parent
LAB = Path.home() / ".cache" / "rawg-lab"
NET = "rawg-lab"
SUBNET = "172.29.99.0/24"
IMAGE = "rawg-bench:l3"
BIN = Path(os.environ.get("RAWGD_BIN", str(Path.home() / ".cache/rawg-target/dgram/release/rawgd")))
GROUP = "lab"
ANNOUNCE_S = 10
CLIENT_NET = "198.18.0.0/15"
FAKE_PUBLIC = False
HUB_IP = "172.29.99.10"
SITE_IP = "172.29.99.50"


def sh(*a, check=True):
    r = subprocess.run(a, capture_output=True, text=True)
    if check and r.returncode:
        sys.exit(f"{' '.join(a[:4])}...: {r.stderr.strip()[-400:]}")
    return r


def node_ip(i):
    return f"172.29.99.{10 + i}"


def run_container(name, ip, cmd, state, extra=()):
    sh("docker", "rm", "-f", name, check=False)
    sh("docker", "run", "-d", "--name", name, "--network", NET, "--ip", ip, "--cap-add", "NET_ADMIN", "--device", "/dev/net/tun",
       "--sysctl", "net.ipv4.ip_forward=1", "-e", "RAWG_DEBUG=1", *(() if os.environ.get("LAB_STRICT") else ("-e", "RAWGD_ALLOW_PRIVATE_DIAL=1")), "-e", "RAWGD_TCP_BACKOFF_S=30", "-v", f"{BIN}:/usr/local/bin/rawgd:ro", "-v", f"{HERE}:/lab:ro", "-v", f"{state}:/state",
       "-v", f"{LAB / 'group.key'}:/secret/group.key:ro", *extra, "--entrypoint", "sh", IMAGE, "-c", cmd)


def lab_nodes():
    return json.loads((LAB / "nodes.json").read_text()) if (LAB / "nodes.json").exists() else []


def start_node(idx, name, hidden, lan_ip, only_ip=None, adv_env=""):
    """Один и тот же конфиг на всех узлах: ни соседей, ни маршрутов, ни собственного адреса. Узлы находят друг друга только по анонсам через «публичный» узел RNS
    (TCP-хаб). Имя - имя хоста контейнера. Единственное отличие узла - переменная RAWGD_ADVERTISE (адрес-имя, если IP динамический, или LAN-адрес для телефона).
    Невидимый напрямую узел: UDP режется, кроме одного соседа (как за NAT/фильтром у провайдера)."""
    state = LAB / name
    state.mkdir(parents=True, exist_ok=True)
    os.chmod(state, 0o777)
    port = 47010 + idx
    conf = {"group": GROUP, "secret_file": "/secret/group.key", "port": 47001, "advertise_private": True,
            "public_rns": [f"{HUB_IP}:4242"], "announce_s": ANNOUNCE_S, "dead_s": 12, "client_net": CLIENT_NET}
    (state / "node.json").write_text(json.dumps(conf, indent=1))
    iso = (f"iptables -A OUTPUT -p udp -d {only_ip} -j ACCEPT; iptables -A OUTPUT -p udp -j DROP; "
           f"iptables -A INPUT -p udp -s {only_ip} -j ACCEPT; iptables -A INPUT -p udp -j DROP; ") if only_ip else ""
    cmd = (iso + "python3 /lab/lab_web.py whoami " + name + " & "
           "iptables -t nat -A POSTROUTING -s " + CLIENT_NET + " ! -o tun0 -j MASQUERADE; "
           # носитель не должен попадать в собственный туннель (журнал N30)
           "iptables -I OUTPUT -d " + CLIENT_NET + " -p udp --sport 47001 -j DROP; "
           "exec rawgd node --state /state --config /state/node.json")
    env = ("-e", f"RAWGD_REGION={name.rstrip('0123456789').upper()[:2]}") + (("-e", f"RAWGD_ADVERTISE={adv_env}") if adv_env else ())
    run_container(name, node_ip(idx), cmd, state, ("--hostname", name, *env, *(("-p", f"{port}:47001/udp", "-p", f"{port}:47001/tcp") if not hidden else ())))


def wait_json(path, secs=25):
    t0 = time.time()
    while not path.exists():
        if time.time() - t0 > secs:
            sys.exit(f"нет {path}")
        time.sleep(0.3)
    return json.loads(path.read_text())


def cmd_up(a):
    global ANNOUNCE_S, FAKE_PUBLIC
    ANNOUNCE_S, FAKE_PUBLIC = a.announce_s, a.fake_public
    if not BIN.exists():
        sys.exit(f"нет {BIN}: соберите bench/build_fork.sh")
    names = [x for x in a.names.split(",") if x]
    hidden = {x for x in a.hidden.split(",") if x}
    LAB.mkdir(parents=True, exist_ok=True)
    if not (LAB / "group.key").exists():
        sh(str(BIN), "keygen", "--out", str(LAB / "group.key"))
    if sh("docker", "network", "inspect", NET, check=False).returncode:
        sh("docker", "network", "create", "--subnet", SUBNET, NET)
    lan_ip = laptop.default_ip()
    hub_state = LAB / "hub"
    hub_state.mkdir(parents=True, exist_ok=True)
    os.chmod(hub_state, 0o777)
    run_container("rawg-hub", HUB_IP, "exec rawgd hub --state /state --port 47000 --tcp-port 4242", hub_state)
    hub_id = wait_json(hub_state / "hub.json")["id"]
    run_container("rawg-site", SITE_IP, "exec python3 /lab/lab_web.py site", LAB / "hub")
    (LAB / "nodes.json").write_text(json.dumps(names))
    via = a.via or (names[0] if names else None)
    for n in names:
        idx = names.index(n) + 1
        hid = n in hidden
        adv = ""
        if n == a.domain_node:
            adv = f"{n}:47001"            # адрес-имя (в Docker имя контейнера разрешается, как домен с динамическим IP)
        elif not hid:
            adv = f"{node_ip(idx)}:47001,{lan_ip}:{47010 + idx}"
        start_node(idx, n, hid, lan_ip, node_ip(names.index(via) + 1) if hid else None, adv)
    print(f"хаб {HUB_IP}, серверы {names} (не видны напрямую: {sorted(hidden) or '-'}; их сосед {via}), сайт {SITE_IP}.")
    print("ждите ~30 с, затем: lab.py status ; lab.py pair --push")


def cmd_pair(a):
    issuer = a.on or lab_nodes()[0]
    out = sh("docker", "exec", issuer, "rawgd", "issue", "--state", "/state", "--client-name", a.client_name, "--servers", str(a.servers),
             *(["--max-addrs", str(a.max_addrs)] if a.max_addrs else []))
    prof = out.stdout.strip()
    print(out.stderr.strip())
    (LAB / "phone.profile").write_text(prof)
    os.chmod(LAB / "phone.profile", 0o600)
    print(f"профиль ({len(prof)} символов) сохранён в {LAB / 'phone.profile'}")
    print(prof)
    if a.push:
        r = subprocess.run(["adb", "shell", "am", "start", "-n", "com.rawg.vpn/.MainActivity", "--es", "profile", prof], capture_output=True, text=True)
        print("отправлено в приложение по adb" if r.returncode == 0 else r.stderr)


def cmd_status(a):
    running = set(sh("docker", "ps", "--format", "{{.Names}}").stdout.split())
    for n in [x for x in lab_nodes() if x in running]:
        r = sh("docker", "exec", n, "cat", "/state/neighbors.json", check=False)
        if r.returncode:
            print(f"{n}: нет таблицы"); continue
        t = json.loads(r.stdout)
        print(f"{n}:")
        for e in t["exits"]:
            tag = "это я" if e.get("self") else f"{e['s']:4s} хопов {e['h']} rtt {('%.1f' % e['r']) if e.get('r') is not None else '-':>5} мс, анонс {e.get('age_s')} с назад, ответ {e.get('heard_s')} с назад"
            print(f"   {e['n']:4s} {e['d'][:8]}  {tag}")
    first = next((x for x in lab_nodes() if x in running), None)
    r = sh("docker", "exec", first, "rawgd", "list", "--state", "/state", check=False) if first else type("R", (), {"stdout": ""})()
    print(r.stdout.split("таблица соседей")[0].strip())


def cmd_stop(a):
    sh("docker", "stop", "-t", "1", a.name)
    print(a.name, "остановлен")


def cmd_start(a):
    sh("docker", "start", a.name)
    print(a.name, "запущен")


def cmd_down(a):
    for n in ["rawg-hub", "rawg-site"] + lab_nodes():
        sh("docker", "rm", "-f", n, check=False)
    sh("docker", "network", "rm", NET, check=False)
    print("убрано (состояние и ключи сохранены в", LAB, ")")


ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
sp = ap.add_subparsers(dest="c", required=True)
x = sp.add_parser("up"); x.add_argument("--names", default="de,ru1,nl1"); x.add_argument("--hidden", default="nl1", help="узлы, не видимые напрямую (через соседа --via)"); x.add_argument("--via", default="de"); x.add_argument("--announce-s", type=int, default=600); x.add_argument("--domain-node", default="ru1", help="узел, адрес которого - имя, а не IP"); x.add_argument("--fake-public", action="store_true"); x.set_defaults(f=cmd_up)
x = sp.add_parser("pair"); x.add_argument("--push", action="store_true"); x.add_argument("--client-name", default="phone"); x.add_argument("--servers", type=int, default=3); x.add_argument("--max-addrs", type=int, default=0); x.add_argument("--on", default=""); x.set_defaults(f=cmd_pair)
x = sp.add_parser("status"); x.set_defaults(f=cmd_status)
x = sp.add_parser("stop"); x.add_argument("name"); x.set_defaults(f=cmd_stop)
x = sp.add_parser("start"); x.add_argument("name"); x.set_defaults(f=cmd_start)
x = sp.add_parser("down"); x.set_defaults(f=cmd_down)
a = ap.parse_args()
a.f(a)
