#!/usr/bin/env python3
"""Лаборатория модели 0013 (приглашения и права) в Docker. Легаси-лаборатория - lab.py, здесь с ней ничего общего нет.

  lab13.py up [--phone]               (--phone: порт adm виден в LAN) сеть, «публичная RNS» (хаб), «сайт», нода adm (сама себе админ, с выходом)
  lab13.py node NAME [--rights relay] [--from adm] [--only-ip IP]
                                      приглашение с ноды --from (права по умолчанию relay), запуск ноды NAME по нему;
                                      --only-ip: UDP режется, кроме одного соседа (как за NAT)
  lab13.py client NAME [--from adm] [--rights user] [--nodes H1,H2]  (--nodes: identity-хеши входных нод приглашения)
                                      то же для клиента с TUN: ходит на «сайт» и в whoami через выход
  lab13.py restart NAME               перезапуск контейнера (состояние и identity сохраняются, приглашение игнорируется)
  lab13.py wipe NAME                  удалить контейнер вместе с состоянием (переустановка)
  lab13.py list [NAME]                rawgd list на ноде (права, записи, приглашения)
  lab13.py test NAME                  с клиента: curl «сайта» и whoami через туннель
  lab13.py logs NAME [N]              хвост журнала
  lab13.py down                       убрать контейнеры и сеть (состояние остаётся в ~/.cache/rawg-lab13/lab)

Топология: сеть rawg-lab13 172.29.98.0/24, хаб .10 (TCP 4242 изображает публичный узел RNS), «сайт» .50, ноды с .11.
Бинарь - отладочная сборка из bench/rns-iroh-node/target/debug/rawgd (RAWGD_BIN переопределяет).
"""
import argparse
import laptop
import os
import re
import subprocess
import sys
import time
from pathlib import Path

HERE = Path(__file__).resolve().parent
# Имя попадает в имена контейнеров, каталоги state и аргументы rm -rf: только безопасный набор символов.
NAME_RE = re.compile(r"^[a-z][a-z0-9-]{0,30}$")
BIN = Path(os.environ.get("RAWGD_BIN", str(HERE.parent / "rns-iroh-node/target/debug/rawgd")))
# Отдельный префикс позволяет запускать сценарии на изолированной сети, не затрагивая rawg-lab13.
PREFIX = os.environ.get("LAB13_PREFIX", "")
LAB = Path(os.environ.get("LAB13_ROOT", str(Path.home() / ".cache/rawg-lab13/lab")))
IMAGE = "rawg-bench:l3"
NET = f"{PREFIX}-net" if PREFIX else "rawg-lab13"
SUBNET = os.environ.get("LAB13_SUBNET", "172.29.98.0/24")
HUB_NAME = f"{PREFIX}-hub" if PREFIX else "l13-hub"
SITE_NAME = f"{PREFIX}-site" if PREFIX else "l13-site"
ADM_NAME = f"{PREFIX}-adm" if PREFIX else "adm"
HUB_IP, SITE_IP = "172.29.98.10", "172.29.98.50"
CLIENT_NET = "198.18.0.0/15"
PHONE_PORT = 47011
HUB_LAN_PORT = 4243   # хаб «публичной RNS» на LAN-адресе ноутбука (для телефона)


def sh(*a, check=True):
    r = subprocess.run(a, capture_output=True, text=True)
    if check and r.returncode:
        sys.exit(f"{' '.join(a[:5])}...: {(r.stderr or r.stdout).strip()[-600:]}")
    return r


def ip_of(name):
    return sh("docker", "inspect", "-f", f"{{{{(index .NetworkSettings.Networks \"{NET}\").IPAddress}}}}", name).stdout.strip()


def next_ip():
    used = set()
    for n in sh("docker", "ps", "-a", "--filter", f"network={NET}", "--format", "{{.Names}}").stdout.split():
        used.add(ip_of(n))
    for i in range(11, 200):
        ip = f"172.29.98.{i}"
        if ip not in used and ip not in (HUB_IP, SITE_IP):
            return ip
    sys.exit("нет свободных адресов")


def run(name, ip, cmd, state, extra=()):
    sh("docker", "rm", "-f", name, check=False)
    sh("docker", "run", "-d", "--name", name, "--hostname", name, "--network", NET, "--ip", ip, "--cap-add", "NET_ADMIN", "--device", "/dev/net/tun",
       "--sysctl", "net.ipv4.ip_forward=1", "-e", "RAWG_DEBUG=1", "-e", "RAWGD_ALLOW_PRIVATE_DIAL=1", "-e", "RAWGD_TCP_BACKOFF_S=30",
       "-v", f"{BIN}:/usr/local/bin/rawgd:ro", "-v", f"{HERE}:/lab:ro", "-v", f"{state}:/state", *extra, "--entrypoint", "sh", IMAGE, "-c", cmd)


def valid_name(s):
    if not NAME_RE.fullmatch(s):
        raise argparse.ArgumentTypeError(f"имя '{s}': нужно ^[a-z][a-z0-9-]{{0,30}}$")
    return s


def state_dir(name):
    # 0700 достаточно: контейнер пишет в bind-mount как root (без userns-remap это root хоста, DAC обходится),
    # а владелец каталога - пользователь лаборатории. 0777 давало любому локальному пользователю подмену identity/trust.
    LAB.mkdir(parents=True, exist_ok=True)
    os.chmod(LAB, 0o700)
    d = LAB / name
    d.mkdir(parents=True, exist_ok=True)
    os.chmod(d, 0o700)
    return d


def write_private(path, text):
    """Приглашение создаётся сразу с 0600 (без окна, когда файл читается другими); fchmod снимает старые права."""
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
    with os.fdopen(fd, "w") as f:
        os.fchmod(fd, 0o600)
        f.write(text)


def isolate(only_ip):
    if not only_ip:
        return ""
    return (f"iptables -A OUTPUT -p udp -d {only_ip} -j ACCEPT; iptables -A OUTPUT -p udp -j DROP; "
            f"iptables -A INPUT -p udp -s {only_ip} -j ACCEPT; iptables -A INPUT -p udp -j DROP; ")


def node_cmd(name, ip, only_ip, has_invite, lan="", auto_adv=False):
    inv = " --invite-file /state/invite.txt" if has_invite else ""
    # auto_adv: адрес не задан явно, нода берёт его с интерфейса и перепроверяет (0014 R4: смена IP)
    adv = " --advertise-private" if auto_adv else f" --advertise {ip}:47001{lan}"
    return (isolate(only_ip) + f"python3 /lab/lab_web.py whoami {name} & "
            f"iptables -t nat -A POSTROUTING -s {CLIENT_NET} ! -o tun0 -j MASQUERADE; "
            # носитель не должен попадать в собственный туннель (журнал N30)
            f"iptables -I OUTPUT -d {CLIENT_NET} -p udp --sport 47001 -j DROP; "
            f"{os.environ.get('LAB_NODE_ENV', '')}rawgd node --state /state --name {name} --port 47001{adv} --public-rns-file /state/pub.txt --announce-s 10{inv}{os.environ.get('LAB_NODE_EXTRA', '')} 2>&1 | tee -a /state/node.log")


def client_cmd(only_ip, has_invite=True):
    inv = " --invite-file /state/invite.txt" if has_invite else ""
    return (isolate(only_ip) + f"rawgd client --state /state{inv} --public-rns-file /state/pub.txt >> /state/client.log 2>&1 & "
            "until ip link show tun0 >/dev/null 2>&1; do sleep 0.3; done; "
            f"ip route add {SITE_IP}/32 dev tun0; ip route add 10.99.0.1/32 dev tun0; wait")


def write_pub(d):
    (d / "pub.txt").write_text(f"{HUB_IP}:4242\n")


def wait_file(c, path, secs=40):
    t0 = time.time()
    while sh("docker", "exec", c, "test", "-f", path, check=False).returncode:
        if time.time() - t0 > secs:
            sys.exit(f"{c}: нет {path}")
        time.sleep(0.5)


def cmd_up(a):
    if not BIN.exists():
        sys.exit(f"нет {BIN}: cargo build --bin rawgd в bench/rns-iroh-node")
    if sh("docker", "network", "inspect", NET, check=False).returncode:
        sh("docker", "network", "create", "--subnet", SUBNET, NET)
    hub = state_dir("hub")
    hub_pub = ("-p", f"{HUB_LAN_PORT}:4242/tcp") if a.phone else ()
    run(HUB_NAME, HUB_IP, "exec rawgd hub --state /state --port 47000 --tcp-port 4242", hub, hub_pub)
    run(SITE_NAME, SITE_IP, "exec python3 /lab/lab_web.py site", hub)
    if a.no_adm:
        print(f"хаб {HUB_IP}, сайт {SITE_IP}; adm не запущен")
        return
    d = state_dir("adm")
    write_pub(d)
    ip = next_ip()
    lan_ip = laptop.default_ip() if a.phone else ""
    lan = f",{lan_ip}:{PHONE_PORT}" if a.phone else ""
    pub = ("-p", f"{PHONE_PORT}:47001/udp", "-p", f"{PHONE_PORT}:47001/tcp") if a.phone else ()
    run(ADM_NAME, ip, node_cmd("adm", ip, None, False, lan), d, pub)
    wait_file(ADM_NAME, "/state/server.json")
    print(f"хаб {HUB_IP}, сайт {SITE_IP}, adm {ip} (сам себе админ, выход включён)")


def make_invite(src, rights, label, nodes="", root=""):
    extra = ["--nodes", nodes] if nodes else []
    root_arg = ["--root", root] if root else []
    # Приглашение не попадает в stdout/логи/argv: rawgd пишет его в файл с mode 0600.
    path = f"/state/.invite-{os.getpid()}"
    sh("docker", "exec", src, "rawgd", "invite", "--state", "/state", "--rights", rights,
       "--label", label, "--out", path, *root_arg, *extra)
    try:
        r = sh("docker", "exec", src, "cat", path)
        return r.stdout.strip()
    finally:
        sh("docker", "exec", src, "shred", "-u", path, check=False)


def cmd_node(a):
    d = state_dir(a.name)
    write_pub(d)
    if a.invite_file:
        inv = Path(a.invite_file).read_text().strip()
    else:
        inv = a.invite or make_invite(a.src, a.rights, a.name, root=a.root)
    write_private(d / "invite.txt", inv)
    ip = next_ip()
    lan, pub = "", ()
    if a.phone_port:
        lan = f",{laptop.default_ip()}:{a.phone_port}"
        pub = ("-p", f"{a.phone_port}:47001/udp", "-p", f"{a.phone_port}:47001/tcp")
    run(a.name, ip, node_cmd(a.name, ip, a.only_ip, True, lan, a.auto_adv), d, pub)
    print(f"нода {a.name} {ip} запущена по приглашению от {a.src} (права {a.rights})")


def cmd_client(a):
    d = state_dir(a.name)
    write_pub(d)
    if a.invite_file:
        inv = Path(a.invite_file).read_text().strip()
    else:
        inv = make_invite(a.src, a.rights, a.name, getattr(a, "nodes", ""), a.root)
    write_private(d / "invite.txt", inv)
    run(a.name, next_ip(), client_cmd(a.only_ip), d)
    print(f"клиент {a.name} запущен по приглашению от {a.src} (права {a.rights}); проверка: lab13.py test {a.name}")


def cmd_admin(a):
    """Клиент без приглашения: сам себе админ, как телефон до первого сервера. Приглашения для нод: node NAME --from <этот>."""
    d = state_dir(a.name)
    write_pub(d)
    run(a.name, next_ip(), client_cmd("", False), d)
    wait_file(a.name, "/state/identity.key")
    print(f"админ-клиент {a.name} запущен без приглашения")


def cmd_restart(a):
    sh("docker", "restart", "-t", "1", a.name)
    print(a.name, "перезапущен")


def cmd_wipe(a):
    if not NAME_RE.fullmatch(a.name or ""):
        sys.exit("wipe: недопустимое имя, state не трогаю")
    sh("docker", "rm", "-f", a.name, check=False)
    sh("docker", "run", "--rm", "-v", f"{LAB}:/l", "--entrypoint", "rm", IMAGE, "-rf", f"/l/{a.name}")
    print(a.name, "удалён вместе с состоянием")


def cmd_list(a):
    print(sh("docker", "exec", a.name, "rawgd", "list", "--state", "/state").stdout.split("таблица соседей")[0].strip())


def cmd_test(a):
    for u in (f"http://{SITE_IP}/", "http://10.99.0.1:8080/"):
        r = sh("docker", "exec", a.name, "curl", "-s", "-m", "8", u, check=False)
        print(u, "->", r.stdout.strip() or f"нет ответа ({r.returncode})")


def cmd_logs(a):
    for f in ("node.log", "client.log"):
        r = sh("docker", "exec", a.name, "tail", "-n", str(a.n), f"/state/{f}", check=False)
        if r.returncode == 0:
            print(r.stdout)


def cmd_down(a):
    names = sh("docker", "ps", "-a", "--filter", f"network={NET}", "--format", "{{.Names}}").stdout.split()
    for n in names:
        sh("docker", "rm", "-f", n, check=False)
    sh("docker", "network", "rm", NET, check=False)
    print("убрано; состояние в", LAB)


ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
sp = ap.add_subparsers(dest="c", required=True)
x = sp.add_parser("up"); x.add_argument("--phone", action="store_true", help="опубликовать порт adm на LAN-адресе ноутбука для телефона"); x.add_argument("--no-adm", action="store_true", help="без ноды adm (админом будет клиент: lab13.py admin NAME)"); x.set_defaults(f=cmd_up)
for nm, fn, rt in (("node", cmd_node, "relay"), ("client", cmd_client, "user")):
    x = sp.add_parser(nm); x.add_argument("name", type=valid_name); x.add_argument("--rights", default=rt); x.add_argument("--from", dest="src", type=valid_name, default=ADM_NAME); x.add_argument("--root", default=""); x.add_argument("--only-ip", default=""); x.add_argument("--nodes", default="")
    x.add_argument("--invite", default="", help="готовое приглашение rawgi-… (например, из приложения на телефоне) вместо выдачи с контейнера --from")
    x.add_argument("--invite-file", default="", help="файл с готовым приглашением (предпочтительно; секрет не передаётся в argv)")
    x.add_argument("--phone-port", type=int, default=0, help="опубликовать порт ноды на LAN-адресе ноутбука и объявить его (для телефона)")
    x.add_argument("--auto-adv", action="store_true", help="без --advertise: адрес с интерфейса, перепроверка раз в 60 с (смена IP)"); x.set_defaults(f=fn)
for nm, fn in (("admin", cmd_admin), ("restart", cmd_restart), ("wipe", cmd_wipe), ("test", cmd_test)):
    x = sp.add_parser(nm); x.add_argument("name", type=valid_name); x.set_defaults(f=fn)
x = sp.add_parser("list"); x.add_argument("name", nargs="?", type=valid_name, default="adm"); x.set_defaults(f=cmd_list)
x = sp.add_parser("logs"); x.add_argument("name", type=valid_name); x.add_argument("n", nargs="?", type=int, default=40); x.set_defaults(f=cmd_logs)
x = sp.add_parser("down"); x.set_defaults(f=cmd_down)
a = ap.parse_args()
a.f(a)
