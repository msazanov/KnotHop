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
  lab13.py list [NAME]                knothopd list на ноде (права, записи, приглашения)
  lab13.py test NAME                  с клиента: curl «сайта» и whoami через туннель
  lab13.py logs NAME [N]              хвост журнала
  lab13.py down                       убрать контейнеры и сеть (состояние остаётся в ~/.cache/knothop-lab13/lab)
  lab13.py meshperf [--pairs 3] [--secs 10] [--keep]
                                      A/B mesh (KNOTHOP_MESH=0/1) в топологии клиент–T–выход: клиент только в сети perf-neta 172.29.102.0/24 вместе с T и хабом, выход (adm) и
                                      «сайт» только в perf-net, T в обеих; клиент не достаёт до выхода по IP. Ядра: adm=1,cl=2,gen=3,site=4,hub=5,t=6 (PERF_CPUS)
  lab13.py realityfail [--keep] [--unblock N]
                                      REALITY: выход слушает TCP-порт REALITY (сайт-прикрытие - TLS 1.3 на «сайте»), на выходе режутся UDP и TCP 47001, клиент переходит на REALITY;
                                      проверки: curl/ping через туннель, зонд без ключа, рестарт клиента при блоке. Сеть rl-net 172.29.103.0/24
  lab13.py perf [--pairs 3] [--secs 10] [--negative] [--keep]
                                      A/B замер прямого канала данных (KNOTHOP_DIRECT_DATA=0/1): отдельная внутренняя сеть perf-net 172.29.101.0/24,
                                      release-бинарь (~/.cache/knothop-target/fork/release/knothopd), выход и клиент по 1 ядру (PERF_CPUS="adm=1,cl=2,gen=3,site=4,hub=5"),
                                      генератор на своём ядре, iperf3 за выходом; результаты - ~/.cache/knothop-perf13/results

Топология: сеть knothop-lab13 172.29.98.0/24, хаб .10 (TCP 4242 изображает публичный узел RNS), «сайт» .50, ноды с .11.
Бинарь - отладочная сборка из bench/rns-iroh-node/target/debug/knothopd (KNOTHOP_BIN переопределяет).
"""
import argparse
import json
import laptop
import os
import re
import subprocess
import sys
import time
from pathlib import Path

HERE = Path(__file__).resolve().parent
if sys.argv[1:2] in (["realityfail"],):
    # REALITY-сценарий: свой префикс и подсеть (172.29.103.0/24), внутренняя сеть, бинарь - отладочная сборка knothopd из ~/.cache/knothop-target/check-rns-iroh-node
    os.environ.setdefault("LAB13_PREFIX", "rl")
    os.environ.setdefault("LAB13_ROOT", str(Path.home() / ".cache/knothop-rl13/lab"))
    os.environ.setdefault("LAB13_SUBNET", "172.29.103.0/24")
    os.environ.setdefault("KNOTHOP_BIN", str(Path.home() / ".cache/knothop-target/check-rns-iroh-node/debug/knothopd"))
if sys.argv[1:2] == ["rootless"]:
    # ADR 0028: сеть без корня на локальной Docker-сети с хабом вместо публичной RNS; отладочная сборка knothopd, свой префикс и подсеть
    os.environ.setdefault("LAB13_PREFIX", "rt")
    os.environ.setdefault("LAB13_ROOT", str(Path.home() / ".cache/knothop-rt13/lab"))
    os.environ.setdefault("LAB13_SUBNET", "172.29.104.0/24")
    os.environ.setdefault("KNOTHOP_BIN", str(Path.home() / ".cache/knothop-target/check-rns-iroh-node/debug/knothopd"))
if sys.argv[1:2] == ["p2p"]:
    # P2P без серверов: два клиента и хаб вместо публичной RNS; свой префикс и подсеть, отладочная сборка knothopd
    os.environ.setdefault("LAB13_PREFIX", "p2")
    os.environ.setdefault("LAB13_ROOT", str(Path.home() / ".cache/knothop-p2-13/lab"))
    os.environ.setdefault("LAB13_SUBNET", "172.29.105.0/24")
    os.environ.setdefault("KNOTHOP_BIN", str(Path.home() / ".cache/knothop-target/check-rns-iroh-node/debug/knothopd"))
if sys.argv[1:2] in (["perf"], ["meshperf"], ["meshfail"], ["blockfail"]):
    # Замер идёт в отдельной внутренней сети со своим префиксом, release-бинарём и без подробного журнала (KNOTHOP_DEBUG замедляет путь данных).
    os.environ.setdefault("LAB13_PREFIX", "perf")
    os.environ.setdefault("LAB13_ROOT", str(Path.home() / ".cache/knothop-perf13/lab"))
    os.environ.setdefault("LAB13_SUBNET", "172.29.101.0/24")
    os.environ.setdefault("LAB13_DEBUG", "0")
    os.environ.setdefault("KNOTHOP_BIN", str(Path.home() / ".cache/knothop-target/fork/release/knothopd"))
# Имя попадает в имена контейнеров, каталоги state и аргументы rm -rf: только безопасный набор символов.
NAME_RE = re.compile(r"^[a-z][a-z0-9-]{0,30}$")
BIN = Path(os.environ.get("KNOTHOP_BIN", str(HERE.parent / "rns-iroh-node/target/debug/knothopd")))
# Отдельный префикс позволяет запускать сценарии на изолированной сети, не затрагивая knothop-lab13.
PREFIX = os.environ.get("LAB13_PREFIX", "")
LAB = Path(os.environ.get("LAB13_ROOT", str(Path.home() / ".cache/knothop-lab13/lab")))
IMAGE = "knothop-bench:l3"
NET = f"{PREFIX}-net" if PREFIX else "knothop-lab13"
SUBNET = os.environ.get("LAB13_SUBNET", "172.29.98.0/24")
HUB_NAME = f"{PREFIX}-hub" if PREFIX else "l13-hub"
SITE_NAME = f"{PREFIX}-site" if PREFIX else "l13-site"
ADM_NAME = f"{PREFIX}-adm" if PREFIX else "adm"
BASE = SUBNET.rsplit(".", 1)[0]   # первые три октета подсети (по умолчанию 172.29.98)
HUB_IP, SITE_IP = f"{BASE}.10", f"{BASE}.50"
# LAB13_CPUSETS="имя=cpu,имя=cpu": закрепление контейнеров за ядрами (замеры на 1 ядро); LAB13_DEBUG=0: без KNOTHOP_DEBUG
CPUSETS = dict(x.split("=", 1) for x in os.environ.get("LAB13_CPUSETS", "").split(",") if "=" in x)
# Opt-in isolation for the rootless scenario, which otherwise uses bare names.
# Map only Docker container arguments, never command text or unrelated names.
ISOLATED_ROOTLESS = sys.argv[1:2] == ["rootless"] and os.environ.get("LAB13_ISOLATED") == "1"
ROOTLESS_NAMES = frozenset(("adm", "s1", "s2", "s3", "cl", "bad", "c1", "c2"))
if ISOLATED_ROOTLESS and (not PREFIX or not re.fullmatch(r"[a-z][a-z0-9-]{2,24}", PREFIX)):
    sys.exit("LAB13_ISOLATED=1 требует уникальный LAB13_PREFIX (3–25 строчных символов)")
CLIENT_NET = "198.18.0.0/15"
PHONE_PORT = 47011
HUB_LAN_PORT = 4243   # хаб «публичной RNS» на LAN-адресе ноутбука (для телефона)


def sh(*a, check=True):
    if ISOLATED_ROOTLESS and len(a) >= 3 and a[0] == "docker":
        a = list(a)
        if a[1] in ("exec", "inspect", "start", "stop", "restart", "rm", "logs"):
            # `exec` may itself contain arguments named like a node: map only
            # the container position, never its command arguments.
            indices = [2] if a[1] in ("exec", "start", "logs") else [len(a) - 1]
            for i in indices:
                if i < len(a) and a[i] in ROOTLESS_NAMES:
                    a[i] = f"{PREFIX}-{a[i]}"
        elif a[1] == "run" and "--name" in a:
            i = a.index("--name") + 1
            if i < len(a) and a[i] in ROOTLESS_NAMES:
                a[i] = f"{PREFIX}-{a[i]}"
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
        ip = f"{BASE}.{i}"
        if ip not in used and ip not in (HUB_IP, SITE_IP):
            return ip
    sys.exit("нет свободных адресов")


def run(name, ip, cmd, state, extra=(), net=None, private_dial=True):
    if not ISOLATED_ROOTLESS:
        sh("docker", "rm", "-f", name, check=False)
    debug = ("-e", "KNOTHOP_DEBUG=1") if os.environ.get("LAB13_DEBUG", "1") != "0" else ()
    cpus = ("--cpuset-cpus", CPUSETS[name]) if name in CPUSETS else ()
    trace = ("-e", "KNOTHOP_LINK_TRACE=1") if ISOLATED_ROOTLESS and os.environ.get("KNOTHOP_LINK_TRACE") == "1" else ()
    sh("docker", "run", "-d", "--name", name, "--hostname", name, "--network", net or NET, "--ip", ip, "--cap-add", "NET_ADMIN", "--device", "/dev/net/tun",
       "--sysctl", "net.ipv4.ip_forward=1", *debug, *trace, *cpus, *(("-e", "KNOTHOP_ALLOW_PRIVATE_DIAL=1") if private_dial else ()), "-e", "KNOTHOP_TCP_BACKOFF_S=30",
       "-v", f"{BIN}:/usr/local/bin/knothopd:ro", "-v", f"{HERE}:/lab:ro", "-v", f"{state}:/state", *extra, "--entrypoint", "sh", IMAGE, "-c", cmd)


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
    inv_own = "chown root:root /state/invite.txt 2>/dev/null; chmod 600 /state/invite.txt 2>/dev/null; " if has_invite else ""
    return (isolate(only_ip) + inv_own + f"python3 /lab/lab_web.py whoami {name} & "
            f"iptables -t nat -A POSTROUTING -s {CLIENT_NET} ! -o tun0 -j MASQUERADE; "
            # носитель не должен попадать в собственный туннель (журнал N30)
            f"iptables -I OUTPUT -d {CLIENT_NET} -p udp --sport 47001 -j DROP; "
            f"{os.environ.get('LAB_NODE_ENV', '')}knothopd node --state /state --name {name} --port 47001 --no-host-nft{adv} --public-rns-file /state/pub.txt --announce-s 10{inv}{os.environ.get('LAB_NODE_EXTRA', '')} 2>&1 | tee -a /state/node.log")


def client_cmd(only_ip, has_invite=True):
    inv = " --invite-file /state/invite.txt" if has_invite else ""
    return (isolate(only_ip) + f"{os.environ.get('LAB_CLIENT_ENV', '')}knothopd client --state /state{inv} --public-rns-file /state/pub.txt >> /state/client.log 2>&1 & "
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
        sys.exit(f"нет {BIN}: cargo build --bin knothopd в bench/rns-iroh-node")
    if sh("docker", "network", "inspect", NET, check=False).returncode:
        sh("docker", "network", "create", "--subnet", SUBNET, NET)
    hub = state_dir("hub")
    hub_pub = ("-p", f"{HUB_LAN_PORT}:4242/tcp") if a.phone else ()
    run(HUB_NAME, HUB_IP, "exec knothopd hub --state /state --port 47000 --tcp-port 4242", hub, hub_pub)
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
    # Приглашение не попадает в stdout/логи/argv: knothopd пишет его в файл с mode 0600.
    path = f"/state/.invite-{os.getpid()}"
    sh("docker", "exec", src, "knothopd", "invite", "--state", "/state", "--rights", rights,
       "--out", path, *root_arg, *extra)
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
    print(sh("docker", "exec", a.name, "knothopd", "list", "--state", "/state").stdout.split("таблица соседей")[0].strip())


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


# ---------------------------------------------------------------------------------------------------- perf: A/B замер прямого канала данных
INET = "1.1.1.1"          # «интернет»: публичный адрес на lo сайта (частные адреса закрыты изоляцией выхода, ослаблять её нельзя)
CL_NAME, GEN_NAME = f"{PREFIX or 'l13'}-cl", f"{PREFIX or 'l13'}-gen"
CPU_PY = """import os
tck = os.sysconf('SC_CLK_TCK'); tot = 0.0
for p in os.listdir('/proc'):
    if p.isdigit():
        try:
            if open(f'/proc/{p}/comm').read().strip() != 'knothopd':
                continue
            f = open(f'/proc/{p}/stat').read().rsplit(')', 1)[1].split()
            tot += (int(f[11]) + int(f[12])) / tck
        except OSError:
            pass
print(tot)
"""


def dx(c, *cmd, check=True):
    return sh("docker", "exec", c, *cmd, check=check)


def cpu_s(c):
    return float(dx(c, "python3", "/tmp/cpu.py").stdout.strip())


def perf_down():
    sh("docker", "rm", "-f", GEN_NAME, check=False)
    cmd_down(None)
    # state замера создан этим скриптом: удаляем из контейнера (владелец root), и только каталог с именем lab внутри каталога perf
    if LAB.name == "lab" and "perf" in str(LAB.parent) and LAB.exists():
        sh("docker", "run", "--rm", "-v", f"{LAB.parent}:/l", "--entrypoint", "rm", IMAGE, "-rf", "/l/lab")


def perf_up(mode):
    from types import SimpleNamespace
    cpus = dict(adm="1", cl="2", gen="3", site="4", hub="5")
    cpus.update(dict(x.split("=", 1) for x in os.environ.get("PERF_CPUS", "").split(",") if "=" in x))
    CPUSETS.update({ADM_NAME: cpus["adm"], CL_NAME: cpus["cl"], SITE_NAME: cpus["site"], HUB_NAME: cpus["hub"]})
    perf_down()
    LAB.parent.mkdir(parents=True, exist_ok=True)
    sh("docker", "network", "create", "--internal", "--subnet", SUBNET, "--label", "knothop.perf=1", NET)
    pre = ("printf '%s' '{\"version\":1,\"aliases\":[],\"allow\":[]}' > /state/host-acl.json; chmod 600 /state/host-acl.json; "
           f"ip route replace {INET}/32 via {SITE_IP}; ")
    os.environ["LAB_NODE_ENV"] = pre + f"KNOTHOP_DIRECT_DATA={mode} "
    os.environ["LAB_CLIENT_ENV"] = f"KNOTHOP_DIRECT_DATA={mode} "
    cmd_up(SimpleNamespace(phone=False, no_adm=False))
    dx(SITE_NAME, "ip", "addr", "add", f"{INET}/32", "dev", "lo")
    sh("docker", "exec", "-d", SITE_NAME, "taskset", "-c", cpus["site"], "iperf3", "-s", "-B", INET)
    adm_hash = json.loads(dx(ADM_NAME, "knothopd", "whoami", "--state", "/state").stdout)["hash"]   # входная нода приглашения v4 (публичный хеш)
    cmd_client(SimpleNamespace(name=CL_NAME, src=ADM_NAME, rights="user", root="", only_ip="", nodes=adm_hash, invite="", invite_file=""))
    deadline = time.time() + 120
    consented = False
    while time.time() < deadline:
        if not consented:
            # согласие новичка (в приложении - диалог): лаборатория отвечает на предложение приглашения v4 «принять»
            r = sh("docker", "exec", CL_NAME, "cat", "/state/enrollment.json", check=False)
            try:
                offer = json.loads(r.stdout) if r.returncode == 0 else {}
            except ValueError:
                offer = {}
            if offer.get("state") == "offer" and offer.get("request"):
                body = json.dumps({"request": offer["request"], "accept": True})
                sh("docker", "exec", CL_NAME, "sh", "-c", f"printf '%s' '{body}' > /state/enroll-consent.json")
                consented = True
        if sh("docker", "exec", CL_NAME, "ip", "link", "show", "tun0", check=False).returncode == 0:
            sh("docker", "exec", CL_NAME, "ip", "route", "replace", f"{INET}/32", "dev", "tun0")
            if sh("docker", "exec", CL_NAME, "curl", "-s", "-m", "3", f"http://{INET}/", check=False).stdout.strip():
                break
        time.sleep(1)
    else:
        sys.exit("туннель не поднялся за 120 с")
    Path(LAB.parent / "cpu.py").write_text(CPU_PY)
    for c in (CL_NAME, ADM_NAME):
        sh("docker", "cp", str(LAB.parent / "cpu.py"), f"{c}:/tmp/cpu.py")
    # генератор: отдельный контейнер в сетевом пространстве клиента (видит tun0), на своём ядре, не делит ядро с knothopd клиента
    sh("docker", "run", "-d", "--name", GEN_NAME, "--network", f"container:{CL_NAME}", "--cpuset-cpus", cpus["gen"], "--entrypoint", "sleep", IMAGE, "infinity")


def fresh_status(c, after, secs=45):
    """status.json узла, записанный после момента `after` (unix): узел пишет его с паузой до 20 с."""
    end = time.time() + secs
    while time.time() < end:
        m = dx(c, "stat", "-c", "%Y", "/state/status.json", check=False).stdout.strip()
        if m and int(m) >= int(after):
            try:
                return json.loads(dx(c, "cat", "/state/status.json").stdout)
            except ValueError:
                pass
        time.sleep(1)
    return {}


def dp_counters(st):
    t = (st or {}).get("tun") or {}
    d = dict(t.get("dataplane") or {})
    d["unauth_drops"] = t.get("unauth_drops")
    d["from_tun_pkts"], d["to_tun_pkts"] = t.get("from_tun_pkts"), t.get("to_tun_pkts")
    d["mesh"] = t.get("mesh")
    return d


def ping_stats(out):
    t = sorted(float(x) for x in re.findall(r"time=([\d.]+) ms", out))
    m = re.search(r"(\d+) packets transmitted, (\d+) received", out)
    r = {"sent": int(m.group(1)) if m else None, "recv": len(t)}
    if t:
        r.update(p50=round(t[len(t) // 2], 2), p95=round(t[min(len(t) - 1, int(len(t) * 0.95))], 2), max=round(t[-1], 2))
    return r


def iperf(args):
    r = dx(GEN_NAME, "iperf3", "-c", INET, "-J", *args, check=False)
    try:
        return json.loads(r.stdout)
    except ValueError:
        return {"error": (r.stdout or r.stderr)[-200:]}


MESH_T = False   # в топологии meshperf есть транзит T: его CPU тоже считаем


def measured(fn):
    c0 = (cpu_s(CL_NAME), cpu_s(ADM_NAME), cpu_s(T_NAME) if MESH_T else 0.0)
    t0 = time.time()
    res = fn()
    wall = time.time() - t0
    c1 = (cpu_s(CL_NAME), cpu_s(ADM_NAME), cpu_s(T_NAME) if MESH_T else 0.0)
    r = {"wall_s": round(wall, 2), "cl_cpu_s": round(c1[0] - c0[0], 2), "adm_cpu_s": round(c1[1] - c0[1], 2)}
    if MESH_T:
        r["t_cpu_s"] = round(c1[2] - c0[2], 2)
    return res, r


def perf_tests(secs):
    out = {}
    s = str(secs)
    ping = lambda n, i="0.2": ["docker", "exec", GEN_NAME, "ping", "-n", "-i", i, "-c", str(n), "-W", "1", INET]
    out["ping_idle"] = ping_stats(subprocess.run(ping(25), capture_output=True, text=True).stdout)
    for name, rev in (("tcp_up", []), ("tcp_down", ["-R"])):
        p = subprocess.Popen(ping(int(secs * 4.5)), stdout=subprocess.PIPE, text=True) if rev else None
        j, cpu = measured(lambda: iperf(["-t", s, *rev]))
        e = j.get("end", {})
        rec = dict(cpu, **{"bytes": e.get("sum_received", {}).get("bytes"), "mbit": round(e.get("sum_received", {}).get("bits_per_second", 0) / 1e6, 1),
                           "retransmits": e.get("sum_sent", {}).get("retransmits"), "error": j.get("error")})
        if rec["bytes"]:
            gib = rec["bytes"] / 2 ** 30
            rec["cl_cpu_s_per_gib"], rec["adm_cpu_s_per_gib"] = round(cpu["cl_cpu_s"] / gib, 2), round(cpu["adm_cpu_s"] / gib, 2)
        if p:
            rec["ping_under_load"] = ping_stats(p.communicate()[0])
        out[name] = rec
    for name, rev, extra in (("udp_up_30M", [], ["-b", "30M", "-l", "1200"]), ("udp_down_30M", ["-R"], ["-b", "30M", "-l", "1200"]),
                             ("pps_up_64B_12M", [], ["-b", "12M", "-l", "64"]), ("pps_down_64B_12M", ["-R"], ["-b", "12M", "-l", "64"])):
        j, cpu = measured(lambda: iperf(["-u", "-t", s, *extra, *rev]))
        e = j.get("end", {}).get("sum", {})
        rec = dict(cpu, **{"mbit": round(e.get("bits_per_second", 0) / 1e6, 2), "jitter_ms": e.get("jitter_ms"), "packets": e.get("packets"),
                           "lost": e.get("lost_packets"), "lost_pct": round(e.get("lost_percent", 0), 2) if e else None, "error": j.get("error")})
        if e.get("packets"):
            rec["pps"] = round(e["packets"] / secs)
        out[name] = rec
    # функциональная проверка: curl через туннель (сайт, служба выхода, 16 МиБ)
    f = {}
    r = dx(GEN_NAME, "curl", "-s", "-m", "8", f"http://{INET}/", check=False)
    f["site"] = r.stdout.strip()[:120] or f"нет ответа ({r.returncode})"
    r = dx(GEN_NAME, "curl", "-s", "-m", "8", "http://10.99.0.1:8080/", check=False)
    f["exit_service_8080_expected_blocked"] = r.stdout.strip()[:120] or f"нет ответа ({r.returncode})"
    r = dx(GEN_NAME, "curl", "-s", "-m", "30", "-o", "/dev/null", "-w", "%{size_download} %{http_code}", f"http://{INET}/big", check=False)
    f["big_16MiB"] = r.stdout.strip() or f"нет ответа ({r.returncode})"
    out["functional"] = f
    return out


def perf_sweep(mode, secs):
    perf_up(mode)
    # прогрев: TCP 6 с вверх и вниз, пинги; результаты отбрасываются
    iperf(["-t", "6"]); iperf(["-t", "6", "-R"])
    t_start = int(time.time())
    res = {"mode": mode, "secs": secs, "tests": perf_tests(secs)}
    st_cl = fresh_status(CL_NAME, time.time())
    st_adm = fresh_status(ADM_NAME, time.time())
    cur = (st_cl.get("current") or {})
    res["client_carrier"] = cur.get("carrier")
    res["dataplane_client"], res["dataplane_exit"] = dp_counters(st_cl), dp_counters(st_adm)
    res["started_unix"] = t_start
    return res


def perf_negative(blackhole=False):
    """Отзыв прав клиента под нагрузкой при включённом прямом канале: пакеты после закрытия Link не должны проходить."""
    perf_up(1)
    iperf(["-t", "5"])
    whoami = json.loads(dx(CL_NAME, "knothopd", "whoami", "--state", "/state").stdout)
    holder_pk = whoami["pk"]   # публичный ключ клиента (не секрет): держатель без записи у админа (приглашение v4) задаётся ключом, не префиксом хеша
    n = 3000
    p = subprocess.Popen(["docker", "exec", GEN_NAME, "ping", "-n", "-D", "-i", "0.01", "-c", str(n), "-W", "1", INET], stdout=subprocess.PIPE, text=True)
    time.sleep(6)
    before = fresh_status(ADM_NAME, time.time() - 1)
    if blackhole:
        # выход перестаёт слать клиенту по UDP: о закрытии Link клиент не узнаёт и продолжает слать VPN-датаграммы (стороннее «устаревшее» поведение)
        client_ip = ip_of(CL_NAME)
        dx(ADM_NAME, "iptables", "-I", "OUTPUT", "-p", "udp", "-d", client_ip, "-j", "DROP")
        dx(ADM_NAME, "iptables", "-I", "OUTPUT", "-p", "tcp", "-d", client_ip, "-j", "DROP")
        time.sleep(0.5)
        before = fresh_status(ADM_NAME, time.time() - 1)
    t_rev = time.time()
    r = dx(ADM_NAME, "knothopd", "grant", "--state", "/state", "--holder", holder_pk, "--rights", "none", check=False)
    rev_out = (r.stdout + r.stderr).strip()[-200:]
    out = p.communicate()[0]
    rx = [(float(a), int(b)) for a, b in re.findall(r"^\[([\d.]+)\].*icmp_seq=(\d+)", out, re.M)]
    before_rev = [x for x in rx if x[0] < t_rev]
    after = [x for x in rx if x[0] >= t_rev]
    last_ok = max((x[0] for x in rx), default=None)
    time.sleep(1)
    adm = fresh_status(ADM_NAME, time.time())
    cl = fresh_status(CL_NAME, time.time())
    adm_log = dx(ADM_NAME, "sh", "-c", "grep -a 'close link\\|отозв\\|USE снято\\|право' /state/node.log | tail -5", check=False).stdout
    return {"blackhole": blackhole, "revoke_cli": rev_out, "replies_before_revoke": len(before_rev), "replies_after_revoke": len(after),
            "reply_stops_s_after_revoke": round(last_ok - t_rev, 2) if last_ok else None,
            "exit_before": dp_counters(before), "exit_after": dp_counters(adm), "client_after": dp_counters(cl),
            "client_state": cl.get("state"), "exit_log_tail": adm_log.strip().splitlines()[-5:]}


def cmd_perf(a):
    import statistics
    if not BIN.exists():
        sys.exit(f"нет {BIN}: bash bench/build_fork.sh --offline --locked --bin knothopd")
    res_dir = LAB.parent / "results"
    res_dir.mkdir(parents=True, exist_ok=True)
    sweeps = []
    try:
        if a.negative:
            neg = perf_negative(a.blackhole)
            (res_dir / ("negative-blackhole.json" if a.blackhole else "negative.json")).write_text(json.dumps(neg, ensure_ascii=False, indent=1))
            print(json.dumps(neg, ensure_ascii=False, indent=1))
            return
        order = [0, 1] * a.pairs if not a.modes else [int(x) for x in a.modes.split(",")]
        for i, mode in enumerate(order):
            print(f"[perf] прогон {i + 1}/{len(order)} режим KNOTHOP_DIRECT_DATA={mode}", flush=True)
            r = perf_sweep(mode, a.secs)
            r["index"] = i
            sweeps.append(r)
            (res_dir / f"sweep-{i}-mode{mode}.json").write_text(json.dumps(r, ensure_ascii=False, indent=1))
            print(json.dumps({"mode": mode, "tcp_up": r["tests"]["tcp_up"].get("mbit"), "tcp_down": r["tests"]["tcp_down"].get("mbit"),
                              "dp_client": r["dataplane_client"], "dp_exit": r["dataplane_exit"]}, ensure_ascii=False), flush=True)
    finally:
        if not a.keep:
            perf_down()
    if not sweeps:
        return
    rows = [("tcp_up", "mbit"), ("tcp_up", "cl_cpu_s_per_gib"), ("tcp_up", "adm_cpu_s_per_gib"), ("tcp_down", "mbit"), ("tcp_down", "cl_cpu_s_per_gib"),
            ("tcp_down", "adm_cpu_s_per_gib"), ("tcp_down", "ping_under_load.p50"), ("tcp_down", "ping_under_load.p95"), ("tcp_up", "retransmits"),
            ("ping_idle", "p50"), ("ping_idle", "p95"),
            ("udp_up_30M", "lost_pct"), ("udp_up_30M", "jitter_ms"), ("udp_up_30M", "cl_cpu_s"), ("udp_up_30M", "adm_cpu_s"),
            ("udp_down_30M", "lost_pct"), ("udp_down_30M", "jitter_ms"), ("udp_down_30M", "cl_cpu_s"), ("udp_down_30M", "adm_cpu_s"),
            ("pps_up_64B_12M", "pps"), ("pps_up_64B_12M", "lost_pct"), ("pps_up_64B_12M", "cl_cpu_s"), ("pps_up_64B_12M", "adm_cpu_s"),
            ("pps_down_64B_12M", "pps"), ("pps_down_64B_12M", "lost_pct"), ("pps_down_64B_12M", "cl_cpu_s"), ("pps_down_64B_12M", "adm_cpu_s")]

    def get(r, t, k):
        v = r["tests"].get(t, {})
        for part in k.split("."):
            v = v.get(part) if isinstance(v, dict) else None
        return v

    print(f"\n{'метрика':36} {'режим 0 (Link) мед [мин..макс]':34} {'режим 1 (dataplane)':34}")
    for t, k in rows:
        cells = []
        for m in (0, 1):
            xs = [get(r, t, k) for r in sweeps if r["mode"] == m]
            xs = [x for x in xs if isinstance(x, (int, float))]
            cells.append(f"{statistics.median(xs):.2f} [{min(xs):.2f}..{max(xs):.2f}] n={len(xs)}" if xs else "-")
        print(f"{t + '.' + k:36} {cells[0]:34} {cells[1]:34}")
    for r in sweeps:
        print(f"#{r['index']} mode={r['mode']} carrier={r.get('client_carrier')} client={r['dataplane_client']} exit={r['dataplane_exit']} functional={r['tests']['functional']}")


# ---------------------------------------------------------------------------------------------------- meshperf: клиент–T–выход
NET_A, SUBNET_A, T_IPA = f"{PREFIX or 'l13'}-neta", "172.29.102.0/24", "172.29.102.20"
T_NAME = f"{PREFIX or 'l13'}-t"


def mesh_down():
    for n in (GEN_NAME, CL_NAME, T_NAME, ADM_NAME, HUB_NAME, SITE_NAME):
        sh("docker", "rm", "-f", n, check=False)
    sh("docker", "network", "rm", NET_A, check=False)
    sh("docker", "network", "rm", NET, check=False)
    if LAB.name == "lab" and "perf" in str(LAB.parent) and LAB.exists():
        sh("docker", "run", "--rm", "-v", f"{LAB.parent}:/l", "--entrypoint", "rm", IMAGE, "-rf", "/l/lab")


def mesh_up(mode, direct=False, pre_client=None):
    """adm (выход) и сайт в perf-net; T в обеих сетях; клиент и хаб (публичная RNS для обнаружения адресов) достижимы клиентом через perf-neta."""
    from types import SimpleNamespace
    global MESH_T
    MESH_T = True
    cpus = dict(adm="1", cl="2", gen="3", site="4", hub="5", t="6")
    cpus.update(dict(x.split("=", 1) for x in os.environ.get("PERF_CPUS", "").split(",") if "=" in x))
    CPUSETS.update({ADM_NAME: cpus["adm"], CL_NAME: cpus["cl"], SITE_NAME: cpus["site"], HUB_NAME: cpus["hub"], T_NAME: cpus["t"]})
    mesh_down()
    LAB.parent.mkdir(parents=True, exist_ok=True)
    sh("docker", "network", "create", "--internal", "--subnet", SUBNET, "--label", "knothop.perf=1", NET)
    sh("docker", "network", "create", "--internal", "--subnet", SUBNET_A, "--label", "knothop.perf=1", NET_A)
    pre = ("printf '%s' '{\"version\":1,\"aliases\":[],\"allow\":[]}' > /state/host-acl.json; chmod 600 /state/host-acl.json; "
           f"ip route replace {INET}/32 via {SITE_IP}; ")
    env = f"KNOTHOP_DIRECT_DATA=1 KNOTHOP_MESH={mode} " + os.environ.get("MESH_EXTRA_ENV", "")
    os.environ["LAB_NODE_ENV"] = pre + env
    os.environ["LAB_CLIENT_ENV"] = env
    # identity adm и T создаём заранее, право T (USE+TRANSIT: чистый транзит, не выход) выдаём офлайн ДО старта adm; якорь корня ставим на T (узел сам не вступает)
    da, dt = state_dir("adm"), state_dir(T_NAME)
    kn = lambda d: ("docker", "run", "--rm", "-v", f"{BIN}:/usr/local/bin/knothopd:ro", "-v", f"{d}:/state", "--entrypoint", "knothopd", IMAGE)
    adm_who = json.loads(sh(*kn(da), "whoami", "--state", "/state").stdout)
    t_who = json.loads(sh(*kn(dt), "whoami", "--state", "/state").stdout)
    sh(*kn(da), "grant", "--state", "/state", "--holder", t_who["pk"], "--rights", "relay")
    # запись права T: файл inbox13 админа копируем в inbox13 T (узел принимает его при старте: корень T уже якорь); иначе T «без прав» и сеть его не видит
    sh("docker", "run", "--rm", "-v", f"{LAB}:/l", "--entrypoint", "sh", IMAGE, "-c", f"mkdir -p /l/{T_NAME}/inbox13 && cp /l/adm/inbox13/* /l/{T_NAME}/inbox13/")
    write_private(dt / "root.pk", adm_who["pk"])
    sh(*kn(dt), "trust-anchor", "--state", "/state", "--root-key-file", "/state/root.pk", "--fingerprint", adm_who["hash"])
    cmd_up(SimpleNamespace(phone=False, no_adm=False))
    sh("docker", "network", "connect", NET_A, HUB_NAME)
    hub_a = sh("docker", "inspect", "-f", f"{{{{(index .NetworkSettings.Networks \"{NET_A}\").IPAddress}}}}", HUB_NAME).stdout.strip()
    dx(SITE_NAME, "ip", "addr", "add", f"{INET}/32", "dev", "lo")
    sh("docker", "exec", "-d", SITE_NAME, "taskset", "-c", cpus["site"], "iperf3", "-s", "-B", INET)
    d = dt
    write_pub(d)
    ip_b = next_ip()
    # прямой сосед T -> adm (seed): записи прав (adm -> T) доходят по этой связи; без неё обнаружение идёт только через хаб и не успевает
    os.environ["LAB_NODE_EXTRA"] = f" --seed {adm_who['pk'][64:]}@{ip_of(ADM_NAME)}:47001"
    run(T_NAME, ip_b, node_cmd(T_NAME, ip_b, None, False, f",{T_IPA}:47001"), d)
    os.environ["LAB_NODE_EXTRA"] = ""
    sh("docker", "network", "connect", "--ip", T_IPA, NET_A, T_NAME)
    wait_file(T_NAME, "/state/server.json")
    adm_hash = adm_who["hash"]
    t_hash = t_who["hash"]
    # T: носитель клиента (клиент дозванивается только до нод с правом EXIT), но выходом T быть не должна - её политика сужает выдачу до USE+TRANSIT
    for _ in range(40):
        if dx(T_NAME, "knothopd", "policy", "--state", "/state", "--root", adm_hash, "--rights", "use+transit", check=False).returncode == 0:
            break
        time.sleep(1)
    # клиент: только perf-neta; хаб ему доступен по адресу в этой сети
    c = state_dir(CL_NAME)
    (c / "pub.txt").write_text(f"{hub_a}:4242\n")
    write_private(c / "invite.txt", make_invite(ADM_NAME, "user", CL_NAME, f"{adm_hash},{t_hash}", ""))
    if pre_client:
        pre_client()
    if direct:
        # клиент достаёт выход напрямую (perf-net) И через транзит T: прямой носитель + тёплый запасной mesh-путь
        run(CL_NAME, "172.29.101.30", client_cmd(""), c, net=NET)
        sh("docker", "network", "connect", "--ip", "172.29.102.30", NET_A, CL_NAME)
    else:
        run(CL_NAME, "172.29.102.30", client_cmd(""), c, net=NET_A)
    deadline = time.time() + 300
    consented = False
    while time.time() < deadline:
        if not consented:
            r = sh("docker", "exec", CL_NAME, "cat", "/state/enrollment.json", check=False)
            try:
                offer = json.loads(r.stdout) if r.returncode == 0 else {}
            except ValueError:
                offer = {}
            if offer.get("state") == "offer" and offer.get("request"):
                body = json.dumps({"request": offer["request"], "accept": True})
                sh("docker", "exec", CL_NAME, "sh", "-c", f"printf '%s' '{body}' > /state/enroll-consent.json")
                consented = True
        if sh("docker", "exec", CL_NAME, "ip", "link", "show", "tun0", check=False).returncode == 0:
            sh("docker", "exec", CL_NAME, "ip", "route", "replace", f"{INET}/32", "dev", "tun0")
            if sh("docker", "exec", CL_NAME, "curl", "-s", "-m", "3", f"http://{INET}/", check=False).stdout.strip():
                break
        time.sleep(1)
    else:
        sys.exit("туннель не поднялся за 300 с")
    Path(LAB.parent / "cpu.py").write_text(CPU_PY)
    for n in (CL_NAME, ADM_NAME, T_NAME):
        sh("docker", "cp", str(LAB.parent / "cpu.py"), f"{n}:/tmp/cpu.py")
    sh("docker", "run", "-d", "--name", GEN_NAME, "--network", f"container:{CL_NAME}", "--cpuset-cpus", cpus["gen"], "--entrypoint", "sleep", IMAGE, "infinity")


def mesh_reach_check():
    """Клиент не должен доставать до выхода по IP: проверка из сети клиента (UDP/TCP 47001 выхода и ping)."""
    adm_ip = ip_of(ADM_NAME)
    r = sh("docker", "exec", CL_NAME, "sh", "-c", f"ping -c1 -W1 {adm_ip} >/dev/null 2>&1 && echo reachable || echo unreachable", check=False)
    return r.stdout.strip()


def mesh_sweep(mode, secs):
    mesh_up(mode)
    reach = mesh_reach_check()
    # прогрев (результаты отбрасываются) и время, за которое mesh успевает подняться (журнал клиента)
    iperf(["-t", "6"]); iperf(["-t", "6", "-R"])
    t_start = int(time.time())
    res = {"mode": mode, "secs": secs, "client_to_exit_ip": reach, "tests": perf_tests(secs)}
    st = {n: fresh_status(n, time.time()) for n in (CL_NAME, ADM_NAME, T_NAME)}
    res["dataplane_client"], res["dataplane_exit"], res["dataplane_t"] = (dp_counters(st[CL_NAME]), dp_counters(st[ADM_NAME]), dp_counters(st[T_NAME]))
    res["client_carrier"] = (st[CL_NAME].get("current") or {}).get("carrier")
    log = dx(CL_NAME, "sh", "-c", "grep -a 'mesh:\\|выход .* принял' /state/client.log | tail -5", check=False).stdout
    res["client_log"] = log.strip().splitlines()
    res["started_unix"] = t_start
    return res


def cmd_meshperf(a):
    import statistics
    if not BIN.exists():
        sys.exit(f"нет {BIN}")
    res_dir = LAB.parent / "results"
    res_dir.mkdir(parents=True, exist_ok=True)
    sweeps = []
    try:
        order = [0, 1] * a.pairs
        for i, mode in enumerate(order):
            print(f"[meshperf] прогон {i + 1}/{len(order)} KNOTHOP_MESH={mode}", flush=True)
            r = mesh_sweep(mode, a.secs)
            r["index"] = i
            sweeps.append(r)
            (res_dir / f"mesh-{i}-mode{mode}.json").write_text(json.dumps(r, ensure_ascii=False, indent=1))
            print(json.dumps({"mode": mode, "reach": r["client_to_exit_ip"], "tcp_up": r["tests"]["tcp_up"].get("mbit"), "tcp_down": r["tests"]["tcp_down"].get("mbit"),
                              "dp_client": r["dataplane_client"], "dp_exit": r["dataplane_exit"], "dp_t": r["dataplane_t"]}, ensure_ascii=False), flush=True)
    finally:
        if not a.keep:
            mesh_down()
    rows = [("tcp_up", "mbit"), ("tcp_up", "cl_cpu_s_per_gib"), ("tcp_up", "adm_cpu_s_per_gib"), ("tcp_up", "t_cpu_s"), ("tcp_down", "mbit"), ("tcp_down", "cl_cpu_s_per_gib"),
            ("tcp_down", "adm_cpu_s_per_gib"), ("tcp_down", "t_cpu_s"), ("tcp_down", "ping_under_load.p50"), ("tcp_down", "ping_under_load.p95"), ("tcp_up", "retransmits"),
            ("ping_idle", "p50"), ("ping_idle", "p95"), ("udp_up_30M", "lost_pct"), ("udp_down_30M", "lost_pct"),
            ("pps_up_64B_12M", "pps"), ("pps_up_64B_12M", "lost_pct"), ("pps_down_64B_12M", "pps"), ("pps_down_64B_12M", "lost_pct")]

    def get(r, t, k):
        v = r["tests"].get(t, {})
        for part in k.split("."):
            v = v.get(part) if isinstance(v, dict) else None
        return v

    print(f"\n{'метрика':36} {'MESH=0 (Link через T) мед [мин..макс]':40} {'MESH=1 (сквозной QUIC)':34}")
    for t, k in rows:
        cells = []
        for m in (0, 1):
            xs = [x for x in (get(r, t, k) for r in sweeps if r["mode"] == m) if isinstance(x, (int, float))]
            cells.append(f"{statistics.median(xs):.2f} [{min(xs):.2f}..{max(xs):.2f}] n={len(xs)}" if xs else "-")
        print(f"{t + '.' + k:36} {cells[0]:40} {cells[1]:34}")
    for r in sweeps:
        print(f"#{r['index']} mode={r['mode']} reach={r['client_to_exit_ip']} client={r['dataplane_client']} exit={r['dataplane_exit']} t={r['dataplane_t']} log={r['client_log']} functional={r['tests']['functional']}")



# ---------------------------------------------------------------------------------------------------- meshfail: переключение прямой -> тёплый mesh-путь
def client_path():
    r = sh("docker", "exec", CL_NAME, "cat", "/state/status.json", check=False)
    try:
        status = json.loads(r.stdout)
        current = status.get("current") or {}
        q = dict(current.get("quic") or {})
        q.update(ts_ms=status.get("ts_ms"), exit=current.get("d"),
                 dataplane=(status.get("tun") or {}).get("dataplane"),
                 mesh=(status.get("tun") or {}).get("mesh"))
        return q
    except ValueError:
        return {}


def ping_gaps(out, t_from, t_to):
    from failover_metrics import ping_window
    return ping_window(out, t_from, t_to)


def fail_scenario(kind, secs=40):
    """kind: 'block' - клиент перестаёт видеть выход (iptables DROP на адрес выхода), T достижим; 'blackhole' - клиент теряет всю сеть на 5 с."""
    adm_ip = sh("docker", "inspect", "-f", f"{{{{(index .NetworkSettings.Networks \"{NET}\").IPAddress}}}}", ADM_NAME).stdout.strip()
    t0 = time.time()
    while time.time() - t0 < 180:
        q = client_path()
        if q.get("kind") == "direct" and "mesh" in (q.get("backup") or []):
            break
        time.sleep(2)
    else:
        return {"error": f"тёплый запасной путь не открылся: {client_path()}"}
    pre = client_path()
    pinned = pre.get("exit", "")
    if not re.fullmatch(r"[0-9a-f]{32}", pinned):
        return {"error": "cannot-pin-exit"}
    sh("docker", "exec", CL_NAME, "sh", "-c", f"printf '%s' '{pinned}' > /state/select")
    p = subprocess.Popen(["docker", "exec", GEN_NAME, "ping", "-n", "-D", "-i", "0.1", "-c", str(secs * 10), "-W", "1", INET], stdout=subprocess.PIPE, text=True)
    ip_p = subprocess.Popen(["docker", "exec", GEN_NAME, "iperf3", "-c", INET, "-J", "-t", str(secs - 4), "-i", "1"], stdout=subprocess.PIPE, text=True)
    time.sleep(10)
    t_block_start = time.time()
    if kind == "block":
        rules_add = [["-I", "OUTPUT", "-d", adm_ip, "-j", "DROP"], ["-I", "INPUT", "-s", adm_ip, "-j", "DROP"]]
        rules_del = [["-D", "OUTPUT", "-d", adm_ip, "-j", "DROP"], ["-D", "INPUT", "-s", adm_ip, "-j", "DROP"]]
    else:
        rules_add = [["-I", "OUTPUT", "!", "-o", "lo", "-j", "DROP"], ["-I", "INPUT", "!", "-i", "lo", "-j", "DROP"]]
        rules_del = [["-D", "OUTPUT", "!", "-o", "lo", "-j", "DROP"], ["-D", "INPUT", "!", "-i", "lo", "-j", "DROP"]]
    applied = []
    trace = []
    cleanup_ok = True
    try:
        for add, delete in zip(rules_add, rules_del):
            sh("docker", "exec", CL_NAME, "iptables", *add)
            applied.append(delete)
        t_block = time.time()
        deadline = t_block + (5 if kind == "blackhole" else 15)
        while time.time() < deadline:
            sample = client_path()
            trace.append({"observed_at": time.time(), **sample})
            time.sleep(0.25)
    finally:
        t_unblock_start = time.time()
        for delete in reversed(applied):
            cleanup_ok &= sh("docker", "exec", CL_NAME, "iptables", *delete, check=False).returncode == 0
        t_unblock = time.time()
    during = trace[-1] if trace else {}
    if kind == "blackhole":
        sh("docker", "exec", CL_NAME, "touch", "/state/netchange", check=False)
    back = None
    for _ in range(60):
        q = client_path()
        if q.get("kind") == "direct" and q.get("exit") == pinned and q.get("ts_ms", 0) >= t_unblock * 1000:
            back = round(time.time() - t_unblock, 1)
            break
        time.sleep(0.5)
    out = p.communicate()[0]
    iout = ip_p.communicate()[0]
    try:
        ij = json.loads(iout)
        ints = [round(x["sum"]["bits_per_second"] / 1e6) for x in ij["intervals"]]
        iperf_min = min(ints[8:20]) if len(ints) > 20 else None
        iperf_ints = ints[6:22]
    except Exception:
        iperf_min, iperf_ints = None, None
    run_dir = LAB.parent / "results" / f"meshfail-{kind}-{time.time_ns()}"
    run_dir.mkdir(parents=True)
    (run_dir / "ping.log").write_text(out)
    (run_dir / "iperf.json").write_text(iout)
    fresh = [q for q in trace if t_block * 1000 <= q.get("ts_ms", 0) <= t_unblock * 1000 and q.get("exit") == pinned]
    return {"kind": kind, "before": pre, "during": during, "path_trace": trace,
            "mesh_observed_during_block": any(q.get("kind") == "mesh" for q in fresh),
            "exit_stayed_pinned": bool(fresh) and all(q.get("exit") == pinned for q in trace),
            "cleanup_ok": cleanup_ok,
            "timing": {"block_started": t_block_start, "block_applied": t_block, "unblock_started": t_unblock_start, "unblock_done": t_unblock},
            "ping_block": ping_gaps(out, t_block, min(t_block + 8, t_unblock)),
            "ping_unblock": ping_gaps(out, t_unblock, t_unblock + 8),
            "back_to_direct_status_s": back, "iperf_mbit_6_22": iperf_ints, "raw_results": str(run_dir)}


def cmd_meshfail(a):
    res_dir = LAB.parent / "results"
    res_dir.mkdir(parents=True, exist_ok=True)
    allr = []
    try:
        mesh_up(1, direct=True)
        for i in range(a.repeats):
            for kind in ("block", "blackhole"):
                r = fail_scenario(kind)
                r["i"] = i
                allr.append(r)
                print(json.dumps(r, ensure_ascii=False), flush=True)
                time.sleep(15)
        st = fresh_status(CL_NAME, time.time())
        print("mesh client:", json.dumps({k: v for k, v in (st.get("tun", {}).get("mesh") or {}).items() if v}, ensure_ascii=False))
    finally:
        (res_dir / "meshfail.json").write_text(json.dumps(allr, ensure_ascii=False, indent=1))
        if not a.keep:
            mesh_down()

# ---------------------------------------------------------------------------------------------------- REALITY: UDP и TCP:47001 к выходу закрыты
RL_PORT = 8443          # порт REALITY на выходе (в проде Traefik :443 -> 127.0.0.1:порт; здесь прямое соединение без PROXY v2)
RL_SNI = "cover.lab.example"


def rl_client_view(secs=0):
    """Что клиент сообщает о носителе выхода: status.json -> carrier (quic|tcp|reality|none)."""
    st = fresh_status(CL_NAME, time.time() - 1, secs or 30)
    return {"servers": [{"name": s.get("name"), "carrier": s.get("carrier"), "state": s.get("state")} for s in (st.get("servers") or st.get("exits") or [])] or None,
            "raw_keys": sorted(st.keys())[:12] if not st.get("servers") and not st.get("exits") else None}


def rl_curl(secs=5):
    return sh("docker", "exec", CL_NAME, "curl", "-s", "-m", str(secs), f"http://{INET}/", check=False).stdout.strip()


def rl_ping_outage(t_from):
    """По /tmp/pingblk.txt клиента (ping -D): ответов до t_from, самый длинный перерыв после t_from и время от t_from до первого ответа после этого перерыва."""
    out = sh("docker", "exec", CL_NAME, "sh", "-c", "pkill -x ping; cat /tmp/pingblk.txt", check=False).stdout
    ts = [float(m) for m in re.findall(r"^\[(\d+\.\d+)\] \d+ bytes from", out, re.M)]
    after = [t for t in ts if t >= t_from]
    if not after:
        return {"replies_total": len(ts), "recovered": False}
    pts = [max(t for t in ts if t < t_from) if any(t < t_from for t in ts) else t_from] + after
    gaps = [(pts[i + 1] - pts[i], pts[i + 1]) for i in range(len(pts) - 1)]
    g, t_end = max(gaps)
    return {"replies_total": len(ts), "replies_after": len(after), "longest_gap_s": round(g, 1), "first_reply_after_s": round(after[0] - t_from, 1),
            "restored_after_s": round(t_end - t_from, 1) if g > 2 else round(after[0] - t_from, 1), "last_reply_after_s": round(after[-1] - t_from, 1)}


def rl_wait(pred, secs, what):
    end = time.time() + secs
    while time.time() < end:
        v = pred()
        if v:
            return v
        time.sleep(2)
    return None


def cmd_realityfail(a):
    """Клиент подключается к выходу обычным путём (QUIC/UDP), узнаёт подсказку `rl`; затем на выходе закрываются UDP и TCP 47001 (открыт только TCP REALITY-порт):
    клиент обязан перейти на REALITY, трафик идёт через туннель; рестарт клиента при том же блоке поднимает туннель по сохранённой подсказке."""
    from types import SimpleNamespace
    res = {"scenario": "realityfail"}
    # state этого сценария создан им же (владелец root внутри контейнера): чистим только каталог lab внутри rl13, иначе журналы прошлых прогонов портят счёт
    if LAB.name == "lab" and "rl13" in str(LAB.parent) and LAB.exists():
        sh("docker", "run", "--rm", "-v", f"{LAB.parent}:/l", "--entrypoint", "rm", IMAGE, "-rf", "/l/lab")
    try:
        # --control: тот же сценарий без REALITY и с закрытым только UDP (TCP:47001 открыт): эталон поведения прежнего TCP-носителя при блоке
        os.environ["LAB_NODE_EXTRA"] = "" if a.control else f" --reality-listen 0.0.0.0:{RL_PORT} --reality-dest {SITE_IP}:443 --reality-sni {RL_SNI} --reality-public-port {RL_PORT}"
        perf_up("1")
        os.environ["LAB_NODE_EXTRA"] = ""
        adm_ip = ip_of(ADM_NAME)
        sh("docker", "exec", "-d", SITE_NAME, "python3", "/lab/lab_web.py", "cover")
        time.sleep(2)
        res["cover_direct"] = sh("docker", "exec", CL_NAME, "curl", "-sk", "--http1.1", "-m", "5", "--resolve", f"{RL_SNI}:443:{SITE_IP}", f"https://{RL_SNI}/", check=False).stdout.strip()
        res["curl_before_block"] = rl_curl()
        # клиент выучил подсказку (каталог по LXMF приходит не сразу)
        hint = rl_wait(lambda: sh("docker", "exec", CL_NAME, "cat", "/state/hints-rl.json", check=False).stdout.strip(), 120, "hints-rl.json")
        res["client_hints_rl_present"] = bool(hint)
        if hint:
            h = json.loads(hint)
            res["client_hint_fields"] = sorted(next(iter(h.values())).keys()) if h else []   # поля (p,s,k,i); значения ключей в отчёт не попадают
        st = fresh_status(ADM_NAME, time.time() - 1, 30)
        res["exit_reality_before"] = (st.get("tun") or {}).get("reality") or st.get("reality")
        # фоновый ping выхода в туннеле (0,5 с, метки времени): по нему считаются перерыв и время восстановления трафика от блока (и от снятия блока)
        if not a.idle:
            sh("docker", "exec", "-d", CL_NAME, "sh", "-c", f"ping -D -i 0.5 -W 1 {INET} > /tmp/pingblk.txt 2>&1")
            time.sleep(3)
        # блок: UDP и TCP 47001 к выходу закрыты (молча, как DPI); открыт TCP REALITY-порт
        for r in (("-p", "udp", "--dport", "47001"),) if a.control else (("-p", "udp", "--dport", "47001"), ("-p", "tcp", "--dport", "47001")):
            dx(ADM_NAME, "iptables", "-I", "INPUT", *r, "-j", "DROP")
        res["blocked_at"] = int(time.time())
        t_block_f = time.time()
        if a.idle:
            # блок посреди простоя: трафика нет, пока не прошло `idle` секунд (Link и QUIC никто не проверяет, кроме keepalive RNS и таймаута QUIC)
            time.sleep(a.idle)
            t_block_f = time.time()
            sh("docker", "exec", "-d", CL_NAME, "sh", "-c", f"ping -D -i 0.5 -W 1 {INET} > /tmp/pingblk.txt 2>&1")
        t0 = time.time()
        sw = rl_wait(lambda: sh("docker", "exec", ADM_NAME, "sh", "-c", "grep -c 'quic accepted from.*(reality)' /state/node.log; true", check=False).stdout.strip() not in ("", "0"), 40 if a.control else 240, "reality")
        res["switch_to_reality_s"] = round(time.time() - t0, 1) if sw else None
        ok = rl_wait(lambda: rl_curl(3), 240, "curl")
        res["curl_after_block"] = ok
        res["curl_after_block_s"] = round(time.time() - t0, 1) if ok else None
        res["ping_outage_after_block"] = rl_ping_outage(t_block_f)
        res["client_log_block"] = sh("docker", "exec", CL_NAME, "sh", "-c", f"awk -F'[][]' '$2 >= {res['blocked_at'] * 1000}' /state/client.log | grep -v 'снимок' | cut -c1-200 | head -40", check=False).stdout.splitlines()
        pg = sh("docker", "exec", CL_NAME, "ping", "-c", "10", "-i", "0.3", "-W", "2", INET, check=False).stdout
        res["ping_exit_tun"] = ping_stats(pg)
        res["client_log_reality"] = [l for l in sh("docker", "exec", CL_NAME, "sh", "-c", "grep -i 'reality' /state/client.log | tail -8", check=False).stdout.splitlines()]
        st = fresh_status(ADM_NAME, time.time() - 1, 30)
        res["exit_reality_after"] = (st.get("tun") or {}).get("reality") or st.get("reality")
        res["exit_log_reality"] = sh("docker", "exec", ADM_NAME, "sh", "-c", "grep -i 'reality' /state/node.log | tail -6", check=False).stdout.splitlines()
        if a.unblock:
            sh("docker", "exec", "-d", CL_NAME, "sh", "-c", f"ping -D -i 0.5 -W 1 {INET} > /tmp/pingblk.txt 2>&1")
            time.sleep(3)
            t_unb = time.time()
            for r in (("-p", "udp", "--dport", "47001"),) if a.control else (("-p", "udp", "--dport", "47001"), ("-p", "tcp", "--dport", "47001")):
                dx(ADM_NAME, "iptables", "-D", "INPUT", *r, "-j", "DROP", check=False)
            res["unblock_wait_s"] = a.unblock
            res["unblocked_at_ms"] = int(t_unb * 1000)
            time.sleep(a.unblock)
            res["ping_outage_after_unblock"] = rl_ping_outage(t_unb)
            res["client_log_return"] = sh("docker", "exec", CL_NAME, "sh", "-c", "grep -i 'возврат\\|reality' /state/client.log | tail -6", check=False).stdout.splitlines()
        # зонд без ключа на порт REALITY получает сайт-прикрытие (сертификат и ответ)
        res["probe_cert_subject"] = sh("docker", "exec", CL_NAME, "sh", "-c", f"echo | openssl s_client -connect {adm_ip}:{RL_PORT} -servername {RL_SNI} -tls1_3 2>/dev/null | openssl x509 -noout -subject", check=False).stdout.strip()
        res["probe_body"] = sh("docker", "exec", CL_NAME, "curl", "-sk", "--http1.1", "-m", "8", "--resolve", f"{RL_SNI}:{RL_PORT}:{adm_ip}", f"https://{RL_SNI}:{RL_PORT}/", check=False).stdout.strip()
        # рестарт клиента при том же блоке: туннель по сохранённой подсказке (при --unblock блок снят, этот шаг пропускается)
        if a.unblock:
            return
        sh("docker", "restart", "-t", "1", CL_NAME)
        time.sleep(3)
        sh("docker", "exec", CL_NAME, "ip", "route", "replace", f"{INET}/32", "dev", "tun0", check=False)
        t1 = time.time()
        def after_restart():
            sh("docker", "exec", CL_NAME, "ip", "route", "replace", f"{INET}/32", "dev", "tun0", check=False)
            return rl_curl(3)
        res["curl_after_restart"] = rl_wait(after_restart, 180, "restart")
        res["restart_recover_s"] = round(time.time() - t1, 1) if res["curl_after_restart"] else None
        if res["curl_after_restart"]:
            # трафик через туннель REALITY при закрытых UDP и TCP:47001: ping выхода в туннеле, HTTP, загрузка 16 МиБ (скорость лабораторная, на выводы о пропускной способности не годится)
            pg = sh("docker", "exec", CL_NAME, "ping", "-c", "20", "-i", "0.2", "-W", "2", INET, check=False).stdout
            res["ping_after_restart"] = ping_stats(pg)
            dl = sh("docker", "exec", CL_NAME, "curl", "-s", "-m", "60", "-o", "/dev/null", "-w", "%{size_download} B %{speed_download} B/s %{time_total} s", f"http://{INET}/big", check=False).stdout
            res["download_16MiB_after_restart"] = dl
            cst = fresh_status(CL_NAME, time.time() - 1, 30)

            def find(o, key, out):
                if isinstance(o, dict):
                    if key in o:
                        out.append({k: o.get(k) for k in ("kind", "path_desc", "max_datagram_size", "current_mtu", "black_holes_detected", "datagram_mtu_drops", "paths_detail")})
                    for v in o.values():
                        find(v, key, out)
                elif isinstance(o, list):
                    for v in o:
                        find(v, key, out)
            pj = []
            find(cst, "path_desc", pj)
            res["client_path_after_restart"] = pj[:2]
            res["client_carrier_after_restart"] = [(x.get("name"), x.get("carrier")) for x in (cst.get("servers") or cst.get("exits") or []) if isinstance(x, dict)]
            st = fresh_status(ADM_NAME, time.time() - 1, 30)
            res["exit_reality_after_restart"] = {k: v for k, v in ((st.get("tun") or {}).get("reality") or st.get("reality") or {}).items() if k != "server"}
            res["exit_reality_server_after_restart"] = ((st.get("tun") or {}).get("reality") or st.get("reality") or {}).get("server")
        res["client_log_after_restart"] = sh("docker", "exec", CL_NAME, "sh", "-c", "grep -i 'reality' /state/client.log | tail -4", check=False).stdout.splitlines()
    finally:
        print(json.dumps(res, ensure_ascii=False, indent=1))
        (LAB.parent / "realityfail.json").write_text(json.dumps(res, ensure_ascii=False, indent=1))
        if not a.keep:
            perf_down()



# ---------------------------------------------------------------------------------------------------- blockfail: прямой путь к выходу закрыт с самого начала
def cmd_blockfail(a):
    """Клиент стартует, когда прямой путь к выходу уже заблокирован (как телефон на пилоте). --kind dpi: UDP 47001 drop, TCP 47001 соединяется, данные нет;
    drop: оба молча drop; asym: клиент->выход UDP проходит, выход->клиент UDP режется. --reality: на выходе REALITY (:8443), --rl-block: порт REALITY тоже закрыт.
    Меряет: время до первого ответа через туннель, число допусков/закрытий Link на выходе, ping 0,5 с за --secs."""
    res = {"scenario": "blockfail", "kind": a.kind, "reality": a.reality, "rl_block": a.rl_block}
    res_dir = LAB.parent / "results"
    res_dir.mkdir(parents=True, exist_ok=True)
    t_start = [0.0]

    def block():
        if a.reality:
            sh("docker", "exec", "-d", SITE_NAME, "python3", "/lab/lab_web.py", "cover")
        rules = []
        if a.kind in ("dpi", "drop", "sym"):
            rules.append(("-p", "udp", "--dport", "47001"))
            rules.append(("-p", "tcp", "--dport", "47001", "!", "--syn") if a.kind == "dpi" else ("-p", "tcp", "--dport", "47001"))
        elif a.kind == "asym":
            rules.append(("-p", "udp", "--sport", "47001"))
        if a.rl_block:
            rules.append(("-p", "tcp", "--dport", str(RL_PORT)))
        for r in rules:
            chain = "OUTPUT" if a.kind == "asym" and r[2] == "--sport" else "INPUT"
            peer = ("-d" if chain == "OUTPUT" else "-s", "172.29.101.30")   # блок только для клиента: T и остальные ноды выхода видят
            dx(ADM_NAME, "iptables", "-I", chain, *peer, *r, "-j", "DROP")
        t_start[0] = time.time()

    extra = f" --reality-listen 0.0.0.0:{RL_PORT} --reality-dest {SITE_IP}:443 --reality-sni {RL_SNI} --reality-public-port {RL_PORT}" if a.reality else ""
    os.environ["LAB_NODE_EXTRA_ADM"] = extra
    try:
        os.environ["LAB_NODE_EXTRA"] = extra
        # mesh_up сам выставляет LAB_NODE_EXTRA для T и сбрасывает; для adm она берётся здесь, до cmd_up
        mesh_up_blk(block)
        res["tunnel_up_s"] = round(time.time() - t_start[0], 1)
        sh("docker", "exec", "-d", CL_NAME, "sh", "-c", f"ping -D -i 0.5 -W 1 {INET} > /tmp/pingblk.txt 2>&1")
        t0 = time.time()
        time.sleep(a.secs)
        res["ping"] = rl_ping_outage(t0)
        nl = dx(ADM_NAME, "sh", "-c", "grep -a -c 'admitted on' /state/node.log; grep -a -c 'close link' /state/node.log; grep -a 'quic accepted' /state/node.log | wc -l", check=False).stdout.split()
        res["exit_admitted_closed_quic_accepted"] = nl
        res["exit_log"] = dx(ADM_NAME, "sh", "-c", "grep -a 'admitted on\\|close link\\|quic accepted\\|packet interface\\|reality' /state/node.log | cut -c1-170 | tail -40", check=False).stdout.splitlines()
        res["client_log"] = dx(CL_NAME, "sh", "-c", "grep -a -v 'снимок' /state/client.log | grep -a 'mesh\\|REALITY\\|reality\\|заблокирован\\|выход .* принял\\|Link\\|TCP\\|QUIC' | cut -c1-200 | tail -40", check=False).stdout.splitlines()
        res["client_path"] = client_path()
        if a.restart:
            # зачисленный клиент (как телефон) перезапускается при том же блоке: время до первого ответа через туннель и шторм Link за 120 с
            sh("docker", "restart", "-t", "1", CL_NAME)
            t1 = time.time()
            def after():
                sh("docker", "exec", CL_NAME, "ip", "route", "replace", f"{INET}/32", "dev", "tun0", check=False)
                return rl_curl(2)
            res["restart_to_traffic_s"] = round(time.time() - t1, 1) if rl_wait(after, 240, "restart") else None
            time.sleep(120)
            res["after_restart_admitted_closed"] = dx(ADM_NAME, "sh", "-c", "grep -a -c 'admitted on' /state/node.log; grep -a -c 'close link' /state/node.log", check=False).stdout.split()
            res["after_restart_ping_curl"] = rl_curl(3)
        st = fresh_status(CL_NAME, time.time())
        res["client_mesh"] = {k: v for k, v in (st.get("tun", {}).get("mesh") or {}).items() if v}
        res["exit_mesh"] = {k: v for k, v in (fresh_status(ADM_NAME, time.time()).get("tun", {}).get("mesh") or {}).items() if v}
    finally:
        print(json.dumps(res, ensure_ascii=False, indent=1))
        (res_dir / f"blockfail-{a.kind}-{int(a.reality)}{int(a.rl_block)}.json").write_text(json.dumps(res, ensure_ascii=False, indent=1))
        if not a.keep:
            mesh_down()


def mesh_up_blk(block):
    mesh_up(1, direct=True, pre_client=block)


# ---------------------------------------------------------------------------------------------------- rootless: сеть без корня (ADR 0028)
def kd(c, *args, check=True):
    """knothopd внутри контейнера; JSON-ответ или None."""
    r = sh("docker", "exec", c, "knothopd", *args, check=check)
    try:
        return json.loads(r.stdout)
    except ValueError:
        return r.stdout.strip()


def wait_until(pred, secs, what, step=1.0):
    t0 = time.time()
    while time.time() - t0 < secs:
        try:
            v = pred()
        except Exception:                   # noqa: BLE001 - опрос: нода ещё поднимается
            v = None
        if v:
            return time.time() - t0
        time.sleep(step)
    sys.exit(f"rootless: не дождался: {what} ({secs} с)")


def whoami_hash(c):
    return kd(c, "whoami", "--state", "/state")["hash"]


def view(c):
    return kd(c, "list", "--state", "/state")


def issue_invite(src, *args):
    """Строка приглашения выпускается нодой src в файл 0600 и читается оттуда; в argv и логи она не попадает."""
    path = f"/state/.inv-{os.getpid()}-{time.time_ns()}"
    sh("docker", "exec", src, "knothopd", "invite", "--state", "/state", "--out", path, *args)
    try:
        return sh("docker", "exec", src, "cat", path).stdout.strip()
    finally:
        sh("docker", "exec", src, "shred", "-u", path, check=False)


def put_invite(name, text):
    write_private(state_dir(name) / "invite.txt", text)


def own_root(c):
    """Файл приглашения создан пользователем лаборатории; нода в контейнере работает от root и требует своего владельца (0600)."""
    sh("docker", "exec", c, "sh", "-c", "chown root:root /state/invite.txt && chmod 600 /state/invite.txt")


def outbox_all_applied(c, targets=None):
    ob = view(c)["outbox"]
    mine = [o for o in ob if targets is None or o["target"] in targets]
    return bool(mine) and all(o["state"] == "applied" for o in mine)


def node_links(c):
    """Хеши соседей-серверов с живым Link (из status.json ноды)."""
    r = sh("docker", "exec", c, "cat", "/state/status.json", check=False)
    try:
        st = json.loads(r.stdout)
    except ValueError:
        return set()
    return set(range(int(st.get("links", 0))))


SRV_IPS = {}


def curl_exit(c, secs=8):
    """Имя выхода, через который пришёл запрос к «интернету» (сайт отвечает адресом источника = адрес контейнера выхода за NAT)."""
    r = sh("docker", "exec", c, "curl", "-s", "-m", str(secs), f"http://{INET}/", check=False)
    try:
        src = json.loads(r.stdout)["you_are"]
    except (ValueError, KeyError):
        return None
    return next((n for n, ip in SRV_IPS.items() if ip == src), src)


def forged_invite(admin_hash):
    """Строка приглашения с верным хешем админа и неверным пином (тот же формат, что в invite.rs)."""
    import base64
    import hashlib
    body = bytes([1, 1]) + bytes.fromhex(admin_hash) + b"\x55" * 16
    body += hashlib.sha256(b"knothop-invite-v5" + body).digest()[:4]
    return base64.urlsafe_b64encode(body).decode().rstrip("=")


def cmd_rootless(a):
    res = {"scenario": "rootless"}
    T = {}
    t_all = time.time()
    if not BIN.exists():
        sys.exit(f"нет {BIN}: bash bench/cargo_fork.sh rns-iroh-node build --offline --locked --bin knothopd")
    if ISOLATED_ROOTLESS:
        if LAB.exists() or sh("docker", "network", "inspect", NET, check=False).returncode == 0:
            sys.exit("изолированный rootless требует новый каталог и новую сеть; существующее состояние не удаляется")
        names = [f"{PREFIX}-{n}" for n in ROOTLESS_NAMES] + [HUB_NAME, SITE_NAME]
        if any(sh("docker", "inspect", name, check=False).returncode == 0 for name in names):
            sys.exit("изолированный rootless требует уникальные имена контейнеров; существующие не удаляются")
    else:
        cmd_down(a)
    shutil_rmtree = __import__("shutil").rmtree
    if not ISOLATED_ROOTLESS:
        shutil_rmtree(LAB, ignore_errors=True)
    sh("docker", "network", "create", "--subnet", SUBNET, NET)
    hub = state_dir("hub")
    run(HUB_NAME, HUB_IP, "exec knothopd hub --state /state --port 47000 --tcp-port 4242", hub)
    run(SITE_NAME, SITE_IP, "exec python3 /lab/lab_web.py site", hub)
    wait_until(lambda: sh("docker", "exec", SITE_NAME, "ip", "addr", "add", f"{INET}/32", "dev", "lo", check=False).returncode == 0, 20, "адрес «интернета» на сайте")
    # админ — клиентская нода без приглашений (как телефон): корня нет, он просто первый, кто выпускает коды
    d = state_dir("adm"); write_pub(d)
    run("adm", next_ip(), client_cmd("", False), d)
    wait_file("adm", "/state/identity.key")
    wait_until(lambda: view("adm").get("me"), 30, "ядро админа")
    adm = whoami_hash("adm")
    # 1. три сервера стартуют с пустым state по коду админа
    t0 = time.time()
    srv = {}
    for n in ("s1", "s2", "s3"):
        d = state_dir(n); write_pub(d)
        put_invite(n, issue_invite("adm", "--rights", "use"))
        ip = next_ip()
        pre = ("printf '%s' '{\"version\":1,\"aliases\":[],\"allow\":[]}' > /state/host-acl.json; chmod 600 /state/host-acl.json; "
               f"ip route replace {INET}/32 via {SITE_IP}; ")
        run(n, ip, pre + node_cmd(n, ip, None, True), d)
        srv[n] = {"ip": ip}
        SRV_IPS[n] = ip
    for n in srv:
        wait_file(n, "/state/server.json")
        srv[n]["hash"] = whoami_hash(n)
    T["join_first_s"] = None
    for n in srv:
        dt = wait_until(lambda n=n: adm in view(n).get("controllers", []), 240, f"{n}: админ управляет нодой")
        T["join_first_s"] = min(T["join_first_s"] or 1e9, time.time() - t0)
        srv[n]["joined_s"] = round(time.time() - t0, 1)
    T["join_all_s"] = round(time.time() - t0, 1)
    print("серверы вступили:", {n: v["joined_s"] for n, v in srv.items()})
    # 2. роли: s1 — выход+транзит, s2/s3 — транзит (быть PN, relay и пересылать)
    hs = {n: v["hash"] for n, v in srv.items()}
    kd("adm", "peers", "config", "--state", "/state", "--target", hs["s1"], "--transit", "true", "--exit", "true")
    kd("adm", "peers", "config", "--state", "/state", "--target", hs["s2"], "--transit", "true")
    kd("adm", "peers", "config", "--state", "/state", "--target", hs["s3"], "--transit", "true")
    T["config_s"] = round(wait_until(lambda: outbox_all_applied("adm", set(hs.values())), 120, "config.set применён"), 1)
    # 3. знакомство нод: пакеты операций ставит админ, дальше ноды сами
    t1 = time.time()
    if a.offline_node:
        sh("docker", "stop", "-t", "1", "s3")
    kd("adm", "introduce", "--state", "/state", "--nodes", ",".join(hs.values()), "--rights", "server")
    online = {h for n, h in hs.items() if not (a.offline_node and n == "s3")}
    wait_until(lambda: outbox_all_applied("adm", online) , 120, "пакеты знакомства применены на доступных нодах")
    T["introduce_applied_s"] = round(time.time() - t1, 1)
    if a.offline_node:
        time.sleep(45)         # копия на PN уходит после 30 с без ответа
    sh("docker", "stop", "-t", "1", "adm")       # админа нет: ноды гасят приглашения сами
    if a.offline_node:
        sh("docker", "start", "s3")
    def full_mesh():
        for n in srv:
            v = view(n)
            known = {p["hash"] for p in v["peers"] if p["rights"]}
            others = {h for m, h in hs.items() if m != n}
            if not others <= known or len([c for c in v["contacts"] if c["hash"] in others]) < len(others):
                return False
        return True
    T["mesh_table_s"] = round(wait_until(full_mesh, 600 if a.offline_node else 180, "полная таблица (пиры+контакты) на всех серверах") + (time.time() - t1) - 0, 1)
    def quic_mesh():
        for n in srv:
            if len(node_links(n)) < 2:
                return False
        return True
    try:
        T["mesh_links_s"] = round(wait_until(quic_mesh, 120, "Link между всеми серверами") + (time.time() - t1), 1)
    except SystemExit:
        T["mesh_links_s"] = None
    res["links"] = {n: sorted(node_links(n)) for n in srv}
    # 4. админ возвращается; приглашение для клиента на все три ноды (клиент = USE на всех, EXIT — свойство s1)
    sh("docker", "start", "adm")
    wait_until(lambda: view("adm").get("me"), 60, "админ вернулся")
    t2 = time.time()
    inv = issue_invite("adm", "--nodes", ",".join(hs.values()), "--rights", "user")
    wait_until(lambda: outbox_all_applied("adm", set(hs.values())), 120, "invite.add применён на всех нодах")
    T["invite_ready_s"] = round(time.time() - t2, 1)
    d = state_dir("cl"); write_pub(d); put_invite("cl", inv)
    run("cl", next_ip(), client_cmd("", False), d)
    sh("docker", "exec", "cl", "sh", "-c", f"until ip link show tun0 >/dev/null 2>&1; do sleep 0.3; done; ip route replace {INET}/32 dev tun0")
    wait_file("cl", "/state/identity.key")
    wait_until(lambda: view("cl").get("me"), 30, "ядро клиента")
    t3 = time.time()
    own_root("cl")
    kd("cl", "join", "--state", "/state", "--invite-file", "/state/invite.txt")
    cl = whoami_hash("cl")
    T["client_join_s"] = round(wait_until(lambda: len(view("cl")["contacts"]) == 3 and not view("cl")["pending"]["pairs"], 180, "клиент погасил все три пары"), 1)
    # 5. трафик через выход
    T["traffic_s"] = round(wait_until(lambda: curl_exit("cl") == "s1", 120, "трафик через выход s1") + (time.time() - t3), 1)
    res["site_src"] = curl_exit("cl")
    # 6. блок прямого пути клиент→выход: обход через транзит (s2/s3 знают клиента и s1)
    sh("docker", "exec", "cl", "sh", "-c", f"iptables -I OUTPUT -d {srv['s1']['ip']} -j DROP; iptables -I INPUT -s {srv['s1']['ip']} -j DROP")
    t4 = time.time()
    time.sleep(2)
    T["bypass_s"] = round(wait_until(lambda: curl_exit("cl", 4) == "s1", 180, "обход блока через транзит") + (time.time() - t4), 1)
    cs = json.loads(sh("docker", "exec", "cl", "cat", "/state/status.json").stdout)
    res["bypass_current"] = cs.get("current")
    res["transit_status"] = {n: json.loads(sh("docker", "exec", n, "cat", "/state/status.json").stdout).get("clients") for n in ("s2", "s3")}
    if ISOLATED_ROOTLESS and os.environ.get("LAB13_TRACE_POLICY") == "1":
        # Force a fresh Link without restarting the established mesh carrier.
        # This runs only in the disposable, namespaced laboratory; restore even
        # if observation of the disabled state times out.
        print("trace-policy: disabling isolated exit with direct path blocked", flush=True)
        try:
            kd("adm", "peers", "config", "--state", "/state", "--target", hs["s1"], "--exit", "false")
            wait_until(lambda: view("s1").get("exit_enabled") is False, 60, "s1 exit отключён")
            time.sleep(5)
        finally:
            kd("adm", "peers", "config", "--state", "/state", "--target", hs["s1"], "--exit", "true")
        wait_until(lambda: view("s1").get("exit_enabled") is True, 60, "s1 exit восстановлен")
        wait_until(lambda: curl_exit("cl", 4) == "s1", 180, "выход вернулся после разрешения")
        res["trace_policy_exit_restored"] = True
        print(json.dumps(res, ensure_ascii=False, indent=1), flush=True)
        return
    if ISOLATED_ROOTLESS and os.environ.get("LAB13_TRACE_MESH") == "1":
        # Leave the direct block in place while restarting only this isolated
        # exit. This forces a fresh Link and gives the trace a real opportunity
        # to observe request/proof on the mesh path, not merely a migrated Link.
        print("trace-mesh: restarting isolated exit with direct path blocked", flush=True)
        t_restart = time.time()
        sh("docker", "restart", "s1")
        wait_until(lambda: curl_exit("cl", 4) == "s1", 180, "выход вернулся при заблокированном прямом пути")
        cs = json.loads(sh("docker", "exec", "cl", "cat", "/state/status.json").stdout)
        current = cs.get("current") or {}
        quic = current.get("quic") or {}
        res["trace_mesh_restart_s"] = round(time.time() - t_restart, 1)
        res["trace_mesh_current_kind"] = quic.get("kind")
        if quic.get("kind") != "mesh":
            sys.exit("trace-mesh: трафик восстановился, но выбранный путь не подтверждён как mesh")
        print(json.dumps(res, ensure_ascii=False, indent=1), flush=True)
        return
    # 7. снятие USE у клиента на выходе → доступ потерян
    sh("docker", "exec", "cl", "sh", "-c", f"iptables -D OUTPUT -d {srv['s1']['ip']} -j DROP; iptables -D INPUT -s {srv['s1']['ip']} -j DROP")
    kd("adm", "peers", "remove", "--state", "/state", "--target", hs["s1"], "--hash", cl)
    t5 = time.time()
    wait_until(lambda: curl_exit("cl", 3) is None, 120, "клиент потерял выход после снятия USE")
    T["revoke_use_s"] = round(time.time() - t5, 1)
    # 7б. вернуть USE (запись новее надгробия), затем выключить exit_enabled на выходе: клиент теряет выход и по этой причине
    cl_pk = kd("cl", "whoami", "--state", "/state")["pk"]
    kd("adm", "peers", "set", "--state", "/state", "--target", hs["s1"], "--pk", cl_pk, "--rights", "use")
    t6 = time.time()
    T["restore_use_s"] = round(wait_until(lambda: curl_exit("cl", 4) == "s1", 180, "выход вернулся после повторной выдачи USE") + (time.time() - t6), 1)
    kd("adm", "peers", "config", "--state", "/state", "--target", hs["s1"], "--exit", "false")
    t7 = time.time()
    wait_until(lambda: curl_exit("cl", 3) is None, 120, "клиент потерял выход после exit_enabled=false")
    T["exit_off_s"] = round(time.time() - t7, 1)
    # 8. неверный пин → молчание; повтор приглашения вторым получателем → отказ
    d = state_dir("bad"); write_pub(d); put_invite("bad", forged_invite(adm))
    run("bad", next_ip(), client_cmd("", False), d)
    wait_file("bad", "/state/identity.key"); wait_until(lambda: view("bad").get("me"), 30, "ядро bad")
    own_root("bad")
    kd("bad", "join", "--state", "/state", "--invite-file", "/state/invite.txt")
    open_before = [i for i in view("adm")["invites"] if i["state"] == "open"]
    time.sleep(45)
    bad = view("bad")
    res["wrong_pin"] = {"bad_contacts": len(bad["contacts"]), "bad_pending_pairs": len(bad["pending"]["pairs"]),
                        "adm_open_invites_unchanged": len([i for i in view("adm")["invites"] if i["state"] == "open"]) == len(open_before),
                        "adm_knows_bad": any(p["hash"] == whoami_hash("bad") for p in view("adm")["peers"])}
    inv2 = issue_invite("adm", "--rights", "user")
    d = state_dir("c1"); write_pub(d); put_invite("c1", inv2)
    run("c1", next_ip(), client_cmd("", False), d)
    d = state_dir("c2"); write_pub(d); put_invite("c2", inv2)
    run("c2", next_ip(), client_cmd("", False), d)
    for c in ("c1", "c2"):
        wait_file(c, "/state/identity.key"); wait_until(lambda c=c: view(c).get("me"), 30, f"ядро {c}")
    own_root("c1"); own_root("c2")
    kd("c1", "join", "--state", "/state", "--invite-file", "/state/invite.txt")
    wait_until(lambda: len(view("c1")["contacts"]) == 1, 120, "первый получатель погасил")
    kd("c2", "join", "--state", "/state", "--invite-file", "/state/invite.txt")
    time.sleep(40)
    v2 = view("c2")
    res["second_redeemer"] = {"contacts": len(v2["contacts"]), "pending_pairs": len(v2["pending"]["pairs"]),
                              "adm_has_c2": any(p["hash"] == whoami_hash("c2") for p in view("adm")["peers"])}
    T["total_s"] = round(time.time() - t_all, 1)
    res["times"] = T
    res["nodes"] = {n: v["hash"][:8] for n, v in srv.items()}
    print(json.dumps(res, ensure_ascii=False, indent=1))
    if not a.keep and not ISOLATED_ROOTLESS:
        cmd_down(a)


# ---------------------------------------------------------------------------------------------------- p2p: два клиента без серверов
def p2p_status(c):
    """Список p2p из status.json клиента: {id(hex 32): запись}."""
    r = sh("docker", "exec", c, "cat", "/state/status.json", check=False)
    try:
        return {e["id"]: e for e in json.loads(r.stdout).get("p2p", [])}
    except ValueError:
        return {}


def cmd_p2p(a):
    """A выпускает приглашение на себя, B гасит (LXMF через «публичную RNS» - хаб); дальше QUIC между ними по ЛОКАЛЬНОЙ СЕТИ
    (адреса Docker 172.29.98.0/24 - подсеть интерфейса eth0; KNOTHOP_ALLOW_PRIVATE_DIAL не задан: работает только исключение для контактов); затем блок между ними - статус должен честно стать «не отвечает», а не вечное «подключаюсь»."""
    res = {"scenario": "p2p"}
    T = {}
    t_all = time.time()
    if not BIN.exists():
        sys.exit(f"нет {BIN}: bash bench/cargo_fork.sh rns-iroh-node build --offline --locked --bin knothopd")
    cmd_down(a)
    __import__("shutil").rmtree(LAB, ignore_errors=True)
    sh("docker", "network", "create", "--subnet", SUBNET, NET)
    hub = state_dir("hub")
    run(HUB_NAME, HUB_IP, "exec knothopd hub --state /state --port 47000 --tcp-port 4242", hub)
    ips = {}
    for n in ("pa", "pb"):
        d = state_dir(n); write_pub(d)
        ips[n] = next_ip()
        run(n, ips[n], client_cmd("", False), d, private_dial=False)   # без KNOTHOP_ALLOW_PRIVATE_DIAL: путь только по LAN-исключению для контактов
    for n in ips:
        wait_file(n, "/state/identity.key")
        wait_until(lambda n=n: view(n).get("me"), 40, f"ядро {n}")
    ha, hb = whoami_hash("pa"), whoami_hash("pb")
    # A выпускает приглашение на себя (никаких других узлов), B гасит
    inv = issue_invite("pa", "--rights", "use")
    put_invite("pb", inv)
    own_root("pb")
    t0 = time.time()
    kd("pb", "join", "--state", "/state", "--invite-file", "/state/invite.txt")
    wait_until(lambda: view("pb")["contacts"] and not view("pb")["pending"]["pairs"], 240, "B погасил приглашение A")
    T["redeem_s"] = round(time.time() - t0, 1)
    wait_until(lambda: any(c["hash"] == hb for c in view("pa")["contacts"]), 120, "A получил контакт B из ack (обратный дозвон)")
    T["ack_contact_s"] = round(time.time() - t0, 1)
    va, vb = view("pa"), view("pb")
    res["rights"] = {"B_on_A": next((p["rights"] for p in va["peers"] if p["hash"] == hb), 0), "A_on_B": next((p["rights"] for p in vb["peers"] if p["hash"] == ha), 0)}
    res["hints_count"] = {"A_has_B": next(c["hints"] for c in va["contacts"] if c["hash"] == hb), "B_has_A": next(c["hints"] for c in vb["contacts"] if c["hash"] == ha)}
    # QUIC между ними
    wait_until(lambda: p2p_status("pa").get(hb, {}).get("state") == "direct" and p2p_status("pb").get(ha, {}).get("state") == "direct", 150, "прямое соединение A<->B")
    T["direct_s"] = round(time.time() - t0, 1)
    res["direct"] = {"A": p2p_status("pa")[hb], "B": p2p_status("pb")[ha]}
    assert res["direct"]["A"].get("lan") and res["direct"]["B"].get("lan"), f"путь должен быть помечен как локальная сеть: {res['direct']}"
    # блок между ними (оба направления): QUIC умирает по таймауту простоя, набор не удаётся
    for n, other in (("pa", "pb"), ("pb", "pa")):
        sh("docker", "exec", n, "sh", "-c", f"iptables -I OUTPUT -d {ips[other]} -j DROP; iptables -I INPUT -s {ips[other]} -j DROP")
    t1 = time.time()
    wait_until(lambda: p2p_status("pa").get(hb, {}).get("state") == "unreachable", 240, "статус «не отвечает» после блока")
    T["unreachable_s"] = round(time.time() - t1, 1)
    res["blocked"] = {"A": p2p_status("pa")[hb], "B": p2p_status("pb").get(ha)}
    # права и выход не изменились ни от адресов, ни от блока: у B нет EXIT, выход через A недоступен
    res["rights_after"] = {"B_on_A": next((p["rights"] for p in view("pa")["peers"] if p["hash"] == hb), 0)}
    T["total_s"] = round(time.time() - t_all, 1)
    res["times"] = T
    print(json.dumps(res, ensure_ascii=False, indent=1))
    if not a.keep:
        cmd_down(a)


ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
sp = ap.add_subparsers(dest="c", required=True)
x = sp.add_parser("up"); x.add_argument("--phone", action="store_true", help="опубликовать порт adm на LAN-адресе ноутбука для телефона"); x.add_argument("--no-adm", action="store_true", help="без ноды adm (админом будет клиент: lab13.py admin NAME)"); x.set_defaults(f=cmd_up)
for nm, fn, rt in (("node", cmd_node, "relay"), ("client", cmd_client, "user")):
    x = sp.add_parser(nm); x.add_argument("name", type=valid_name); x.add_argument("--rights", default=rt); x.add_argument("--from", dest="src", type=valid_name, default=ADM_NAME); x.add_argument("--root", default=""); x.add_argument("--only-ip", default=""); x.add_argument("--nodes", default="")
    x.add_argument("--invite", default="", help="готовое приглашение kh-… (например, из приложения на телефоне) вместо выдачи с контейнера --from")
    x.add_argument("--invite-file", default="", help="файл с готовым приглашением (предпочтительно; секрет не передаётся в argv)")
    x.add_argument("--phone-port", type=int, default=0, help="опубликовать порт ноды на LAN-адресе ноутбука и объявить его (для телефона)")
    x.add_argument("--auto-adv", action="store_true", help="без --advertise: адрес с интерфейса, перепроверка раз в 60 с (смена IP)"); x.set_defaults(f=fn)
for nm, fn in (("admin", cmd_admin), ("restart", cmd_restart), ("wipe", cmd_wipe), ("test", cmd_test)):
    x = sp.add_parser(nm); x.add_argument("name", type=valid_name); x.set_defaults(f=fn)
x = sp.add_parser("list"); x.add_argument("name", nargs="?", type=valid_name, default="adm"); x.set_defaults(f=cmd_list)
x = sp.add_parser("logs"); x.add_argument("name", type=valid_name); x.add_argument("n", nargs="?", type=int, default=40); x.set_defaults(f=cmd_logs)
x = sp.add_parser("down"); x.set_defaults(f=cmd_down)
x = sp.add_parser("perf", help="A/B замер KNOTHOP_DIRECT_DATA=0/1: выход и клиент по 1 ядру, iperf3 за выходом")
x.add_argument("--pairs", type=int, default=3, help="число пар (0,1) вперемешку")
x.add_argument("--modes", default="", help="явный порядок режимов, например 1,0,1")
x.add_argument("--secs", type=int, default=10)
x.add_argument("--negative", action="store_true", help="вместо A/B: отзыв прав клиента под нагрузкой при включённом прямом канале")
x.add_argument("--blackhole", action="store_true", help="с --negative: выход не отвечает клиенту (клиент не видит закрытия Link и шлёт дальше)")
x.add_argument("--keep", action="store_true", help="не убирать стенд после замера")
x.set_defaults(f=cmd_perf)
x = sp.add_parser("meshfail", help="переключение прямой -> тёплый mesh при блоке выхода и при потере сети клиентом")
x.add_argument("--repeats", type=int, default=3)
x.add_argument("--keep", action="store_true")
x.set_defaults(f=cmd_meshfail)
x = sp.add_parser("meshperf", help="A/B KNOTHOP_MESH=0/1 в топологии клиент–T–выход (клиент не достаёт до выхода по IP)")
x.add_argument("--pairs", type=int, default=3)
x.add_argument("--secs", type=int, default=10)
x.add_argument("--keep", action="store_true")
x.set_defaults(f=cmd_meshperf)
x = sp.add_parser("blockfail", help="клиент стартует при уже закрытом прямом пути к выходу (dpi|drop|asym), выход достижим через T; --reality/--rl-block")
x.add_argument("--kind", default="dpi", choices=["none", "dpi", "drop", "asym"]); x.add_argument("--reality", action="store_true"); x.add_argument("--rl-block", action="store_true")
x.add_argument("--secs", type=int, default=300); x.add_argument("--restart", action="store_true"); x.add_argument("--keep", action="store_true"); x.set_defaults(f=cmd_blockfail)
x = sp.add_parser("realityfail", help="REALITY: UDP и TCP:47001 к выходу закрыты, открыт только TCP на порт REALITY (без Traefik); клиент переходит на REALITY")
x.add_argument("--keep", action="store_true")
x.add_argument("--control", action="store_true", help="без REALITY, закрыт только UDP (эталон: TCP-носитель)")
x.add_argument("--idle", type=int, default=0, help="после блока N секунд без трафика, затем ping выхода; время восстановления считается от начала ping")
x.add_argument("--unblock", type=int, default=0, help="после проверок снять блок и ждать N секунд (возврат на QUIC)")
x.set_defaults(f=cmd_realityfail)
x = sp.add_parser("rootless", help="ADR 0028: сеть без корня (3 сервера по коду админа, знакомство, клиент, обход блока, отзыв)")
x.add_argument("--offline-node", action="store_true", help="s3 выключен при знакомстве, админ уходит, письмо ждёт на PN (долго: ждёт анонс PN)")
x.add_argument("--keep", action="store_true"); x.set_defaults(f=cmd_rootless)
x = sp.add_parser("p2p", help="P2P без серверов: A выпускает на себя, B гасит, QUIC между ними, затем блок - честный статус")
x.add_argument("--keep", action="store_true"); x.set_defaults(f=cmd_p2p)
a = ap.parse_args()
a.f(a)
