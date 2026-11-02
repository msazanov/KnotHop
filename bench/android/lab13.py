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
if sys.argv[1:2] == ["perf"]:
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
        ip = f"{BASE}.{i}"
        if ip not in used and ip not in (HUB_IP, SITE_IP):
            return ip
    sys.exit("нет свободных адресов")


def run(name, ip, cmd, state, extra=()):
    sh("docker", "rm", "-f", name, check=False)
    debug = ("-e", "KNOTHOP_DEBUG=1") if os.environ.get("LAB13_DEBUG", "1") != "0" else ()
    cpus = ("--cpuset-cpus", CPUSETS[name]) if name in CPUSETS else ()
    sh("docker", "run", "-d", "--name", name, "--hostname", name, "--network", NET, "--ip", ip, "--cap-add", "NET_ADMIN", "--device", "/dev/net/tun",
       "--sysctl", "net.ipv4.ip_forward=1", *debug, *cpus, "-e", "KNOTHOP_ALLOW_PRIVATE_DIAL=1", "-e", "KNOTHOP_TCP_BACKOFF_S=30",
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
    return (isolate(only_ip) + f"python3 /lab/lab_web.py whoami {name} & "
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


def measured(fn):
    c0 = (cpu_s(CL_NAME), cpu_s(ADM_NAME))
    t0 = time.time()
    res = fn()
    wall = time.time() - t0
    c1 = (cpu_s(CL_NAME), cpu_s(ADM_NAME))
    return res, {"wall_s": round(wall, 2), "cl_cpu_s": round(c1[0] - c0[0], 2), "adm_cpu_s": round(c1[1] - c0[1], 2)}


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
a = ap.parse_args()
a.f(a)
