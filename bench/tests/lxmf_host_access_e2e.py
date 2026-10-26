#!/usr/bin/env python3
"""E2E HOST_ACCESS + прямой LXMF-админ в изолированной Docker-лаборатории (только локально, без публичной RNS).

Цепь: «телефон» (admin: knothopd client + драйвер, мост admin_cli_json в процессе) -> direct LXMF -> нода-выход (NodeCtx)
-> подписанная запись HOST_ACCESS -> durable save -> подписанный app-ACK -> смена ACL уже существующего Link (usr: клиент с TUN).

  lxmf_host_access_e2e.py up           поднять сеть, hub, site, admin, exit1, usr (идемпотентно)
  lxmf_host_access_e2e.py run [--only A,B]   сценарии (требует up), результат -> results JSON и stdout
  lxmf_host_access_e2e.py down         убрать контейнеры и сеть (состояние остаётся)
  lxmf_host_access_e2e.py wipe         убрать контейнеры, сеть и состояние лаборатории

Окружение: E2E_BIN (knothopd), E2E_DRIVER (драйвер), E2E_ROOT (состояние, по умолчанию ~/.cache/knothop-lxe2e/lab),
E2E_PREFIX (lxe2e), E2E_SUBNET (172.29.97.0/24). Образ knothop-bench:l3 (уже локальный). Секретов в выводе нет:
identity, приглашения и ключи лаборатории синтетические, приглашение создаётся в файле 0600 и удаляется.
Никаких host-global nft/ssh/публичных адресов; «интернет» - 1.1.1.1 на lo контейнера site (маршрут только в netns выхода).
"""
import argparse
import json
import os
import re
import subprocess
import sys
import time
from pathlib import Path

HERE = Path(__file__).resolve().parent
HOME = Path.home()
BIN = Path(os.environ.get("E2E_BIN", HOME / ".cache/knothop-lxe2e/bin/knothopd"))
DRIVER = Path(os.environ.get("E2E_DRIVER", HOME / ".cache/knothop-lxe2e/bin/driver"))
ROOT = Path(os.environ.get("E2E_ROOT", HOME / ".cache/knothop-lxe2e/lab"))
P = os.environ.get("E2E_PREFIX", "lxe2e")
NET = f"{P}-net"
SUBNET = os.environ.get("E2E_SUBNET", "172.29.97.0/24")
BASE = SUBNET.rsplit(".", 1)[0]
IMAGE = "knothop-bench:l3"
HUB_IP, SITE_IP, EXIT1_IP, EXIT2_IP = f"{BASE}.10", f"{BASE}.50", f"{BASE}.11", f"{BASE}.21"
INET_IP = "1.1.1.1"      # «интернет» (публичный по классификации ACL; живёт только на lo контейнера site)
HOST_PUB = "1.1.1.1"     # публичный адрес самого выхода (dummy0)
HOST_PRIV = "10.55.0.1"      # приватный адрес самого выхода (dummy1): требует точного allow
DOCKER_IP = "172.17.0.1"     # мост docker0 на выходе: исключён из инвентаря -> чужая приватная сеть
SVC_TUN = "10.99.0.1"        # служебный адрес khd0 выхода
OTHER_CLIENT = "198.19.99.9" # адрес другого клиента из пула
HOST_PORT = 8080
NAME = lambda n: f"{P}-{n}"


def sh(*a, check=True, timeout=120, inp=None):
    r = subprocess.run(a, capture_output=True, text=True, timeout=timeout, input=inp)
    if check and r.returncode:
        raise RuntimeError(f"{' '.join(a[:6])}...: rc={r.returncode} {(r.stderr or r.stdout).strip()[-500:]}")
    return r


def dx(name, *cmd, check=False, timeout=60):
    return sh("docker", "exec", NAME(name), *cmd, check=check, timeout=timeout)


def exists(name):
    return sh("docker", "inspect", "-f", "{{.State.Running}}", NAME(name), check=False).stdout.strip() == "true"


def sdir(name):
    d = ROOT / name
    ROOT.mkdir(parents=True, exist_ok=True)
    os.chmod(ROOT, 0o700)
    d.mkdir(parents=True, exist_ok=True)
    os.chmod(d, 0o700)
    return d


def run(name, ip, cmd, extra=()):
    sh("docker", "rm", "-f", NAME(name), check=False)
    sh("docker", "run", "-d", "--name", NAME(name), "--hostname", name, "--network", NET, "--ip", ip,
       "--cap-add", "NET_ADMIN", "--cap-add", "NET_RAW", "--device", "/dev/net/tun",
       "--sysctl", "net.ipv4.ip_forward=1", "-e", "KNOTHOP_DEBUG=1", "-e", "KNOTHOP_ALLOW_PRIVATE_DIAL=1", "-e", "KNOTHOP_TCP_BACKOFF_S=30",
       "-v", f"{BIN}:/usr/local/bin/knothopd:ro", "-v", f"{DRIVER}:/usr/local/bin/driver:ro", "-v", f"{HERE}:/e2e:ro",
       "-v", f"{sdir(name)}:/state", *extra, "--entrypoint", "sh", IMAGE, "-c", cmd)


def wait(fn, secs, what, step=0.5):
    t0 = time.time()
    last = None
    while time.time() - t0 < secs:
        try:
            last = fn()
            if last:
                return last
        except Exception as e:  # noqa: BLE001
            last = e
        time.sleep(step)
    raise TimeoutError(f"{what}: нет за {secs} с (последнее: {str(last)[:200]})")


def jread(name, path):
    r = dx(name, "cat", path)
    return json.loads(r.stdout) if r.returncode == 0 and r.stdout.strip() else None


def whoami(name):
    r = dx(name, "knothopd", "whoami", "--state", "/state", check=True)
    return json.loads(r.stdout.strip().splitlines()[-1])


def make_invite(src, rights, label):
    path = f"/state/.inv-{os.getpid()}"
    dx(src, "knothopd", "invite", "--state", "/state", "--rights", rights, "--label", label, "--out", path, check=True)
    try:
        return dx(src, "cat", path, check=True).stdout.strip()
    finally:
        dx(src, "shred", "-u", path)


def write_private(name, rel, text):
    p = sdir(name) / rel
    fd = os.open(p, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
    with os.fdopen(fd, "w") as f:
        os.fchmod(fd, 0o600)
        f.write(text)


def put_file(name, rel, text, mode="600"):
    """Файл в состояние контейнера от root (узел требует владельца root/euid и режим 0600); текст идёт через stdin, не через argv."""
    sh("docker", "run", "--rm", "-i", "-v", f"{sdir(name)}:/state", "--entrypoint", "sh", IMAGE, "-c",
       f"umask 077; cat > /state/{rel}; chmod {mode} /state/{rel}", inp=text)


# Всё идемпотентно: при `docker restart` netns пересоздаётся, но при повторном запуске внутри живого netns команды не должны падать.
EXIT_NET_SETUP = (
    f"ip link add dummy0 type dummy 2>/dev/null; ip addr replace {HOST_PUB}/32 dev dummy0; ip link set dummy0 up; "
    f"ip link add dummy1 type dummy 2>/dev/null; ip addr replace {HOST_PRIV}/32 dev dummy1; ip link set dummy1 up; "
    f"ip link add docker0 type dummy 2>/dev/null; ip addr replace {DOCKER_IP}/16 dev docker0; ip link set docker0 up; "
    f"ip route replace {INET_IP}/32 via {SITE_IP}; "
    "iptables -t nat -C POSTROUTING -s 198.18.0.0/15 -o eth0 -j MASQUERADE 2>/dev/null || iptables -t nat -A POSTROUTING -s 198.18.0.0/15 -o eth0 -j MASQUERADE; "
    "iptables -C OUTPUT -d 198.18.0.0/15 -p udp --sport 47001 -j DROP 2>/dev/null || iptables -I OUTPUT -d 198.18.0.0/15 -p udp --sport 47001 -j DROP; "
    "python3 /e2e/lxmf_host_access_e2e_services.py web 8080 & "
    "python3 /e2e/lxmf_host_access_e2e_services.py udplog 9998 /state/udp-host.log & "
)


def exit_cmd(name, ip, acl, policy_root=None):
    """acl: текст host-acl.json (None - файл не создавать: узел обязан отказаться стартовать). policy_root: корень, которому
    оператор разрешает выдавать HOST_ACCESS на этой ноде (host-policy.json, M5); None - политики нет."""
    pre = ""
    if acl is not None:
        pre += f"[ -e /state/host-acl.json ] || printf '%s' '{acl}' > /state/host-acl.json; chmod 600 /state/host-acl.json; "
    if policy_root:
        pol = json.dumps({"v": 1, "roots": [{"root": policy_root, "max_holders": 16}]}, separators=(",", ":"))
        pre += f"[ -e /state/host-policy.json ] || printf '%s' '{pol}' > /state/host-policy.json; chmod 600 /state/host-policy.json; "
    return (EXIT_NET_SETUP + pre +
            f"knothopd node --state /state --name {name} --port 47001 --tun-name khd0 --advertise {ip}:47001 "
            "--public-rns-file /state/pub.txt --announce-s 10 --invite-file /state/invite.txt 2>&1 | tee -a /state/node.log")


# Адреса, которые клиент шлёт в TUN. Адрес eth0 выхода сюда не входит: маршрут на него увёл бы собственный носитель в TUN.
USR_ROUTE_IPS = (INET_IP, HOST_PUB, HOST_PRIV, DOCKER_IP, SVC_TUN)
USR_ROUTES = " ".join(f"ip route replace {ip}/32 dev tun0;" for ip in USR_ROUTE_IPS)


def client_cmd(invite=True, routes=True):
    inv = " --invite-file /state/invite.txt" if invite else ""
    return (f"knothopd client --state /state{inv} --public-rns-file /state/pub.txt >> /state/client.log 2>&1 & "
            f"until ip link show tun0 >/dev/null 2>&1; do sleep 0.3; done; {USR_ROUTES if routes else ''} wait")


def cmd_up(a):
    for p in (BIN, DRIVER):
        if not p.exists():
            sys.exit(f"нет {p}: собрать bench/cargo_fork.sh rns-iroh-node build --offline --locked --bin knothopd --example lxmf_host_access_e2e_driver")
    if sh("docker", "network", "inspect", NET, check=False).returncode:
        sh("docker", "network", "create", "--subnet", SUBNET, NET)
    hub = sdir("hub")
    if not exists("hub"):
        run("hub", HUB_IP, "exec knothopd hub --state /state --port 47000 --tcp-port 4242")
    if not exists("site"):
        run("site", SITE_IP, f"ip addr add {INET_IP}/32 dev lo; python3 /e2e/lxmf_host_access_e2e_services.py udplog 9999 /state/udp.log & "
            "exec python3 /e2e/lxmf_host_access_e2e_services.py web 80")
    for n in ("admin", "exit1", "exit2", "usr", "deleg", "foreign"):
        (sdir(n) / "pub.txt").write_text(f"{HUB_IP}:4242\n")
    if not exists("admin"):
        run("admin", f"{BASE}.12", "exec driver /run/ctl.sock /state -- client --state /state --public-rns-file /state/pub.txt")
        wait(lambda: dx("admin", "test", "-f", "/state/identity.key").returncode == 0, 40, "admin identity")
    root = whoami("admin")["hash"]
    acl = '{"version":1,"aliases":[],"allow":[]}'
    for n, ip in (("exit1", EXIT1_IP), ("exit2", EXIT2_IP)):
        if not exists(n):
            put_file(n, "invite.txt", make_invite("admin", "relay", n))
            run(n, ip, exit_cmd(n, ip, acl, policy_root=root))
            wait(lambda n=n: dx(n, "test", "-f", "/state/server.json").returncode == 0, 60, f"{n} server.json")
    # usr зачисляется ДО deleg: клиент получает только записи, существующие на момент его зачисления,
    # поэтому делегат не узнаёт «позже зачисленных» держателей (находка, см. отчёт).
    if not exists("usr"):
        put_file("usr", "invite.txt", make_invite("admin", "user", "usr"))
        run("usr", f"{BASE}.13", client_cmd())
        wait(lambda: root in (dx("usr", "cat", "/state/trust.json").stdout or ""), 90, "usr enrolled (admin root in trust)")
    # Клиент-делегат: пресет admin (ADD/REMOVE/...), свой LXMF-процесс; чужой корень: клиент без приглашения.
    drv = "exec driver /run/ctl.sock /state -- client --state /state --public-rns-file /state/pub.txt"
    if not exists("deleg"):
        put_file("deleg", "invite.txt", make_invite("admin", "admin", "deleg"))
        run("deleg", f"{BASE}.14", drv + " --invite-file /state/invite.txt")
    if not exists("foreign"):
        run("foreign", f"{BASE}.15", drv)
    print("up: hub, site, admin, exit1, exit2, usr, deleg, foreign запущены")


def cmd_down(a):
    names = sh("docker", "ps", "-a", "--filter", f"network={NET}", "--format", "{{.Names}}", check=False).stdout.split()
    for n in names:
        sh("docker", "rm", "-f", n, check=False)
    sh("docker", "network", "rm", NET, check=False)
    print("down: состояние в", ROOT)


def cmd_wipe(a):
    cmd_down(a)
    if ROOT.exists():
        sh("docker", "run", "--rm", "-v", f"{ROOT}:/l", "--entrypoint", "rm", IMAGE, "-rf", "/l/hub", "/l/site", "/l/admin", "/l/exit1", "/l/exit2",
           "/l/usr", "/l/usr2", "/l/deleg", "/l/foreign", "/l/bad1", "/l/bad2", "/l/bad3", check=False)
    print("wipe: готово")


def cmd_run(a):
    sys.path.insert(0, str(HERE))
    import lxmf_host_access_e2e_scenarios as S
    sys.exit(S.run(sys.modules[__name__], a))


def main():
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    sp = ap.add_subparsers(dest="c", required=True)
    sp.add_parser("up").set_defaults(f=cmd_up)
    r = sp.add_parser("run")
    r.add_argument("--only", default="", help="ID сценариев через запятую (по умолчанию все)")
    r.add_argument("--bench", action="store_true", help="после зелёных функциональных сценариев - малый замер издержек")
    r.set_defaults(f=cmd_run)
    sp.add_parser("down").set_defaults(f=cmd_down)
    sp.add_parser("wipe").set_defaults(f=cmd_wipe)
    a = ap.parse_args()
    a.f(a)


if __name__ == "__main__":
    main()
