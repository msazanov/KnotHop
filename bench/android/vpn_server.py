#!/usr/bin/env python3
"""Сервер-выход rawg VPN на ноутбуке: контейнер Docker (TUN + NAT в интернет) и HTTP-раздача профиля и APK.

  python3 vpn_server.py [--ip 192.168.31.239] [--http-port 8081] [--quic-port 47001]
  python3 vpn_server.py --stop

Контейнер `rawg-exit`: rns-iroh-node --role e --mode tun, UDP --quic-port опубликован на хост, исходящий трафик
клиентов (10.99.0.0/24) выходит в интернет через NAT контейнера и далее хоста. Привилегии: только NET_ADMIN и /dev/net/tun
в контейнере, хостовые сети и правила не трогаются. Тот же запуск без изменений годится для тестового сервера (там --ip - публичный адрес).

HTTP (локальная сеть): GET / (ссылка на APK), /rawgvpn.apk, /e.json (профиль выхода: адрес и ключи), POST /result (отчёт приложения).
Профиль отдаётся без аутентификации: годится для лаборатории, для реального сервера нужен спаривание/ключ (см. журнал, O32).
"""
import argparse
import os
import shutil
import signal
import subprocess
import sys
import tempfile
import threading
import time
from pathlib import Path

import laptop  # тот же каталог: обработчик HTTP и разбор отчёта

NAME = "rawg-exit"
IMAGE = "rawg-bench:l3"
BIN = laptop.BIN
APK = Path(os.environ.get("APK", str(Path.home() / ".cache/rawg-android/rawgvpn.apk")))


def docker(*a, check=True):
    return subprocess.run(["docker", *a], check=check, capture_output=True, text=True)


def main():
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--ip", default=laptop.default_ip(), help="адрес, который увидит клиент (LAN ноутбука или публичный адрес сервера)")
    ap.add_argument("--http-port", type=int, default=8081)
    ap.add_argument("--quic-port", type=int, default=47001)
    ap.add_argument("--quic-cc-mbit", type=int, default=500)
    ap.add_argument("--stop", action="store_true")
    a = ap.parse_args()
    docker("rm", "-f", NAME, check=False)
    if a.stop:
        return
    for p in (BIN, APK):
        if not p.exists():
            sys.exit(f"нет файла: {p}")
    laptop.APK = APK
    state = Path(tempfile.mkdtemp(prefix="rawg-vpn-", dir="/tmp/opencode" if Path("/tmp/opencode").is_dir() else None))
    os.chmod(state, 0o777)
    # Носитель не должен попадать в собственный туннель: iroh рассылает пирам все локальные адреса, и выход пробует путь к адресу
    # клиента в туннеле (10.99.0.2). QUIC уходит внутрь туннеля, путь рвётся при каждой смене сети (журнал N30).
    exit_cmd = (f"iptables -I OUTPUT -d 10.99.0.0/24 -p udp --sport {a.quic_port} -j DROP && "
                f"iptables -t nat -A POSTROUTING -s 10.99.0.0/24 ! -o tun0 -j MASQUERADE && "
                f"exec /usr/local/bin/rns-iroh-node --role e --mode tun --ip {a.ip} --port {a.quic_port} --relay none "
                f"--carrier datagram --dgram-mtu 1400 --cipher gcm --data-cap 4096 --chan-buf 4096 --quic-initial-mtu 1452 "
                f"--quic-cc tunnel --quic-cc-mbit {a.quic_cc_mbit} --tun-ip 10.99.0.1/24 --tun-mtu 1327 --tun-txqlen 10240 "
                f"--tun-qdisc fq_codel --announce-s 30 --state /state")
    r = docker("run", "-d", "--name", NAME, "--cap-add", "NET_ADMIN", "--device", "/dev/net/tun", "--sysctl", "net.ipv4.ip_forward=1",
               "-p", f"{a.quic_port}:{a.quic_port}/udp", "-v", f"{BIN}:/usr/local/bin/rns-iroh-node:ro", "-v", f"{state}:/state",
               "--entrypoint", "sh", IMAGE, "-c", exit_cmd, check=False)
    if r.returncode:
        sys.exit("docker run: " + r.stderr[-500:])
    t0 = time.time()
    while not (state / "e.json").exists():
        if time.time() - t0 > 30 or docker("inspect", "-f", "{{.State.Running}}", NAME, check=False).stdout.strip() != "true":
            sys.exit("выход не запустился:\n" + docker("logs", "--tail", "30", NAME, check=False).stdout[-1500:])
        time.sleep(0.3)
    srv = laptop.ThreadingHTTPServer(("0.0.0.0", a.http_port), laptop.make_handler(state))
    print(f"выход: UDP {a.ip}:{a.quic_port} (контейнер {NAME}); состояние {state}")
    print(f"APK:   http://{a.ip}:{a.http_port}/   (прямая: http://{a.ip}:{a.http_port}/rawgvpn.apk)")
    print(f"журнал выхода: docker logs -f {NAME}\nCtrl+C - остановить.", flush=True)
    signal.signal(signal.SIGTERM, lambda *_: threading.Thread(target=srv.shutdown, daemon=True).start())
    try:
        srv.serve_forever()
    except KeyboardInterrupt:
        pass
    finally:
        docker("rm", "-f", NAME, check=False)


if __name__ == "__main__":
    main()
