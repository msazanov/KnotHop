#!/usr/bin/env python3
"""Ноутбучная сторона замера с телефоном: выход E (rns-iroh-node --mode meas) и HTTP-сервер.

  python3 laptop.py [--ip 192.168.31.239] [--http-port 8081] [--quic-port 47001]

HTTP (для телефона, только локальная сеть):
  GET  /               страница со ссылкой на APK
  GET  /rawgmeas.apk   установочный файл
  GET  /e.json         адрес и ключи выхода (меняются при каждом запуске E)
  POST /result         результат замера от телефона -> bench/results/android/<время>-<модель>.json
Носитель - QUIC/UDP на --quic-port: прямой путь по Wi-Fi, без relay и без внешних серверов.
"""
import argparse
import datetime
import json
import os
import re
import signal
import socket
import subprocess
import sys
import tempfile
import threading
import time
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path

HERE = Path(__file__).resolve().parent
RESULTS = HERE.parent / "results" / "android"
BIN = Path(os.environ.get("RNS_IROH_BIN", str(Path.home() / ".cache/rawg-target/dgram/release/rns-iroh-node")))
APK = Path(os.environ.get("APK", str(Path.home() / ".cache/rawg-android/rawgmeas.apk")))


def default_ip():
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    try:
        s.connect(("192.0.2.1", 9))  # ничего не отправляется, нужен только выбор интерфейса
        return s.getsockname()[0]
    finally:
        s.close()


def summary(r):
    res = r.get("result") or {}
    d = r.get("device", {})
    w = r.get("wifi_before", {})
    e = (res.get("echo_64") or {})
    return (f"{d.get('manufacturer')} {d.get('model')} (Android {d.get('release')}, {d.get('soc', d.get('hardware'))}) "
            f"Wi-Fi {w.get('frequency_mhz')} МГц {w.get('rssi_dbm')} dBm, link {w.get('rx_link_speed_mbps')}/{w.get('tx_link_speed_mbps')} Мбит/с | "
            f"RTT p50 {e.get('p50_ms')} p95 {e.get('p95_ms')} мс | вверх {res.get('best_up_mbit_s')} вниз {res.get('best_down_mbit_s')} Мбит/с"
            + (f" | ОШИБКА {r.get('error')}" if r.get("error") else ""))


def make_handler(state):
    class H(BaseHTTPRequestHandler):
        def log_message(self, fmt, *a):
            print(f"[http] {self.address_string()} {fmt % a}", flush=True)

        def _send(self, code, body, ctype="text/plain; charset=utf-8", extra=None):
            self.send_response(code)
            self.send_header("Content-Type", ctype)
            self.send_header("Content-Length", str(len(body)))
            for k, v in (extra or {}).items():
                self.send_header(k, v)
            self.end_headers()
            self.wfile.write(body)

        def do_GET(self):
            if self.path in ("/", "/index.html"):
                size = APK.stat().st_size if APK.exists() else 0
                html = (f"<meta name=viewport content='width=device-width'><h2>rawg замер</h2>"
                        f"<p><a href='/{APK.name}'>{APK.name}</a> ({size/1e6:.1f} МБ).</p>")
                self._send(200, html.encode(), "text/html; charset=utf-8")
            elif self.path.endswith(".apk") and self.path.startswith("/rawg") and APK.exists():
                self._send(200, APK.read_bytes(), "application/vnd.android.package-archive",
                           {"Content-Disposition": f"attachment; filename={APK.name}"})
            elif self.path == "/e.json" and (state / "e.json").exists():
                self._send(200, (state / "e.json").read_bytes(), "application/json")
            else:
                self._send(404, b"not found")

        def do_POST(self):
            if self.path != "/result":
                return self._send(404, b"not found")
            n = int(self.headers.get("Content-Length", "0"))
            raw = self.rfile.read(n)
            try:
                r = json.loads(raw)
            except json.JSONDecodeError:
                return self._send(400, b"bad json")
            RESULTS.mkdir(parents=True, exist_ok=True)
            model = re.sub(r"[^A-Za-z0-9_-]+", "", str(r.get("device", {}).get("model", "phone"))) or "phone"
            path = RESULTS / f"{datetime.datetime.now().strftime('%Y%m%d-%H%M%S')}-{model}.json"
            path.write_text(json.dumps(r, indent=1, ensure_ascii=False) + "\n", encoding="utf-8")
            print(f"[result] {path}\n[result] {summary(r)}", flush=True)
            self._send(200, b"ok")
    return H


def main():
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--ip", default=default_ip())
    ap.add_argument("--http-port", type=int, default=8081)
    ap.add_argument("--quic-port", type=int, default=47001)
    ap.add_argument("--quic-cc-mbit", type=int, default=500)
    a = ap.parse_args()
    for p in (BIN, APK):
        if not p.exists():
            sys.exit(f"нет файла: {p}")
    state = Path(tempfile.mkdtemp(prefix="rawg-android-", dir="/tmp/opencode" if Path("/tmp/opencode").is_dir() else None))
    os.chmod(state, 0o755)
    cmd = [str(BIN), "--role", "e", "--ip", a.ip, "--port", str(a.quic_port), "--relay", "none", "--mode", "meas",
           "--carrier", "datagram", "--dgram-mtu", "1400", "--cipher", "gcm", "--data-cap", "4096", "--chan-buf", "4096",
           "--quic-initial-mtu", "1452", "--quic-cc", "tunnel", "--quic-cc-mbit", str(a.quic_cc_mbit), "--state", str(state)]
    elog = open(state / "e.log", "wb")
    e = subprocess.Popen(cmd, stdout=elog, stderr=subprocess.STDOUT)
    t0 = time.time()
    while not (state / "e.json").exists():
        if e.poll() is not None or time.time() - t0 > 20:
            sys.exit("выход E не запустился:\n" + (state / "e.log").read_text()[-800:])
        time.sleep(0.2)
    srv = ThreadingHTTPServer(("0.0.0.0", a.http_port), make_handler(state))
    print(f"выход E: UDP {a.ip}:{a.quic_port}; состояние {state}; журнал {state/'e.log'}")
    print(f"APK:     http://{a.ip}:{a.http_port}/   (прямая: http://{a.ip}:{a.http_port}/rawgmeas.apk)")
    print("Ctrl+C - остановить.", flush=True)

    def stop(*_):
        (state / "fin").touch()
        srv.shutdown()
    signal.signal(signal.SIGTERM, lambda *_: threading.Thread(target=stop, daemon=True).start())
    try:
        srv.serve_forever()
    except KeyboardInterrupt:
        pass
    finally:
        (state / "fin").touch()
        try:
            e.wait(timeout=5)
        except subprocess.TimeoutExpired:
            e.kill()


if __name__ == "__main__":
    main()
