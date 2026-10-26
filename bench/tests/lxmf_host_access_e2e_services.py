#!/usr/bin/env python3
"""Лабораторные помощники E2E HOST_ACCESS (запускаются ВНУТРИ контейнеров лаборатории, только синтетика).

  web PORT                      HTTP: / -> маленький JSON, /slow -> ~50 КиБ/с до 120 с (долгий поток для проверки отзыва)
  udplog PORT FILE              UDP: каждая датаграмма -> строка "src:port tag" в FILE
  ctl SOCK "команда"            одна строка в Unix-сокет драйвера (мост admin_cli_json), ответ JSON в stdout
  stream HOST PORT SECS FILE    читает /slow, пишет "t total" в FILE каждые 0.2 с (поток переживает отзыв)
  inject IFACE SRC DST KIND TAG [PORT]
                                сырой IPv4-пакет в TUN (AF_PACKET): KIND = ok | badver | ihl4 | longlen | shortlen
                                | trunc | opts | frag | gre | tcpsyn
"""
import json
import socket
import struct
import sys
import time
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer


def cmd_web(port):
    class H(BaseHTTPRequestHandler):
        def log_message(self, *a):
            pass

        def do_GET(self):
            if self.path.startswith("/slow"):
                self.send_response(200)
                self.send_header("Content-Type", "application/octet-stream")
                self.end_headers()
                try:
                    for _ in range(6000):
                        self.wfile.write(b"x" * 1024)
                        self.wfile.flush()
                        time.sleep(0.02)
                except OSError:
                    pass
                return
            body = json.dumps({"host": socket.gethostname(), "you_are": self.client_address[0]}).encode()
            self.send_response(200)
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)

    ThreadingHTTPServer(("0.0.0.0", port), H).serve_forever()


def cmd_udplog(port, path):
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    s.bind(("0.0.0.0", port))
    while True:
        data, addr = s.recvfrom(2048)
        with open(path, "a") as f:
            f.write(f"{addr[0]}:{addr[1]} {data[:48].decode('latin1')}\n")


def cmd_ctl(sock, line):
    s = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
    s.settimeout(20)
    s.connect(sock)
    s.sendall(line.encode() + b"\n")
    buf = b""
    while not buf.endswith(b"\n"):
        chunk = s.recv(65536)
        if not chunk:
            break
        buf += chunk
    sys.stdout.write(buf.decode())


def cmd_stream(host, port, secs, path):
    s = socket.create_connection((host, port), timeout=10)
    s.sendall(f"GET /slow HTTP/1.0\r\nHost: {host}\r\n\r\n".encode())
    s.settimeout(0.2)
    t0 = time.time()
    total = 0
    last = 0
    with open(path, "w") as f:
        while time.time() - t0 < secs:
            try:
                d = s.recv(65536)
                if not d:
                    break
                total += len(d)
            except socket.timeout:
                pass
            except OSError:
                break
            if time.time() - last >= 0.2:
                f.write(f"{time.time():.2f} {total}\n")
                f.flush()
                last = time.time()
        f.write(f"{time.time():.2f} {total} end\n")


def cmd_blast(host, port, count, pps, tag):
    """count UDP-датаграмм по pps штук/с; в конце печатает фактическое число и длительность (отправитель)."""
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    t0 = time.time()
    for i in range(count):
        s.sendto(f"{tag}-{i}".encode(), (host, port))
        due = t0 + (i + 1) / pps
        d = due - time.time()
        if d > 0:
            time.sleep(d)
    print(json.dumps({"sent": count, "secs": round(time.time() - t0, 3)}))


def csum(b):
    if len(b) % 2:
        b += b"\0"
    s = sum(struct.unpack("!%dH" % (len(b) // 2), b))
    s = (s >> 16) + (s & 0xFFFF)
    s += s >> 16
    return (~s) & 0xFFFF


def ip4(s):
    return socket.inet_aton(s)


def build(kind, src, dst, tag, port):
    payload = tag.encode()
    udp = struct.pack("!HHHH", 40000, port, 8 + len(payload), 0) + payload
    proto = 17
    ihl = 5
    ver = 4
    flags_frag = 0
    opts = b""
    body = udp
    if kind == "tcpsyn":
        proto = 6
        body = struct.pack("!HHIIBBHHH", 40001, port, 1, 0, 5 << 4, 2, 1000, 0, 0)
    if kind == "gre":
        proto = 47
        body = b"\0\0\x08\0" + payload
    if kind == "opts":
        ihl = 6
        opts = b"\x01\x01\x01\x00"
    if kind == "frag":
        flags_frag = 0x2000
    if kind == "badver":
        ver = 5
    if kind == "ihl4":
        ihl = 4
    tot = ihl * 4 + len(body) if kind not in ("longlen", "shortlen") else (ihl * 4 + len(body) + 200 if kind == "longlen" else 10)
    hdr = struct.pack("!BBHHHBBH4s4s", (ver << 4) | ihl, 0, tot, 4242, flags_frag, 64, proto, 0, ip4(src), ip4(dst)) + opts
    hdr = hdr[:10] + struct.pack("!H", csum(hdr)) + hdr[12:]
    pkt = hdr + body
    if kind == "trunc":
        pkt = pkt[:14]
    return pkt


def cmd_inject(iface, src, dst, kind, tag, port):
    s = socket.socket(socket.AF_PACKET, socket.SOCK_DGRAM, socket.htons(0x0800))
    s.bind((iface, 0x0800))
    s.send(build(kind, src, dst, tag, port))
    print("sent", kind, tag)


if __name__ == "__main__":
    a = sys.argv[1:]
    m = a[0]
    if m == "web":
        cmd_web(int(a[1]))
    elif m == "udplog":
        cmd_udplog(int(a[1]), a[2])
    elif m == "ctl":
        cmd_ctl(a[1], a[2])
    elif m == "stream":
        cmd_stream(a[1], int(a[2]), float(a[3]), a[4])
    elif m == "blast":
        cmd_blast(a[1], int(a[2]), int(a[3]), float(a[4]), a[5])
    elif m == "inject":
        cmd_inject(a[1], a[2], a[3], a[4], a[5], int(a[6]) if len(a) > 6 else 9999)
    else:
        sys.exit(__doc__)
