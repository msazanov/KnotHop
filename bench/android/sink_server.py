#!/usr/bin/env python3
"""Источник и приёмник трафика для замеров VPN-приложения: GET /down?mb=N отдаёт N МБ нулей, POST /up читает и отбрасывает тело.
Запускается внутри контейнера выхода (knothop-exit) на 10.99.0.1:8099, чтобы мерить тракт, а не интернет."""
import socketserver
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
import re

CH = b"\0" * 65536


class H(BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"

    def log_message(self, *a):
        pass

    def do_GET(self):
        m = re.search(r"mb=(\d+)", self.path)
        n = int(m.group(1)) * 1024 * 1024 if m else 1024 * 1024
        self.send_response(200)
        self.send_header("Content-Length", str(n))
        self.end_headers()
        while n > 0:
            k = min(n, len(CH))
            self.wfile.write(CH[:k])
            n -= k

    def do_POST(self):
        n = int(self.headers.get("Content-Length", "0"))
        got = 0
        while got < n:
            b = self.rfile.read(min(65536, n - got))
            if not b:
                break
            got += len(b)
        self.send_response(200)
        self.send_header("Content-Length", "2")
        self.end_headers()
        self.wfile.write(b"ok")


class S(ThreadingHTTPServer):
    daemon_threads = True
    request_queue_size = 64


if __name__ == "__main__":
    S(("0.0.0.0", 8099), H).serve_forever()
