#!/usr/bin/env python3
"""Простые тестовые серверы лаборатории.
  lab_web.py whoami NAME   -> на :8080 отвечает, какой выход обслужил запрос (адрес выхода в туннеле 10.99.0.1 одинаков у всех выходов,
                              ответ различается именем) и с какого адреса клиента пришёл запрос
  lab_web.py site          -> на :80 «внешний сайт»: отвечает адресом источника; за NAT выхода это адрес контейнера выхода
  lab_web.py cover         -> на :443 «сайт-прикрытие» REALITY: TLS 1.3 (ALPN h2/http/1.1), самоподписанный сертификат для cover.lab.example, отвечает COVER-OK
"""
import json
import socket
import sys
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

mode = sys.argv[1]
name = sys.argv[2] if len(sys.argv) > 2 else "site"


class H(BaseHTTPRequestHandler):
    def log_message(self, *a):
        pass

    def do_GET(self):
        if self.path.startswith("/big"):
            n = 16 * 1024 * 1024
            self.send_response(200)
            self.send_header("Content-Length", str(n))
            self.end_headers()
            chunk = b"x" * 65536
            while n > 0:
                self.wfile.write(chunk[: min(n, len(chunk))])
                n -= min(n, len(chunk))
            return
        body = json.dumps({"served_by": name, "you_are": self.client_address[0], "host": socket.gethostname()}).encode()
        self.send_response(200)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)


if mode == "cover":
    import ssl
    import subprocess

    subprocess.run(["openssl", "req", "-x509", "-newkey", "ec", "-pkeyopt", "ec_paramgen_curve:prime256v1", "-nodes", "-subj", "/CN=cover.lab.example",
                    "-days", "2", "-keyout", "/tmp/cover.key", "-out", "/tmp/cover.crt"], check=True, capture_output=True)

    class C(BaseHTTPRequestHandler):
        def log_message(self, *a):
            pass

        def do_GET(self):
            body = b"COVER-OK\n"
            self.send_response(200)
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)

    srv = ThreadingHTTPServer(("0.0.0.0", 443), C)
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    ctx.minimum_version = ssl.TLSVersion.TLSv1_3
    ctx.load_cert_chain("/tmp/cover.crt", "/tmp/cover.key")
    ctx.set_alpn_protocols(["h2", "http/1.1"])
    srv.socket = ctx.wrap_socket(srv.socket, server_side=True)
    srv.serve_forever()
port = 8080 if mode == "whoami" else 80
ThreadingHTTPServer(("0.0.0.0", port), H).serve_forever()
