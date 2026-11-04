#!/usr/bin/env python3
"""Снимает сырые ClientHello браузера: слушает TCP, читает первую TLS-запись, пишет hex в файл, закрывает.
Использование: capture_ch.py PORT OUT SECS"""
import socket, sys, time, threading
port, out, secs = int(sys.argv[1]), sys.argv[2], float(sys.argv[3])
s = socket.socket(); s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1); s.bind(("127.0.0.1", port)); s.listen(64); s.settimeout(0.5)
f = open(out, "a"); end = time.time() + secs
def h(c):
    try:
        c.settimeout(2); d = b""
        while len(d) < 5: d += c.recv(5 - len(d))
        n = int.from_bytes(d[3:5], "big")
        while len(d) < 5 + n: d += c.recv(5 + n - len(d))
        f.write(d.hex() + "\n"); f.flush()
    except Exception as e: sys.stderr.write(repr(e)+"\n")
    finally: c.close()
while time.time() < end:
    try: c, _ = s.accept()
    except socket.timeout: continue
    threading.Thread(target=h, args=(c,), daemon=True).start()
