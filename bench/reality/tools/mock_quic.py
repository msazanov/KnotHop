#!/usr/bin/env python3
"""Имитация размеров начала QUIC-сессии iroh в кадрах носителя (u16 длина | пакет) для сравнения формы записей.
  mock_quic.py srv PORT   - «сервер QUIC» за мостом (target): отвечает по сценарию
  mock_quic.py cli PORT   - «клиент QUIC» (слушатель моста): отправляет по сценарию, затем выходит
Сценарий (типично для QUIC 1.3 handshake + загрузка): C Initial 1252; S 1252+1252+620; C 1252+75; S 95, затем 60 кадров по 1200;
C шлёт ACK 60 Б после каждых 10 принятых кадров. Это МОДЕЛЬ размеров, не настоящий QUIC."""
import socket, struct, sys, os, time
role, port = sys.argv[1], int(sys.argv[2])
def send(c, n): c.sendall(struct.pack(">H", n) + os.urandom(n))
def recv(c):
    h = b""
    while len(h) < 2:
        x = c.recv(2 - len(h))
        if not x: return None
        h += x
    n = struct.unpack(">H", h)[0]; b = b""
    while len(b) < n:
        x = c.recv(n - len(b))
        if not x: return None
        b += x
    return n
if role == "srv":
    s = socket.socket(); s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1); s.bind(("127.0.0.1", port)); s.listen(8)
    while True:
        c, _ = s.accept()
        try:
            recv(c)
            for n in (1252, 1252, 620): send(c, n)
            recv(c); recv(c)
            send(c, 95)
            for i in range(60): send(c, 1200)
            while recv(c) is not None: pass
        except OSError: pass
        finally: c.close()
else:
    t0 = time.time()
    c = socket.create_connection(("127.0.0.1", port)); c.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)
    send(c, 1252)
    recv(c); t1 = time.time() - t0  # первый ответный кадр (после рукопожатия моста)
    for _ in range(2): recv(c)
    send(c, 1252); send(c, 75)
    recv(c)
    for i in range(60):
        recv(c)
        if i % 10 == 9: send(c, 60)
    print(f"first_reply {t1*1000:.0f} ms, done {(time.time()-t0)*1000:.0f} ms")
    c.close()
