#!/usr/bin/env python3
"""TCP-прокси, логирующий границы TLS-записей: время (мс от первого байта), направление, тип, длина тела.
Использование: recsniff.py LISTEN_PORT TARGET_HOST TARGET_PORT OUT.tsv [MAX_CONNS]
На каждое соединение пишет блок "# conn N" и строки "t_ms\tdir(c2s|s2c)\ttype\tbody_len\ttcp_chunk_len".
Эти размеры/порядок видит и пассивный DPI (шифртекст не читается)."""
import os, socket, sys, threading, time
DELAY = float(os.environ.get("DELAY_MS", "0")) / 1000  # односторонняя задержка в обе стороны (RTT = 2*DELAY_MS)
lp, th, tp, out = int(sys.argv[1]), sys.argv[2], int(sys.argv[3]), sys.argv[4]
maxc = int(sys.argv[5]) if len(sys.argv) > 5 else 10**9
f = open(out, "a"); lock = threading.Lock(); cn = [0]
def pump(src, dst, d, t0, cid):
    # читатель штампует время приёма, писатель отпускает через DELAY (очередь: задержка не накапливается на пачке)
    import queue
    q = queue.Queue()
    def writer():
        buf = b""
        while True:
            it = q.get()
            if it is None: break
            tr, c = it
            if DELAY: time.sleep(max(0.0, tr + DELAY - time.time()))
            try: dst.sendall(c)
            except OSError: break
            t = (time.time() - t0[0]) * 1000
            buf += c
            while len(buf) >= 5:
                n = int.from_bytes(buf[3:5], "big")
                if len(buf) < 5 + n: break
                with lock: f.write(f"{cid}\t{t:.1f}\t{d}\t{buf[0]}\t{n}\t{len(c)}\n"); f.flush()
                buf = buf[5 + n:]
        try: dst.shutdown(socket.SHUT_WR)
        except OSError: pass
    w = threading.Thread(target=writer, daemon=True); w.start()
    try:
        while True:
            c = src.recv(65536)
            if not c: break
            q.put((time.time(), c))
    except OSError: pass
    q.put(None); w.join()
s = socket.socket(); s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1); s.bind(("127.0.0.1", lp)); s.listen(64)
while cn[0] < maxc:
    c, _ = s.accept(); u = socket.create_connection((th, tp))
    for x in (c, u): x.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)
    cn[0] += 1; t0 = [time.time()]
    threading.Thread(target=pump, args=(c, u, "c2s", t0, cn[0]), daemon=True).start()
    threading.Thread(target=pump, args=(u, c, "s2c", t0, cn[0]), daemon=True).start()
time.sleep(float(os.environ.get("LINGER", "20")))  # дать дописать последние соединения
