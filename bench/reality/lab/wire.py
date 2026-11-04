#!/usr/bin/env python3
"""Разбор pcap (tcpdump -i eth0, Ethernet): по каждому TCP-потоку к порту PORT выводит последовательность TLS-записей обоих направлений.
Использование: wire.py FILE.pcap PORT [ch-hex N]   (ch-hex N: hex первой записи клиента N-го потока - для повтора ClientHello)"""
import struct, sys, collections

def packets(path):
    d = open(path, "rb").read(); off = 24
    while off + 16 <= len(d):
        _, _, cl, _ = struct.unpack("<IIII", d[off:off + 16]); off += 16
        yield d[off:off + cl]; off += cl

def flows(path, port):
    fl = collections.OrderedDict()
    for p in packets(path):
        if p[12:14] != b"\x08\x00": continue
        ihl = (p[14] & 0xf) * 4; ip = p[14:]
        if ip[9] != 6: continue
        tcp = ip[ihl:]; sport, dport, seq = struct.unpack(">HHI", tcp[:8]); doff = (tcp[12] >> 4) * 4; pay = tcp[doff:]
        if port not in (sport, dport): continue
        if dport == port: key = (ip[12:16], sport); d = "c2s"
        else: key = (ip[16:20], dport); d = "s2c"
        f = fl.setdefault(key, {"c2s": {}, "s2c": {}})
        if pay: f[d][seq] = pay
    return fl

def stream(segs):
    out = b""; nxt = None
    for s in sorted(segs):
        if nxt is not None and s < nxt: 
            if s + len(segs[s]) <= nxt: continue
            out += segs[s][nxt - s:]; nxt = s + len(segs[s]); continue
        out += segs[s]; nxt = s + len(segs[s])
    return out

def records(b):
    r = []; i = 0
    while i + 5 <= len(b):
        n = struct.unpack(">H", b[i + 3:i + 5])[0]; r.append((b[i], n)); i += 5 + n
    return r

if __name__ == "__main__":
    path, port = sys.argv[1], int(sys.argv[2])
    fl = flows(path, port)
    if len(sys.argv) > 3 and sys.argv[3] == "ch-hex":
        k = list(fl)[int(sys.argv[4])]; b = stream(fl[k]["c2s"]); n = struct.unpack(">H", b[3:5])[0]; print(b[:5 + n].hex()); sys.exit()
    for i, (k, f) in enumerate(fl.items()):
        c = records(stream(f["c2s"])); s = records(stream(f["s2c"]))
        print(f"flow {i} sport={k[1]}\n  c2s: {c[:12]}\n  s2c: {s[:14]}")
