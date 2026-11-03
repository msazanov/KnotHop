#!/usr/bin/env python3
"""Разбор ClientHello из pcap (tcpdump, Ethernet): JA3, JA4 и человекочитаемый вывод. Использование: ja.py file.pcap DSTPORT"""
import struct, sys, hashlib

def grease(v): return (v & 0x0f0f) == 0x0a0a and (v >> 8) == (v & 0xff)

def packets(path):
    d = open(path, "rb").read()
    magic = struct.unpack("<I", d[:4])[0]
    assert magic in (0xa1b2c3d4, 0xa1b23c4d), hex(magic)
    off = 24
    while off + 16 <= len(d):
        _, _, cl, _ = struct.unpack("<IIII", d[off:off + 16]); off += 16
        yield d[off:off + cl]; off += cl

def client_stream(path, port, srcip=None):
    segs = {}; src = None
    for p in packets(path):
        if p[12:14] != b"\x08\x00": continue
        ihl = (p[14] & 0xf) * 4; ip = p[14:]
        if ip[9] != 6: continue
        tcp = ip[ihl:]; sport, dport, seq = struct.unpack(">HHI", tcp[:8]); doff = (tcp[12] >> 4) * 4
        pay = tcp[doff:]
        if dport == port and pay:
            if srcip and '.'.join(map(str, ip[12:16])) != srcip: continue
            key = (ip[12:16], sport)
            src = src or key
            if key == src: segs[seq] = pay
    out = b""; 
    for s in sorted(segs): out += segs[s]
    return out

def parse(ch):
    assert ch[0] == 22; rl = struct.unpack(">H", ch[3:5])[0]; hs = ch[5:5 + rl]
    if len(hs) < rl: hs = ch[5:]
    assert hs[0] == 1
    b = hs[4:]; ver = struct.unpack(">H", b[:2])[0]; i = 34
    sid = b[i]; i += 1 + sid
    cl = struct.unpack(">H", b[i:i + 2])[0]; ciphers = [struct.unpack(">H", b[i + 2 + k:i + 4 + k])[0] for k in range(0, cl, 2)]; i += 2 + cl
    i += 1 + b[i]
    el = struct.unpack(">H", b[i:i + 2])[0]; i += 2; end = i + el; exts = []
    while i < end:
        t, l = struct.unpack(">HH", b[i:i + 4]); exts.append((t, b[i + 4:i + 4 + l])); i += 4 + l
    return dict(ver=ver, sid=sid, ciphers=ciphers, exts=exts, total=5 + rl)

def u16list(d, hdr=2): return [struct.unpack(">H", d[hdr + k:hdr + k + 2])[0] for k in range(0, len(d) - hdr, 2)]

def analyze(path, port, name, srcip=None):
    h = parse(client_stream(path, port, srcip)); E = {t: d for t, d in h["exts"]}
    ciphers = [c for c in h["ciphers"] if not grease(c)]
    et = [t for t, _ in h["exts"] if not grease(t)]
    groups = [g for g in u16list(E.get(10, b"\0\0")) if not grease(g)]
    ecpf = list(E.get(11, b"\0")[1:])
    sigs = [x for x in u16list(E[13]) if not grease(x)] if 13 in E else []
    sv = [v for v in u16list(E[43], 1) if not grease(v)] if 43 in E else []
    alpn = []
    if 16 in E:
        d = E[16][2:]; 
        while d: alpn.append(d[1:1 + d[0]].decode()); d = d[1 + d[0]:]
    ja3s = ",".join([str(h["ver"]), "-".join(map(str, ciphers)), "-".join(map(str, et)), "-".join(map(str, groups)), "-".join(map(str, ecpf))])
    ja3 = hashlib.md5(ja3s.encode()).hexdigest()
    a = "t" + ("13" if 0x0304 in sv else "12") + ("d" if 0 in E else "i") + f"{min(len(ciphers),99):02d}" + f"{min(len(et),99):02d}" + ((alpn[0][0] + alpn[0][-1]) if alpn else "00")
    bh = hashlib.sha256(",".join(f"{c:04x}" for c in sorted(ciphers)).encode()).hexdigest()[:12]
    ce = ",".join(f"{t:04x}" for t in sorted(t for t in et if t not in (0, 16)))
    cs = ce + ("_" + ",".join(f"{s:04x}" for s in sigs) if sigs else "")
    ch = hashlib.sha256(cs.encode()).hexdigest()[:12]
    ks = []
    if 51 in E:
        d = E[51][2:]
        while d:
            g, l = struct.unpack(">HH", d[:4]); ks.append((g, l)); d = d[4 + l:]
    print(f"== {name}: record {h['total']} B, session_id {h['sid']} B")
    print(f"JA4  = {a}_{bh}_{ch}\nJA3  = {ja3}")
    print(f"ciphers({len(ciphers)}) = {' '.join(f'{c:04x}' for c in ciphers)}")
    print(f"ext order = {' '.join(str(t) for t in et)}  (sorted: {' '.join(str(t) for t in sorted(et))})")
    print(f"groups = {' '.join(f'{g:04x}' for g in groups)}; key_share = {[(f'{g:04x}', l) for g, l in ks if not grease(g)]}; sigalgs = {' '.join(f'{s:04x}' for s in sigs)}")
    print(f"alpn = {alpn}; versions = {[hex(v) for v in sv]}; ecpf = {ecpf}; psk_modes={E.get(45,b'').hex()}; compress_cert={E.get(27,b'').hex()}")
    print(f"has: ECH(65037)={65037 in E} padding(21)={21 in E} session_ticket(35)={35 in E} ems(23)={23 in E} sct(18)={18 in E} status_request(5)={5 in E} renego(65281)={65281 in E} app_settings(17613/17513)={17613 in E or 17513 in E}")
    print(f"GREASE ciphers/exts present: {len(h['ciphers'])-len(ciphers)} / {len(h['exts'])-len(et)}")

analyze(sys.argv[1], int(sys.argv[2]), sys.argv[3] if len(sys.argv) > 3 else sys.argv[1], sys.argv[4] if len(sys.argv) > 4 else None)
