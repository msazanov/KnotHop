#!/usr/bin/env python3
"""Замеры REALITY-PoC: netem в cli/srv (egress, на каждое направление), тесты reality-poc, CPU процессов shoes/reality-poc.
Использование: measure.py PATH(reality|udp) DELAY_MS LOSS_PCT [тест...]   (тесты: rtt dgram20 dgramN up down rttload)"""
import subprocess, sys, re, time, pathlib, os
W = pathlib.Path(os.environ.get("W", pathlib.Path.home() / ".cache/knothop-target/reality-poc"))
ID = (W / "lab/server.id").read_text().strip()

def dx(c, cmd, check=True):
    return subprocess.run(["docker", "exec", c, "sh", "-c", cmd], capture_output=True, text=True, timeout=300)

def netem(delay, loss):
    for c in ("rp-cli", "rp-srv"):
        dx(c, "tc qdisc del dev eth0 root 2>/dev/null; true")
        if delay or loss:
            r = dx(c, f"tc qdisc add dev eth0 root netem delay {delay}ms loss {loss}%")
            assert r.returncode == 0, r.stderr

CPU = r'''for p in /proc/[0-9]*; do n=$(cat $p/comm 2>/dev/null); case "$n" in shoes*|reality-poc) awk -v n="$n" '{print n, $14+$15}' $p/stat;; esac; done'''
def cpu(c):
    out = dx(c, CPU).stdout.split("\n")
    d = {}
    for l in out:
        if l.strip():
            n, v = l.split(); d[n] = d.get(n, 0) + int(v) / 100
    return d

def run(path, test):
    via = "custom:127.0.0.1:9000" if path == "reality" else "udp:" + dx("rp-cli", "getent hosts srv | cut -d' ' -f1").stdout.strip() + ":4433"
    base = f"/b/reality-poc cli --id {ID} --via {via} --cap 1400"
    args = {"rtt": "--test rtt --secs 10", "dgram20": "--test dgram --rate-mbit 20 --secs 10", "dgram100": "--test dgram --rate-mbit 100 --secs 10",
            "dgram300": "--test dgram --rate-mbit 300 --secs 10", "up": "--test up --secs 10", "down": "--test down --secs 10",
            "rttload": "--test rtt --bg-mbit 20 --secs 10",
            "dgram2": "--test dgram --rate-mbit 2 --secs 10", "rttload2": "--test rtt --bg-mbit 2 --secs 10"}[test]
    c0, s0 = cpu("rp-cli"), cpu("rp-srv"); t = time.time()
    r = dx("rp-cli", f"{base} {args} 2>&1")
    wall = time.time() - t; c1, s1 = cpu("rp-cli"), cpu("rp-srv")
    lines = [l for l in r.stdout.split("\n") if re.match(r"(rtt|dgram|stream|connected|max_datagram|cpu_client)", l)]
    cp = lambda a, b: " ".join(f"{k}={b.get(k,0)-a.get(k,0):.2f}s" for k in sorted(b))
    print(f"[{path} {DELAY}ms/{LOSS}% {test}] wall={wall:.0f}s\n  " + "\n  ".join(lines) + f"\n  cpu cli: {cp(c0,c1)} | srv: {cp(s0,s1)}", flush=True)

path, DELAY, LOSS = sys.argv[1], sys.argv[2], sys.argv[3]
netem(DELAY, LOSS)
for t in (sys.argv[4:] or ["rtt", "dgram20", "up", "down", "rttload"]):
    run(path, t)
netem(0, 0)
