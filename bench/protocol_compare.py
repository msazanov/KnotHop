#!/usr/bin/env python3
"""Independent Xray/AWG TCP payload comparators, internal Docker only.

Keys/configs are disposable and stay inside containers. No published ports,
production configurations, internet camouflage targets or public RNS load.
"""
import argparse
import json
import os
import re
import secrets
import signal
import statistics
import tempfile
import time
import uuid
from pathlib import Path
from awg_backbone import cmd, dex, put, cpu, awg_setup, SECRETS, redact
from measure import process_memory, rtt_summary

HERE = Path(__file__).resolve().parent
IMAGE = "rawg-bench:compare"
BIN = Path(os.environ.get("TCP_LOAD_BIN", str(Path.home() / ".cache/rawg-target/fork-win256/release/tcp-load")))


def config(name, value):
    put(name, "/run/xray.json", json.dumps(value))
    dex(name, "xray", "run", "-test", "-config", "/run/xray.json")
    cmd("docker", "exec", "-d", name, "sh", "-c", "exec xray run -config /run/xray.json > /shared/xray-" + name.rsplit("-", 1)[-1] + ".log 2>&1")


def reality_server(name, ip, outbound=None):
    pair = dex(name, "xray", "x25519")
    fields = dict(re.findall(r"^([A-Za-z0-9_ ()-]+):\s*(\S+)", pair, re.M))
    private = fields.get("PrivateKey")
    public = fields.get("PublicKey") or fields.get("Password (PublicKey)") or fields.get("Password")
    if not private or not public:
        raise RuntimeError("unexpected x25519 output shape (values suppressed)")
    client_id, short_id = str(uuid.uuid4()), secrets.token_hex(8)
    SECRETS.update((private, client_id, short_id))
    # REALITY destination is a local TLS fixture, not a public website.
    dex(name, "openssl", "req", "-x509", "-newkey", "ec", "-pkeyopt", "ec_paramgen_curve:P-256",
        "-nodes", "-days", "1", "-subj", "/CN=bench.test", "-keyout", "/run/fixture.key", "-out", "/run/fixture.crt")
    cmd("docker", "exec", "-d", name, "sh", "-c", "exec openssl s_server -quiet -accept 127.0.0.1:8443 -cert /run/fixture.crt -key /run/fixture.key -www -tls1_3 -groups X25519 -alpn h2 > /shared/tls-fixture-" + name.rsplit("-", 1)[-1] + ".log 2>&1")
    value = {"log": {"loglevel": "warning"},
             "inbounds": [{"listen": "0.0.0.0", "port": 4433, "protocol": "vless",
                           "settings": {"clients": [{"id": client_id, "flow": "xtls-rprx-vision"}], "decryption": "none"},
                           "streamSettings": {"network": "tcp", "security": "reality", "realitySettings": {
                               "show": False, "target": "127.0.0.1:8443", "serverNames": ["bench.test"],
                               "privateKey": private, "shortIds": [short_id]}}}],
             "outbounds": [outbound or {"protocol": "freedom", "settings": {"finalRules": [
                 {"action": "allow", "network": "tcp", "port": "4241-4242", "ip": [ip + "/32"]}]}}]}
    config(name, value)
    return {"protocol": "vless", "settings": {"vnext": [{"address": ip, "port": 4433,
             "users": [{"id": client_id, "encryption": "none", "flow": "xtls-rprx-vision"}]}]},
             "streamSettings": {"network": "tcp", "security": "reality", "realitySettings": {
                 "serverName": "bench.test", "fingerprint": "chrome", "password": public, "shortId": short_id}},
             "mux": {"enabled": False}}


def awg_chain(names, ips):
    # Names/addresses may repeat on different interfaces of the transit node.
    for left, right, dev, subnet in (("c", "a", "awgca", "10.202.0"), ("a", "e", "awgae", "10.203.0")):
        private = [dex(names[r], "awg", "genkey") for r in (left, right)]
        SECRETS.update(private)
        public = [dex(names[r], "awg", "pubkey", data=k + "\n") for r, k in zip((left, right), private)]
        header = dex(names[left], "awg", "genkey"); SECRETS.add(header)
        for i, role in enumerate((left, right)):
            peer = right if i == 0 else left
            allowed = f"{subnet}.{2-i}/32"
            if role == "c": allowed += ", 10.203.0.2/32"
            if role == "e": allowed += ", 10.202.0.1/32"
            port = 51820 if dev == "awgca" else 51821
            text = f"""[Interface]
PrivateKey = {private[i]}
ListenPort = {port}
HeaderProtectionKey = {header}
Jc = 5
Jmin = 50
Jmax = 1000
S1 = 40
S2 = 60
S3 = 30
S4 = 15
H1 = 5-500000000
H2 = 500000001-1000000000
H3 = 1000000001-1500000000
H4 = 1500000001-2000000000
ContentPaddingAddition = 0-0
RandomTrailers = off
[Peer]
PublicKey = {public[1-i]}
Endpoint = {ips[peer]}:{port}
AllowedIPs = {allowed}
PersistentKeepalive = 25
"""
            dex(names[role], "amneziawg-go", dev)
            put(names[role], f"/run/{dev}.conf", text)
            dex(names[role], "awg", "setconf", dev, f"/run/{dev}.conf")
            dex(names[role], "ip", "address", "add", f"{subnet}.{i+1}/30", "dev", dev)
            dex(names[role], "ip", "link", "set", "dev", dev, "mtu", "1280", "up")
    dex(names["c"], "ip", "route", "add", "10.203.0.2/32", "dev", "awgca")
    dex(names["e"], "ip", "route", "add", "10.202.0.1/32", "dev", "awgae")
    dex(names["c"], "ping", "-c", "3", "-W", "3", "10.203.0.2", timeout=20)
    return "10.203.0.2"


def main():
    def interrupt(*_):
        raise KeyboardInterrupt
    signal.signal(signal.SIGTERM, interrupt)
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("protocol", choices=["tcp", "iroh", "xray", "awg"])
    ap.add_argument("tag")
    ap.add_argument("--hops", type=int, choices=[1, 2], default=1)
    ap.add_argument("--duration", type=int, default=20)
    ap.add_argument("--bytes", type=int, default=0)
    ap.add_argument("--verify-sha", action="store_true")
    ap.add_argument("--netem", default="", help="tc netem на egress eth0 каждого узла перед стартом передачи, напр. 'delay 25ms loss 0.5%%'")
    a = ap.parse_args()
    if not re.fullmatch(r"[a-zA-Z0-9_-]+", a.tag): ap.error("invalid tag")
    if a.protocol == "tcp" and a.hops != 1: ap.error("TCP control is one-hop")
    root = HERE / "results" / "protocol-compare"; root.mkdir(parents=True, exist_ok=True)
    out = root / (a.tag + ".json")
    if out.exists(): raise FileExistsError(out)
    if not BIN.exists(): raise FileNotFoundError(BIN)
    roles = ["e", "c"] + (["a"] if a.hops == 2 else [])
    # Same single logical CPU per node as lev_cell.py (relay 2, e 3, c 4, a 5): one core for
    # every server and one for the client, load generator and checker included.
    cpusets = {"e": "3", "c": "4", "a": "5"}
    names = {r: f"rawg-compare-{a.tag}-{r}" for r in roles}
    net = "rawg-compare-" + a.tag
    made, network, interrupted = [], False, False
    result = {"cell": vars(a), "success": False, "cpusets": {r: cpusets[r] for r in roles},
              "load_start": os.getloadavg(), "note": "synthetic application stream, not HTTPS; Vision TLS passthrough not exercised"}
    with tempfile.TemporaryDirectory(prefix="rawg-compare-", dir="/tmp/opencode") as sd:
        shared = Path(sd); os.chmod(shared, 0o777)
        try:
            result["image"] = cmd("docker", "image", "inspect", IMAGE, "--format", "{{.Id}}")
            cmd("docker", "network", "create", "--internal", net); network = True
            for role in roles:
                flags = ["--device", "/dev/net/tun"] if a.protocol == "awg" else []
                cmd("docker", "run", "-d", "--name", names[role], "--network", net, "--cpuset-cpus", cpusets[role],
                    "--cap-add", "NET_ADMIN", "--sysctl", "net.ipv4.ip_forward=1", "--memory", "3g",
                    "-v", f"{shared}:/shared", "-v", f"{BIN}:/usr/local/bin/tcp-load:ro", *flags,
                    "--entrypoint", "sleep", IMAGE, "infinity")
                made.append(names[role])
            result["effective_cpusets"] = {r: dex(names[r], "cat", "/sys/fs/cgroup/cpuset.cpus.effective") for r in roles}
            if result["effective_cpusets"] != result["cpusets"]: raise RuntimeError("affinity mismatch")
            ips = {r: cmd("docker", "inspect", names[r], "--format", "{{range .NetworkSettings.Networks}}{{.IPAddress}}{{end}}") for r in roles}
            result["versions"] = {"xray": dex(names["e"], "xray", "version"), "awg": dex(names["e"], "amneziawg-go", "--version")}
            result["binaries"] = dex(names["e"], "sha256sum", "/usr/local/bin/xray", "/usr/local/bin/amneziawg-go", "/usr/local/bin/tcp-load")
            target, socks = ips["e"], None
            if a.protocol == "awg":
                if a.hops == 1:
                    awg_setup([names["c"], names["e"]], [ips["c"], ips["e"]], 1280, "0-0", "off")
                    target = "10.201.0.2"
                else: target = awg_chain(names, ips)
                result["routes"] = {r: dex(names[r], "ip", "route") for r in roles}
                for role in roles:
                    result.setdefault("handshakes", {})[role] = dex(names[role], "awg", "show", "all", "latest-handshakes")
                result["awg_profile"] = {"userspace": True, "mtu": 1280, "random_trailers": False, "padding": "0-0"}
            if a.protocol == "xray":
                outbound = reality_server(names["e"], ips["e"])
                if a.hops == 2: outbound = reality_server(names["a"], ips["a"], outbound)
                config(names["c"], {"log": {"loglevel": "warning"}, "inbounds": [{"listen": "127.0.0.1", "port": 1080,
                    "protocol": "socks", "settings": {"auth": "noauth", "udp": False}}], "outbounds": [outbound]})
                socks = "127.0.0.1:1080"
            # Exclude a naked TCP path to the target's outer IP in encrypted cases.
            if a.protocol != "tcp":
                for port in (4241, 4242):
                    dex(names["c"], "iptables", "-A", "OUTPUT", "-d", ips["e"], "-p", "tcp", "--dport", str(port), "-j", "REJECT")
            sha = " --verify-sha" if a.verify_sha else ""
            def start(role, args):
                cmd("docker", "exec", "-d", names[role], "sh", "-c", "exec tcp-load " + args + f" > /shared/{role}.log 2>&1")
            mode = " --transport iroh" if a.protocol == "iroh" else ""
            start("e", f"--role server --ip {target}{sha}{mode}")
            def wait(path, timeout):
                end = time.monotonic() + timeout
                while not path.exists():
                    if time.monotonic() > end: raise TimeoutError(path.name)
                    time.sleep(0.05)
            wait(shared / "server-ready", 15)
            peer_name = "e"
            if a.protocol == "iroh" and a.hops == 2:
                start("a", f"--role forward --transport iroh --ip {ips['a']} --quic-peer e")
                wait(shared / "a.quic.json", 15)
                peer_name = "a"
            start("c", f"--role client --peer {target} --duration {a.duration} --bytes {a.bytes}{sha}{mode} --quic-peer {peer_name}" + (f" --socks {socks}" if socks else ""))
            if a.protocol == "iroh":
                result["iroh_profile"] = {"version": "1.3.0", "rns": False, "relay_mode": "disabled",
                                          "echo": "separate bidirectional stream, same connection"}
            wait(shared / "ready", 25)
            before = {r: cpu(names[r]) for r in roles}
            nic0 = {k: int(dex(names["c"], "cat", f"/sys/class/net/eth0/statistics/{k}")) for k in ("tx_bytes", "rx_bytes")}
            if a.netem:
                # Только данные: рукопожатие и зондирование простоя уже прошли по чистой сети.
                for role in roles:
                    dex(names[role], "tc", "qdisc", "replace", "dev", "eth0", "root", "netem", *a.netem.split())
                result["netem"] = a.netem
            t0 = time.monotonic(); (shared / "go").touch()
            wait(shared / "client.json", a.duration + 30)
            wall = time.monotonic() - t0
            after = {r: cpu(names[r]) for r in roles}
            nic1 = {k: int(dex(names["c"], "cat", f"/sys/class/net/eth0/statistics/{k}")) for k in nic0}
            c, e = (json.loads((shared / f"{r}.json").read_text()) for r in ("client", "server"))
            result.update(client=c, server=e)
            # Peak RSS per role: whatever is still alive is read from /proc; the client's tcp-load has
            # normally exited by now, so its own VmHWM (written into client.json) is added instead.
            memory = {}
            for role in roles:
                rows = process_memory(lambda *argv, r=role: dex(names[r], *argv))
                if role == "c" and not any(p["name"] == "tcp-load" for p in rows):
                    rows.append({"pid": 0, "name": "tcp-load(self-reported)", "hwm_kb": c["vm_hwm_kb"], "rss_kb": c["vm_rss_kb"]})
                memory[role] = {"processes": rows, "peak_kb": sum(p["hwm_kb"] for p in rows)}
            result["memory"] = memory
            result["verified"] = c["bytes"] == e["bytes"] and e["mismatch_at"] is None and (not a.verify_sha or c["sha256"] == e["sha256"])
            result["success"] = bool(result["verified"] and c["bytes"] > 0 and (not a.bytes or c["bytes"] == a.bytes))
            result["mib_s"] = e["bytes"] / 1048576 / e["seconds"]
            result["cpu_s_per_gib"] = {r: (after[r]-before[r])/1e6 * 1073741824/e["bytes"] for r in roles}
            result["cpu_seconds"] = {r: (after[r]-before[r])/1e6 for r in roles}
            # Percent of ONE core over the transfer window, the same definition for every stack.
            result["cpu_percent"] = {r: result["cpu_seconds"][r] / e["seconds"] * 100 for r in roles}
            result["outer_tx_payload"] = (nic1["tx_bytes"]-nic0["tx_bytes"])/e["bytes"]
            result["echo"] = rtt_summary(c["echo_rtt_ms"], c["echo_timeouts"])
            result["echo_idle"] = rtt_summary(c["echo_idle_rtt_ms"])
        except KeyboardInterrupt:
            result["error"] = "interrupted"
            interrupted = True
        except Exception as exc:
            result["error"] = redact(str(exc))
        finally:
            for role in roles:
                log = shared / f"{role}.log"
                if log.exists(): (root / f"{a.tag}.{role}.log").write_text(redact(log.read_text()))
                log = shared / f"xray-{role}.log"
                if log.exists(): (root / f"{a.tag}.xray-{role}.log").write_text(redact(log.read_text()))
            for name in reversed(made): cmd("docker", "rm", "-f", name, check=False)
            if network: cmd("docker", "network", "rm", net, check=False)
            SECRETS.clear()
    out.write_text(json.dumps(result, indent=2))
    print(a.tag, "OK" if result["success"] else "FAILED", "MiB/s", round(result.get("mib_s", 0), 2),
          "CPU/GiB", result.get("cpu_s_per_gib"), "echo", result.get("echo"), result.get("error", ""))
    if interrupted:
        raise SystemExit(130)


if __name__ == "__main__": main()
