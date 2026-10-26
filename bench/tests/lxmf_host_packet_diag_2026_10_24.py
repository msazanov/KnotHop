#!/usr/bin/env python3
"""One-off HOST_ACCESS TUN packet diagnostic for a dedicated E2E_PREFIX/ROOT.

Not imported by or wired into the shared suite. Uses the existing E2E bootstrap,
then records only isolated client TUN / exit TUN / dummy service packets in 0600
pcap files and runs one direct-LXMF root grant plus TCP/UDP controls.
"""
import argparse
import hashlib
import json
import os
import socket
import struct
import subprocess
import sys
import time
from pathlib import Path

HERE = Path(__file__).resolve().parent
HARNESS = HERE / "lxmf_host_access_e2e.py"
SERVICES = HERE / "lxmf_host_access_e2e_services.py"
PREFIX = os.environ.get("E2E_PREFIX", "lxpdiag-20261024a")
ROOT = Path(os.environ.get("E2E_ROOT", Path.home() / ".cache/knothop-lxpdiag-20261024/unused"))
SUBNET = os.environ.get("E2E_SUBNET", "172.29.100.0/24")
NET = f"{PREFIX}-net"
BIN = Path(os.environ.get("E2E_BIN", "/usr/local/bin/knothopd"))
DRIVER = Path(os.environ.get("E2E_DRIVER", "/usr/local/bin/driver"))
IMAGE = "knothop-bench:l3"
HOST = "1.1.1.1"
PORT = 8080
UDP_PORT = 9998
CAPTURE_SECS = 55


def sh(*args, check=True, timeout=45, input=None, env=None):
    p = subprocess.run(args, input=input, text=True, capture_output=True, timeout=timeout, env=env)
    if check and p.returncode:
        raise RuntimeError(f"{args[0]} rc={p.returncode}: {(p.stderr or p.stdout)[-500:]}")
    return p


def dx(node, *args, check=True, timeout=30):
    return sh("docker", "exec", f"{PREFIX}-{node}", *args, check=check, timeout=timeout)


def out(node, *args, timeout=30):
    return dx(node, *args, timeout=timeout).stdout.strip()


def digest(path):
    h = hashlib.sha256()
    with open(path, "rb") as f:
        for b in iter(lambda: f.read(1 << 20), b""):
            h.update(b)
    return h.hexdigest()


def wait(predicate, secs, what):
    end = time.monotonic() + secs
    while time.monotonic() < end:
        v = predicate()
        if v:
            return v
        time.sleep(1)
    raise TimeoutError(what)


def ctl(node, line):
    p = dx(node, "python3", "/e2e/lxmf_host_access_e2e_services.py", "ctl", "/run/ctl.sock", line)
    return json.loads(p.stdout.strip().splitlines()[-1])


def whoami(node):
    return json.loads(out(node, "knothopd", "whoami", "--state", "/state").splitlines()[-1])


def capture_child():
    iface, path, seconds = sys.argv[2], sys.argv[3], int(sys.argv[4])
    os.umask(0o077)
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
    # Classic pcap, linktype 101 = raw IPv4; SOCK_DGRAM returns the IP packet.
    os.write(fd, struct.pack("<IHHIIII", 0xA1B2C3D4, 2, 4, 0, 0, 65535, 101))
    s = socket.socket(socket.AF_PACKET, socket.SOCK_DGRAM, socket.htons(0x0800))
    s.bind((iface, 0x0800))
    s.settimeout(0.25)
    end = time.monotonic() + seconds
    count = 0
    try:
        while time.monotonic() < end:
            try:
                pkt, addr = s.recvfrom(65535)
            except socket.timeout:
                continue
            if len(pkt) < 20:
                continue
            ts = time.time()
            sec, usec = int(ts), int((ts % 1) * 1_000_000)
            os.write(fd, struct.pack("<IIII", sec, usec, len(pkt), len(pkt)) + pkt)
            count += 1
    finally:
        s.close()
        os.fsync(fd)
        os.close(fd)
    Path(path + ".count").write_text(str(count) + "\n")
    os.chmod(path + ".count", 0o600)


def checksum(data):
    if len(data) & 1:
        data += b"\0"
    words = struct.unpack("!%dH" % (len(data) // 2), data)
    total = sum(words)
    total = (total & 0xFFFF) + (total >> 16)
    total = (total & 0xFFFF) + (total >> 16)
    return (~total) & 0xFFFF


def build_udp(src, dst, payload, port):
    data = payload.encode("ascii")
    udp = struct.pack("!HHHH", 40000, port, 8 + len(data), 0) + data
    srcb, dstb = socket.inet_aton(src), socket.inet_aton(dst)
    hdr0 = struct.pack("!BBHHHBBH4s4s", 0x45, 0, 20 + len(udp), 4242, 0, 64, 17, 0, srcb, dstb)
    hdr = hdr0[:10] + struct.pack("!H", checksum(hdr0)) + hdr0[12:]
    packet = hdr + udp
    assert len(packet) == 28 + len(data) and checksum(hdr) == 0
    return packet


def inject_child():
    iface, src, dst, port, tag = sys.argv[2:7]
    pkt = build_udp(src, dst, tag, int(port))
    s = socket.socket(socket.AF_PACKET, socket.SOCK_DGRAM, socket.htons(0x0800))
    s.bind((iface, 0x0800))
    s.send(pkt)
    print(json.dumps({"sent": True, "ip_total_length": len(pkt), "ip_checksum_valid": checksum(pkt[:20]) == 0,
                      "udp_length": struct.unpack("!H", pkt[24:26])[0], "tag": tag}))


def parse_pcap(path):
    rows = []
    data = Path(path).read_bytes()
    if len(data) < 24:
        return rows
    off = 24
    while off + 16 <= len(data):
        _, _, caplen, _ = struct.unpack_from("<IIII", data, off)
        off += 16
        pkt = data[off:off + caplen]
        off += caplen
        if len(pkt) < 20 or pkt[0] >> 4 != 4:
            continue
        proto = pkt[9]
        src, dst = socket.inet_ntoa(pkt[12:16]), socket.inet_ntoa(pkt[16:20])
        sport = dport = None
        ihl = (pkt[0] & 15) * 4
        if proto in (6, 17) and len(pkt) >= ihl + 4:
            sport, dport = struct.unpack_from("!HH", pkt, ihl)
        rows.append({"src": src, "dst": dst, "proto": proto, "sport": sport, "dport": dport, "len": len(pkt)})
    return rows


def print_observation(name, rows):
    selected = [r for r in rows if r["dst"] == HOST or r["src"] == HOST]
    counts = {}
    for r in selected:
        key = (r["src"], r["dst"], r["proto"], r["sport"], r["dport"])
        counts[key] = counts.get(key, 0) + 1
    print(f"{name}: packets={len(rows)} host_flow={json.dumps([{'flow':k,'count':v} for k,v in counts.items()])}")


def wait_admin(node, rid, timeout=90):
    deadline = time.monotonic() + timeout
    final = {}
    while time.monotonic() < deadline:
        final = ctl(node, f"admin-status --state /state --request-id {rid}")
        if final.get("state") in ("applied", "rejected", "stale", "expired", "unknown", "applied_not_effective"):
            return final
        time.sleep(1)
    return final


def request_status(target, root):
    rid = os.urandom(16).hex()
    sub = ctl("admin", f"admin-submit --state /state --target {target} --root {root} --op status.get --scope NODE --request-id {rid}")
    if sub.get("accepted") is not True:
        raise RuntimeError(f"status.get submit failed: {json.dumps(sub)[:300]}")
    return wait_admin("admin", rid)


def tun_stats(node):
    try:
        j = json.loads(out(node, "cat", "/state/status.json"))
        t = j.get("tun") or {}
        return {k: t.get(k) for k in ("from_tun_pkts", "to_tun_pkts", "unauth_drops", "not_ipv4", "routes")}
    except Exception:
        return {}


def wait_counter(node, key, start, timeout=12):
    end = time.monotonic() + timeout
    latest = tun_stats(node)
    while time.monotonic() < end:
        latest = tun_stats(node)
        if (latest.get(key) or 0) > (start.get(key) or 0):
            return latest
        time.sleep(0.4)
    return latest


def run():
    resume = "--resume" in sys.argv[1:]
    print(f"artifacts knothopd={digest(BIN)} driver={digest(DRIVER)} image={sh('docker','image','inspect',IMAGE,'--format','{{.Id}}').stdout.strip()}")
    print(f"lab prefix={PREFIX} subnet={SUBNET} state_root={ROOT}")
    if ROOT.exists() and any(ROOT.iterdir()) and not resume:
        raise RuntimeError("E2E_ROOT is not unused; refusing to reuse it")
    # Existing harness up is intentional; its public-RNS fixture points only to its local hub.
    env = os.environ.copy()
    env.update(E2E_PREFIX=PREFIX, E2E_ROOT=str(ROOT), E2E_SUBNET=SUBNET,
               E2E_BIN=str(BIN), E2E_DRIVER=str(DRIVER))
    sh(sys.executable, "-I", str(HARNESS), "up", timeout=900, env=env)
    print("bootstrap=up")

    admin, usr, exit1 = whoami("admin"), whoami("usr"), whoami("exit1")
    admin_hash, usr_hash = admin["hash"], usr["hash"]
    target = next(e["d"] for e in json.loads(out("admin", "cat", "/state/status.json"))["exits"]
                  if str(e.get("n", "")).endswith("exit1"))
    dx("usr", "sh", "-lc", f"printf '%s' {target} > /state/select")
    status = json.loads(out("usr", "cat", "/state/status.json"))
    wait(lambda: (json.loads(out("usr", "cat", "/state/status.json")).get("current") or {}).get("d") == target, 90,
         "client not on exit1")
    client_ip = status.get("ip") or json.loads(out("usr", "cat", "/state/status.json")).get("ip")
    # status root has the current assigned client IP; resolve from tun0 if absent.
    if not client_ip:
        client_ip = out("usr", "sh", "-lc", "ip -4 -o addr show dev tun0 | awk '{print $4}' | cut -d/ -f1")
    else:
        client_ip = client_ip.split("/")[0]
    current_before = json.loads(out("usr", "cat", "/state/status.json")).get("current") or {}
    print(f"public identifiers short root={admin_hash[:8]} holder={usr_hash[:8]} target={exit1['hash'][:8]} client_ip={client_ip}")

    local = dx("exit1", "curl", "--noproxy", "*", "-sS", "-m", "3", "-o", "/dev/null", "-w", "%{http_code}",
                f"http://{HOST}:{PORT}/", check=False)
    route = out("exit1", "ip", "route", "get", client_ip, "from", HOST)
    print(f"service_local_http={local.stdout.strip() or 'no-response'} route_reply_to_client={route}")

    cap_paths = {("usr", "tun0"): "/state/lxpdiag-client-tun0.pcap",
                 ("exit1", "khd0"): "/state/lxpdiag-exit-khd0.pcap",
                 ("exit1", "dummy0"): "/state/lxpdiag-exit-dummy0.pcap"}
    for (node, iface), path in cap_paths.items():
        sh("docker", "exec", "-d", f"{PREFIX}-{node}", "python3", "/e2e/lxmf_host_packet_diag_2026_10_24.py",
           "capture", iface, path, str(CAPTURE_SECS))
    # First obtain fresh capability, then revoke any prior test grant so a real negative baseline exists.
    status_final = request_status(target, admin_hash)
    status_result = status_final.get("result") or {}
    print(f"status_final state={status_final.get('state')} authority_bits={((status_result.get('authority') or {}).get('rights'))} capabilities={json.dumps(status_result.get('capabilities') or {}, sort_keys=True)}")
    rid = os.urandom(16).hex()
    revoke_line = (f"admin-submit --state /state --target {target} --root {admin_hash} --op rights.revoke "
                   f"--holder {usr_hash} --rights 64 --scope NODE --request-id {rid}")
    revoked = ctl("admin", revoke_line)
    if revoked.get("accepted") is not True:
        raise RuntimeError(f"revoke submit failed: {json.dumps(revoked)[:300]}")
    rev_final = wait_admin("admin", rid)
    rev_result = rev_final.get("result") or {}
    print(f"revoke_final state={rev_final.get('state')} durable={rev_result.get('durable_ack')} effective={rev_result.get('effective_host_allowed')} code={rev_result.get('code')}")
    if rev_final.get("state") != "applied" or rev_result.get("effective_host_allowed") is not False:
        raise RuntimeError("pre-grant revoke did not become durably ineffective")

    # Verify denial on this same admitted Link, then refresh capabilities after the revision change.
    client_pre = tun_stats("usr")
    exit_pre = tun_stats("exit1")
    before = dx("usr", "curl", "--noproxy", "*", "-sS", "-m", "3", "-w", "\\n%{http_code}",
                f"http://{HOST}:{PORT}/", check=False)
    lines = before.stdout.strip().splitlines()
    baseline_code = lines[-1] if lines else "000"
    client_after = wait_counter("usr", "from_tun_pkts", client_pre)
    exit_after = wait_counter("exit1", "unauth_drops", exit_pre)
    print(f"baseline_after_revoke_tcp_http={baseline_code} client_tun={client_pre}->{client_after} exit_tun={exit_pre}->{exit_after}")
    if baseline_code == "200":
        raise RuntimeError("host TCP still succeeds after effective revoke; stopping before grant")

    status_final = request_status(target, admin_hash)
    status_result = status_final.get("result") or {}
    print(f"status_after_revoke state={status_final.get('state')} capabilities={json.dumps(status_result.get('capabilities') or {}, sort_keys=True)}")
    rid = os.urandom(16).hex()
    grant_line = (f"admin-submit --state /state --target {target} --root {admin_hash} --op rights.grant "
                  f"--holder {usr_hash} --rights 65 --scope NODE --request-id {rid}")
    submitted = ctl("admin", grant_line)
    print(f"grant_submit accepted={submitted.get('accepted')} queued={submitted.get('queued')} state={submitted.get('state')}")
    if submitted.get("accepted") is not True:
        raise RuntimeError(f"grant submit failed: {json.dumps(submitted)[:300]}")
    final = wait_admin("admin", rid)
    result = final.get("result") or {}
    print(f"grant_final state={final.get('state')} durable={result.get('durable_ack')} committed={result.get('record_committed')} effective={result.get('effective_host_allowed')} code={result.get('code')}")

    # Explicitly avoid proxy variables for the host-bound TCP positive control.
    tcp = dx("usr", "curl", "--noproxy", "*", "-sS", "-m", "6", "-o", "/dev/null", "-w", "%{http_code}",
             f"http://{HOST}:{PORT}/", check=False)
    grant_exit_pre = tun_stats("exit1")
    grant_client_pre = tun_stats("usr")
    client_addr = out("usr", "sh", "-lc", "ip -4 -o addr show dev tun0 | awk '{print $4}' | cut -d/ -f1")
    client_addr = client_addr.split("/")[0]
    udp = dx("usr", "python3", "/e2e/lxmf_host_packet_diag_2026_10_24.py", "inject", "tun0", client_addr, HOST,
             str(UDP_PORT), "LXPDIAG-UDP-01", check=True)
    print(f"tcp_granted_http={tcp.stdout.strip() or '000'} udp_inject={udp.stdout.strip()}")
    grant_client_after = wait_counter("usr", "to_tun_pkts", grant_client_pre)
    grant_exit_after = wait_counter("exit1", "to_tun_pkts", grant_exit_pre)
    print(f"granted_counters client_tun={grant_client_pre}->{grant_client_after} exit_tun={grant_exit_pre}->{grant_exit_after}")
    time.sleep(5)
    udp_log = out("exit1", "sh", "-lc", "grep -F 'LXPDIAG-UDP-01' /state/udp-host.log || true")
    print(f"udp_service_logged={'yes' if udp_log else 'no'}")
    current_after = json.loads(out("usr", "cat", "/state/status.json")).get("current") or {}
    print(f"same_link_before_after={current_before.get('d') == current_after.get('d')} since_s={current_before.get('since_s')}->{current_after.get('since_s')}")
    time.sleep(max(0, CAPTURE_SECS - 10))
    capture_dir = ROOT / "captures"
    capture_dir.mkdir(mode=0o700, parents=True, exist_ok=True)
    os.chmod(capture_dir, 0o700)
    for (node, iface), path in cap_paths.items():
        count = out(node, "cat", path + ".count")
        local_copy = capture_dir / f"{node}-{iface}.pcap"
        sh("docker", "cp", f"{PREFIX}-{node}:{path}", str(local_copy))
        os.chmod(local_copy, 0o600)
        print_observation(f"capture {node}/{iface} n={count} file={local_copy}", parse_pcap(local_copy))

    print("lab_state=preserved; no common lab, host firewall, production source, or pilot service changed")


if __name__ == "__main__":
    if len(sys.argv) > 1 and sys.argv[1] == "capture":
        capture_child()
    elif len(sys.argv) > 1 and sys.argv[1] == "inject":
        inject_child()
    else:
        run()
