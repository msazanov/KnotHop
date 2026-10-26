#!/usr/bin/env python3
"""Isolated HOST_ACCESS host-TCP trace on the post-D1 snapshot (2026-10-25).

Diagnostic only: starts its own --internal Docker network and containers (own prefix), runs the snapshot
knothopd/driver, and traces grant -> TCP, revoke -> grant -> TCP, exit restart -> new Link -> TCP with
small-snaplen raw-IPv4 pcaps (0600) on usr tun0, exit1 khd0/dummy0/lo and exit2 khd0, plus `ss -tn`, node
counters, the client's *current exit* and client/node log excerpts for every probe.

  python3 lxmf_host_tcp_trace_2026_10_25.py [SNAPSHOT_DIR]        # fresh lab, refuses a used E2E_ROOT
  python3 lxmf_host_tcp_trace_2026_10_25.py capture IFACE PATH SECS MAXBYTES   # (internal) capture child

Never touches the shared lab, host firewall, production source, pilot or public RNS. Secrets are not printed.
"""
import hashlib
import json
import os
import socket
import struct
import subprocess
import sys
import time
from pathlib import Path
from types import SimpleNamespace

HERE = Path(__file__).resolve().parent
HOST = "1.1.1.1"      # dummy0 address of exit1 (HOST_PUB in the harness)
HOST2 = "11.22.33.98"     # extra address added after exit1 start (inventory-refresh probe)
INET = "1.1.1.1"
WATCH = (HOST, HOST2, INET)
SNAPLEN = 96
TCP_FLAGS = {0x02: "SYN", 0x12: "SYN-ACK", 0x10: "ACK", 0x18: "PSH-ACK", 0x11: "FIN-ACK", 0x04: "RST", 0x14: "RST-ACK"}


# ------------------------------------------------------------------ capture child (runs inside a container)
def capture_child(iface, path, secs, maxbytes):
    os.umask(0o077)
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
    os.write(fd, struct.pack("<IHHIIII", 0xA1B2C3D4, 2, 4, 0, 0, SNAPLEN, 101))   # raw IPv4
    # ETH_P_ALL: protocol-specific packet sockets see only received frames, not those the kernel transmits.
    s = socket.socket(socket.AF_PACKET, socket.SOCK_DGRAM, socket.htons(3))
    s.bind((iface, 3))
    s.settimeout(0.25)
    watch = {socket.inet_aton(a) for a in WATCH}
    end, written = time.monotonic() + secs, 24
    while time.monotonic() < end and written < maxbytes and not os.path.exists("/tmp/trace.stop"):
        try:
            pkt, addr = s.recvfrom(65535)
        except socket.timeout:
            continue
        if addr[1] != 0x0800 or len(pkt) < 20 or not (pkt[12:16] in watch or pkt[16:20] in watch or pkt[9] == 1):
            continue   # only the watched flows (+ any ICMP, e.g. frag-needed)
        ts = time.time()
        rec = struct.pack("<IIII", int(ts), int((ts % 1) * 1e6), min(len(pkt), SNAPLEN), len(pkt)) + pkt[:SNAPLEN]
        os.write(fd, rec)
        written += len(rec)
    os.close(fd)


# ------------------------------------------------------------------ pcap analysis (host side)
def read_pcap(path):
    data = Path(path).read_bytes()
    off, rows = 24, []
    while off + 16 <= len(data):
        sec, usec, caplen, wire = struct.unpack_from("<IIII", data, off)
        off += 16
        pkt = data[off:off + caplen]
        off += caplen
        if len(pkt) < 20 or pkt[0] >> 4 != 4:
            continue
        ihl, proto = (pkt[0] & 15) * 4, pkt[9]
        row = {"t": sec + usec / 1e6, "src": socket.inet_ntoa(pkt[12:16]), "dst": socket.inet_ntoa(pkt[16:20]),
               "proto": proto, "len": wire}
        if proto == 6 and len(pkt) >= ihl + 14:
            sport, dport = struct.unpack_from("!HH", pkt, ihl)
            flags = pkt[ihl + 13] & 0x3F
            row.update(sport=sport, dport=dport, flags=TCP_FLAGS.get(flags, hex(flags)))
        rows.append(row)
    return rows


def window_summary(rows, t0, t1, ip):
    """Counts of TCP packets to/from ip:8080 (and ICMP) within [t0-0.5, t1+0.5]."""
    out = {}
    for r in rows:
        if not (t0 - 0.5 <= r["t"] <= t1 + 0.5):
            continue
        if r["proto"] == 1:
            key = "ICMP"
        elif r["proto"] == 6 and ip in (r["src"], r["dst"]):
            key = ("->" if r["dst"] == ip else "<-") + r["flags"] + ("+data" if r["len"] > 60 and r["flags"] in ("ACK", "PSH-ACK") else "")
        else:
            continue
        out[key] = out.get(key, 0) + 1
    return out


# ------------------------------------------------------------------ lab
def main(snapshot_arg):
    sys.path.insert(0, str(HERE))
    import run_lxmf_snapshot_e2e as launcher

    snapshot = Path(snapshot_arg).expanduser().resolve()
    manifest = json.loads((snapshot / "manifest.json").read_text())
    for name in ("knothopd", "driver"):
        assert launcher.digest(snapshot / name) == manifest["artifacts"][name], f"{name} digest mismatch"
    archive = snapshot / "source-inputs"
    fixtures = {}
    for rel in ("bench/tests/lxmf_host_access_e2e.py", "bench/tests/lxmf_host_access_e2e_scenarios.py",
                "bench/tests/lxmf_host_access_e2e_services.py"):
        fixtures[rel] = launcher.digest(HERE.parent.parent / rel)
        if os.environ.get("TRACE_FIXED_ONLY") and rel.endswith("_scenarios.py"):
            continue    # the fixed harness under test intentionally differs from the snapshot archive; its sha is printed below
        assert fixtures[rel] == manifest["inputs"]["files"][rel] == launcher.digest(archive / rel), f"{rel}: worktree != snapshot archive"
    prefix = os.environ.get("E2E_PREFIX", "lxtcp-20261025a")
    root = Path(os.environ.get("E2E_ROOT", Path.home() / ".cache/knothop-lxtcp-20261025/run1"))
    if root.exists() and any(root.iterdir()):
        raise SystemExit(f"E2E_ROOT {root} is not empty; refusing to reuse")
    subnet = launcher.unused_subnet()
    os.environ.update(E2E_BIN=str(snapshot / "knothopd"), E2E_DRIVER=str(snapshot / "driver"),
                      E2E_PREFIX=prefix, E2E_ROOT=str(root), E2E_SUBNET=subnet)
    os.umask(0o077)
    import lxmf_host_access_e2e as lab
    import lxmf_host_access_e2e_scenarios as S

    raw_sh = lab.sh

    def private_sh(*command, **kwargs):          # same as the snapshot launcher: ZZ region, no network for helper runs
        if command[:2] == ("docker", "run"):
            at = command.index(lab.IMAGE)
            options = list(command[:at])
            if "--network" not in options:
                options += ["--network", "none"]
            command = (*options, "-e", "KNOTHOP_REGION=ZZ", *command[at:])
        return raw_sh(*command, **kwargs)

    lab.sh = private_sh
    S.H = lab
    root.mkdir(mode=0o700, parents=True, exist_ok=True)
    events = root / "trace-events.jsonl"
    NAME = lab.NAME
    print(f"prefix={prefix} subnet={subnet} root={root} manifest={launcher.digest(snapshot / 'manifest.json')[:16]}", flush=True)
    print(f"knothopd={launcher.digest(snapshot / 'knothopd')} driver={launcher.digest(snapshot / 'driver')}", flush=True)
    print("fixtures:", json.dumps({k.split('/')[-1]: v[:16] for k, v in fixtures.items()}), flush=True)

    def emit(kind, **kv):
        kv.update(kind=kind, ts=round(time.time(), 3))
        with open(events, "a") as f:
            f.write(json.dumps(kv, ensure_ascii=False) + "\n")
        os.chmod(events, 0o600)
        return kv

    def exit_name(d):
        return next((n for n in ("exit1", "exit2") if S.CTX[n]["d"] == d), str(d)[:8])

    def cur():
        c = S.usr_exit()
        return {"exit": exit_name(c.get("d")), "since_s": c.get("since_s")}

    def tun(node):
        j = lab.jread(node, "/state/status.json") or {}
        t = j.get("tun") or {}
        keys = ("from_tun_pkts", "to_tun_pkts", "unauth_drops", "route_miss", "send_errors", "tun_write_drops", "not_ipv4", "routes", "host_acl_ready")
        return {k: t.get(k) for k in keys} | {"uptime_s": j.get("uptime_s")}

    def snap():
        return {"cur": cur(), "usr": tun("usr"), "exit1": tun("exit1"), "exit2": tun("exit2")}

    def log_since(rel, t0, limit=40):
        keep = ("смена", "тишина", "QUIC", "quic", "tcp", "текущий", "недоступен", "носител", "ACL", "clash", "отказал", "admitted", "слушаю", "host", "close link")
        lines = []
        try:
            for line in (root / rel).read_text(errors="replace").splitlines():
                if line.startswith("[") and "]" in line:
                    try:
                        ts = int(line[1:line.index("]")]) / 1000
                    except ValueError:
                        continue
                    if ts >= t0 and "announce" not in line and any(k in line for k in keep):
                        lines.append(time.strftime("%H:%M:%S", time.localtime(ts)) + line[line.index("]") + 1:][:130])
        except OSError:
            pass
        return lines[-limit:]

    windows = []   # (label, t0, t1, exit_before, exit_after)

    def probe(label, ip=HOST, t=6, port=8080, path="/"):
        pre = snap()
        t0 = time.time()
        p = subprocess.Popen(["docker", "exec", NAME("usr"), "curl", "--noproxy", "*", "-sS", "-m", str(t), "-o", "/dev/null", "-w",
                              "%{http_code} conn=%{time_connect} total=%{time_total} bytes=%{size_download}", f"http://{ip}:{port}{path}"],
                             stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
        time.sleep(1.3)
        ss_usr = lab.dx("usr", "ss", "-tnH", "dst", ip).stdout.split()[:1]
        ss_exit = lab.dx("exit1", "sh", "-c", "ss -tanH 'sport = :8080' | awk '{print $1}' | sort | uniq -c | tr '\\n' ' '").stdout.strip()
        out, err = p.communicate(timeout=t + 20)
        t1 = time.time()
        time.sleep(1.6)   # status.json counters are refreshed about once a second
        post = snap()
        code = out.split()[0] if out.split() else "000"
        r = emit("probe", label=label, ip=ip, code=code, curl=out.strip(), err=err.strip()[-90:], ss_usr_state=ss_usr, ss_exit_8080=ss_exit,
                 t0=round(t0, 3), t1=round(t1, 3), cur_before=pre["cur"], cur_after=post["cur"],
                 delta={n: {k: (post[n][k] or 0) - (pre[n][k] or 0) for k in ("from_tun_pkts", "to_tun_pkts", "unauth_drops", "route_miss", "tun_write_drops")}
                        for n in ("usr", "exit1", "exit2")})
        windows.append((label, ip, t0, t1))
        d = r["delta"]
        print(f"  [{label:28}] http={code:3} cur={pre['cur']['exit']}/{pre['cur']['since_s']}->{post['cur']['exit']}/{post['cur']['since_s']} ss_usr={ss_usr} ss_exit1={ss_exit or '-'} "
              f"usr(from/to)={d['usr']['from_tun_pkts']}/{d['usr']['to_tun_pkts']} exit1(to/from/unauth)={d['exit1']['to_tun_pkts']}/{d['exit1']['from_tun_pkts']}/{d['exit1']['unauth_drops']} "
              f"exit2(to/from)={d['exit2']['to_tun_pkts']}/{d['exit2']['from_tun_pkts']}", flush=True)
        return code, r

    caps = []   # (node, iface, path_in_container)
    gen = {"n": 0}

    def start_caps(secs=1500):
        gen["n"] += 1
        for node, iface in (("usr", "tun0"), ("exit1", "khd0"), ("exit1", "dummy0"), ("exit1", "lo"), ("exit2", "khd0")):
            path = f"/state/trace-g{gen['n']}-{node}-{iface}.pcap"
            lab.sh("docker", "exec", "-d", NAME(node), "python3", f"/e2e/{Path(__file__).name}", "capture", iface, path, str(secs), str(3_000_000))
            caps.append((node, iface, path))

    def grant_flow(op, rights=64):
        _, _, st = S.get_status("admin", "exit1")
        assert st.get("state") == "applied" and st.get("durable_ack") is True, f"status.get not durable: {st.get('state')}"
        rid, sub = S.submit("admin", S.CTX["exit1"]["d"], op, holder=S.CTX["usr"]["hash"], rights=rights)
        fin = S.await_final("admin", rid)
        res = fin.get("result") or {}
        emit(op, state=fin.get("state"), durable=res.get("durable_ack"), committed=res.get("record_committed"), effective=res.get("effective_host_allowed"))
        print(f"  {op}: state={fin.get('state')} durable={res.get('durable_ack')} committed={res.get('record_committed')} effective_host_allowed={res.get('effective_host_allowed')}", flush=True)
        return fin

    def stable_on(name, secs=8, limit=150):
        """Wait until the client's current exit is `name` for `secs` seconds without since_s resetting."""
        d = S.CTX[name]["d"]
        end = time.time() + limit
        first = None
        while time.time() < end:
            c = cur()
            if c["exit"] == name and (c["since_s"] or 0) >= secs:
                return c
            time.sleep(1)
        raise TimeoutError(f"client not stable on {name} for {secs}s within {limit}s (last {cur()})")

    try:
        raw_sh("docker", "image", "inspect", lab.IMAGE)
        raw_sh("docker", "network", "create", "--internal", "--subnet", subnet, "--label", f"knothop.e2e.owner={prefix}", lab.NET)
        (root / "run-manifest.json").write_text(json.dumps({"snapshot": str(snapshot), "subnet": subnet, "region": "ZZ", "internal": True,
                                                            "script_sha256": launcher.digest(Path(__file__))}, indent=1) + "\n")
        lab.cmd_up(SimpleNamespace())
        lab.wait(lambda: lab.dx("deleg", "test", "-f", "/state/identity.key").returncode == 0, 60, "delegate identity")
        root_hash = lab.whoami("admin")["hash"]
        members = [lab.whoami(r)["hash"] for r in ("usr", "deleg")]
        lab.wait(lambda: all(launcher.holder_in_saved_root(lab, r, root_hash, h) for r in ("admin", "exit1") for h in members), 120, "enrollment saved")
        S.discover()
        S.select_exit(S.CTX["exit1"]["d"])
        S.wait_usr_link(S.CTX["exit1"]["d"], 120)
        start_caps()
        t_start = time.time()
        mtu = lab.dx("usr", "sh", "-c", "ip -o link show tun0 | sed 's/.*mtu \\([0-9]*\\).*/\\1/'").stdout.strip()
        emit("env", usr_tun0_mtu=mtu, exit_khd0_mtu=lab.dx("exit1", "sh", "-c", "ip -o link show khd0 | sed 's/.*mtu \\([0-9]*\\).*/\\1/'").stdout.strip(),
             exit1_addrs=lab.dx("exit1", "sh", "-c", "ip -4 -o addr | awk '{print $2,$4}' | tr '\\n' ';'").stdout.strip(),
             route_usr=lab.dx("usr", "ip", "route", "get", HOST).stdout.strip(),
             route_exit=lab.dx("exit1", "ip", "route", "get", "198.18.0.2", "from", HOST).stdout.strip())
        print("env:", events.read_text().splitlines()[-1][:600], flush=True)
        ctrl = lab.dx("exit1", "curl", "--noproxy", "*", "-s", "-m", "4", "-o", "/dev/null", "-w", "%{http_code}", f"http://{HOST}:8080/").stdout.strip()
        print(f"service control on exit1 (local): http={ctrl}", flush=True)
        stable_on("exit1", 10)

        def phase6():
            """Fixed harness (S.host_state) across an exit1 restart: never FAIL, BLOCKED only if the client cannot return to exit1."""
            print("== PHASE 6: fixed harness (host_state / host_probe_verdict) across exit1 restart", flush=True)
            grant_flow("rights.grant")
            time.sleep(2)

            def check(label, want_open):
                t0 = time.time()
                state, code = S.host_state(HOST)
                verdict = S.host_probe_verdict(want_open, state)
                print(f"  [{label:28}] state={state} code={code} verdict={verdict} waited={time.time() - t0:.1f}s cur={cur()}", flush=True)
                emit("fixed_check", label=label, state=state, code=code, verdict=verdict, waited=round(time.time() - t0, 1))
                return verdict

            out = [check("P6 before restart (positive)", True)]
            emit("restart", node="exit1")
            S.restart("exit1")
            lab.wait(lambda: (S.exit_status("exit1").get("tun") or {}).get("host_acl_ready") is True, 90, "exit1 ready", step=1.0)
            start_caps()
            for k in range(1, 5):       # the former D5/I3/J11 window: right after restart, client may be failing over to exit2
                out.append(check(f"P6 after restart #{k} (pos)", True))
            saved = S.PIN_WAIT_S
            S.PIN_WAIT_S = 15
            try:
                S.select_exit(S.CTX["exit2"]["d"])
                stable_on("exit2", 6)
                out.append(check("P6 forced exit2 (pos, 15s)", True))   # control: must be BLOCKED, never FAIL
            finally:
                S.PIN_WAIT_S = saved
            print("P6 verdicts:", out, flush=True)
            assert "FAIL" not in out[:-1], out
            assert out[-1] == "BLOCKED", out
        if os.environ.get("TRACE_FIXED_ONLY"):
            phase6()
            emit("end", secs=round(time.time() - t_start))
            return

        print("== PHASE 1: no grant -> grant -> TCP (D0/D5)", flush=True)
        probe("P1 no-grant")
        grant_flow("rights.grant")
        time.sleep(2)
        probe("P1 granted+2s")
        probe("P1 granted again")
        probe("P1 bulk /slow 4s (MSS/MTU)", t=4, path="/slow")
        probe("P1 internet", INET, port=80)

        print("== PHASE 2: revoke -> TCP -> grant -> TCP (H/I1, same Link)", flush=True)
        grant_flow("rights.revoke")
        time.sleep(2)
        probe("P2 revoked")
        grant_flow("rights.grant")
        time.sleep(2)
        probe("P2 regranted+2s")

        print("== PHASE 3: inventory refresh: address added to exit1 after start", flush=True)
        lab.dx("exit1", "sh", "-c", f"ip addr replace {HOST2}/32 dev dummy0")
        lab.dx("usr", "ip", "route", "replace", f"{HOST2}/32", "dev", "tun0")
        t_add = time.time()
        emit("addr_added", ip=HOST2)
        for i, wait_s in enumerate((0, 3, 4, 8)):
            time.sleep(wait_s)
            probe(f"P3 new-addr +{round(time.time() - t_add, 1)}s", HOST2, t=4)

        print("== PHASE 4: forced exit2 (control: host address lives on exit1 only)", flush=True)
        t4 = time.time()
        S.select_exit(S.CTX["exit2"]["d"])
        stable_on("exit2", 6)
        probe("P4 on-exit2 host")
        probe("P4 on-exit2 internet", INET, port=80)
        S.select_exit(S.CTX["exit1"]["d"])
        stable_on("exit1", 8)
        probe("P4 back-on-exit1 host")

        print("== PHASE 5: restart exit1 -> new Link -> TCP (I3), harness-faithful then monitored", flush=True)
        t5 = time.time()
        emit("restart", node="exit1")
        S.restart("exit1")
        lab.wait(lambda: (S.exit_status("exit1").get("tun") or {}).get("host_acl_ready") is True, 90, "exit1 ready", step=1.0)
        t_ready = time.time()
        start_caps()    # old exit1 capture children died with the container netns
        S.wait_usr_link(S.CTX["exit1"]["d"], 150)
        t_link = time.time()
        time.sleep(8)
        print(f"  restart->ready {t_ready - t5:.1f}s, ->current==exit1 {t_link - t5:.1f}s; harness-style probe now", flush=True)
        probe("P5 harness-style (I3)")
        end = time.time() + 100
        k = 0
        while time.time() < end:
            k += 1
            probe(f"P5 monitor {k}", t=4)
            time.sleep(4)
        probe("P5 internet", INET, port=80)
        print("-- client/exit1 log excerpts since restart:", flush=True)
        for line in log_since("usr/client.log", t5, 25):
            print("   usr  ", line, flush=True)
        for line in log_since("exit1/node.log", t5, 15):
            print("   exit1", line, flush=True)
        emit("end", secs=round(time.time() - t_start))
    finally:
        for node, _, _ in caps:
            lab.dx(node, "touch", "/tmp/trace.stop")
        time.sleep(1.5)
        outdir = root / "captures"
        outdir.mkdir(mode=0o700, exist_ok=True)
        summary = {}
        for node, iface, path in caps:
            local = outdir / path.rsplit("/", 1)[1]
            if lab.sh("docker", "cp", f"{NAME(node)}:{path}", str(local), check=False).returncode == 0:
                os.chmod(local, 0o600)
                summary[f"{node}/{iface}/{path.split('-')[1]}"] = (local, read_pcap(local))
        lines = []
        for label, ip, t0, t1 in windows:
            parts = []
            for key, (local, rows) in summary.items():
                w = window_summary(rows, t0, t1, ip)
                if w:
                    parts.append(f"{key}: " + ",".join(f"{k}x{v}" for k, v in sorted(w.items())))
            lines.append(f"{label} [{ip}] {time.strftime('%H:%M:%S', time.localtime(t0))}: " + (" | ".join(parts) or "no packets on any watched interface"))
        print("== pcap windows (tun0=usr client TUN, khd0=exit TUN, lo/dummy0=exit local delivery)", flush=True)
        for line in lines:
            print("  " + line, flush=True)
        (root / "trace-pcap-windows.txt").write_text("\n".join(lines) + "\n")
        os.chmod(root / "trace-pcap-windows.txt", 0o600)
        for role in ("hub", "site", "admin", "exit1", "exit2", "usr", "deleg", "foreign"):
            raw_sh("docker", "rm", "-f", lab.NAME(role), check=False)
        raw_sh("docker", "network", "rm", lab.NET, check=False)
        print(f"lab stopped; state+pcaps preserved: {root}", flush=True)


if __name__ == "__main__":
    if len(sys.argv) > 1 and sys.argv[1] == "capture":
        capture_child(sys.argv[2], sys.argv[3], int(sys.argv[4]), int(sys.argv[5]))
    else:
        main(sys.argv[1] if len(sys.argv) > 1 else str(Path.home() / ".cache/knothop-lxe2e-snapshots/post-d1-20261025T111721"))
