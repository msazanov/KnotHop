#!/usr/bin/env python3
"""IPv4 tunnel test cell: real kernel TCP / UDP / ICMP / QUIC through a VPN, compared on identical terms.

Topology (internal Docker network, nothing published):

    gen (tools, pinned to its own core) --\\
                                           c  ==== carrier (netem here) ====  e  --NAT-->  srv (iperf3, QUIC server)
          VPN client, 1 core ------------/        VPN server, 1 core

stacks:  KnotHop    RNS Link datagrams over QUIC DATAGRAM (this project)
         awg     AmneziaWG 3.1 userspace, the L3 reference
         direct  no tunnel: c talks to srv. Ceiling of the tools and of the host, not a VPN

The traffic generators run in `c` but are pinned to a different core than the VPN process, so the VPN is
measured on one core while the generator never steals from it. CPU is per-process (utime+stime of the VPN
process on c, of the VPN process on e) plus the cgroup of `e`, whose single core also carries the kernel's
NAT/forwarding work.

Netem is applied only to the carrier path (c->e and e->c), never to the e->srv leg.
"""
import argparse
import json
import os
import re
import shutil
import signal
import statistics
import subprocess
import tempfile
import time
from pathlib import Path

from awg_backbone import SECRETS, cmd, dex, put, redact

HERE = Path(__file__).resolve().parent
OUT = HERE / "results" / "l3"
IMAGE = "knothop-bench:l3"
KNOTHOP_BIN = Path(os.environ.get("RNS_IROH_BIN", str(Path.home() / ".cache/knothop-target/dgram/release/rns-iroh-node")))
AWG_DIR = Path.home() / ".cache/knothop-target/awgbin"
CPUSETS = {"srv": "6-7", "e": "3", "c": "4-5", "a": "2", "b": "1"}
VPN_CORE = {"c": "4", "e": "3", "a": "2", "b": "1"}
GEN_CORE = "5"
TUN_MTU = 1327  # == Link MDU at HW_MTU 1400; the same inner MTU is given to AWG so segment sizes match


def ensure_awg_bins():
    if (AWG_DIR / "amneziawg-go").exists() and (AWG_DIR / "awg").exists():
        return
    AWG_DIR.mkdir(parents=True, exist_ok=True)
    cid = cmd("docker", "create", "knothop-bench:awg31")
    try:
        for name in ("amneziawg-go", "awg"):
            cmd("docker", "cp", f"{cid}:/usr/local/bin/{name}", str(AWG_DIR / name))
    finally:
        cmd("docker", "rm", "-f", cid, check=False)


def host_pid(container, comm):
    for line in cmd("docker", "top", container, "-eo", "pid,comm", check=False).splitlines()[1:]:
        parts = line.split(None, 1)
        if len(parts) == 2 and parts[1].strip().startswith(comm):
            return int(parts[0])
    return None


def proc_cpu_s(pid):
    try:
        rest = Path(f"/proc/{pid}/stat").read_text().rsplit(")", 1)[1].split()
        return (int(rest[11]) + int(rest[12])) / os.sysconf("SC_CLK_TCK")
    except (OSError, IndexError, ValueError):
        return None


def proc_rss_kb(pid):
    try:
        for line in Path(f"/proc/{pid}/status").read_text().splitlines():
            if line.startswith("VmHWM:"):
                return int(line.split()[1])
    except OSError:
        pass
    return None


def ctx_switches(pid):
    """Voluntary + involuntary context switches summed over all threads of the process."""
    total = 0
    try:
        for task in Path(f"/proc/{pid}/task").iterdir():
            for line in (task / "status").read_text().splitlines():
                if line.startswith(("voluntary_ctxt_switches", "nonvoluntary_ctxt_switches")):
                    total += int(line.split()[1])
    except OSError:
        return None
    return total


def cgroup_cpu_s(container):
    out = dex(container, "sh", "-c", "awk '/^usage_usec/{print $2}' /sys/fs/cgroup/cpu.stat", check=False)
    return int(out) / 1e6 if out.strip().isdigit() else None


def netem(container, dst_ip, spec):
    """Delay/loss only on packets leaving `container` towards dst_ip."""
    if not spec:
        return
    dex(container, "tc", "qdisc", "replace", "dev", "eth0", "root", "handle", "1:", "prio", "bands", "3",
        "priomap", *["2"] * 16)
    dex(container, "tc", "qdisc", "add", "dev", "eth0", "parent", "1:1", "handle", "10:", "netem", *spec.split())
    dex(container, "tc", "filter", "add", "dev", "eth0", "protocol", "ip", "parent", "1:", "prio", "1",
        "u32", "match", "ip", "dst", f"{dst_ip}/32", "flowid", "1:1")


def netem_extra(container, dst_ip, spec):
    """A second destination through the same netem class (A talks to both C and E on one eth0)."""
    dex(container, "tc", "filter", "add", "dev", "eth0", "protocol", "ip", "parent", "1:", "prio", "1",
        "u32", "match", "ip", "dst", f"{dst_ip}/32", "flowid", "1:1")


def percentile(sorted_vals, p):
    if not sorted_vals:
        return None
    return sorted_vals[max(0, min(len(sorted_vals) - 1, (len(sorted_vals) * p + 99) // 100 - 1))]


class Cell:
    def __init__(self, a):
        self.a = a
        self.names = {r: f"knothop-l3-{a.tag}-{r}" for r in ("srv", "e", "c", "a", "b")}
        self.net = f"knothop-l3-{a.tag}"
        self.ip = {}
        self.res = {"stack": a.stack, "netem": a.netem, "tests": {}, "meta": {"tun_mtu": TUN_MTU}, "success": False}
        self.created = []
        self.network = False
        self.shared = None

    # ---------------------------------------------------------------- infrastructure
    def up(self):
        a = self.a
        cmd("docker", "network", "create", "--internal", self.net)
        self.network = True
        roles = ("srv", "c") if a.stack == "direct" else (("srv", "e", "c", "a", "b") if a.stack == "knothop-multi" else (("srv", "e", "c", "a") if a.stack == "knothop-hop" else ("srv", "e", "c")))
        mounts = ["-v", f"{self.shared}:/shared"]
        if a.stack in ("knothop", "knothop-hop", "knothop-multi"):
            mounts += ["-v", f"{KNOTHOP_BIN}:/usr/local/bin/rns-iroh-node:ro"]
        if a.stack == "awg":
            mounts += ["-v", f"{AWG_DIR}:/opt/awg:ro"]
        for r in roles:
            cmd("docker", "run", "-d", "--name", self.names[r], "--network", self.net, "--cpuset-cpus", CPUSETS[r],
                "--cap-add", "NET_ADMIN", "--cap-add", "SYS_PTRACE", "--device", "/dev/net/tun", "--sysctl", "net.ipv4.ip_forward=1",
                *(["--sysctl", f"net.core.rmem_default={a.rmem_mb << 20}", "--sysctl", f"net.core.rmem_max={a.rmem_mb << 20}",
                   "--sysctl", f"net.core.wmem_default={a.rmem_mb << 20}", "--sysctl", f"net.core.wmem_max={a.rmem_mb << 20}"] if a.rmem_mb and r in ("c", "e", "a") else []),
                "--memory", "3g", *mounts, "--entrypoint", "sleep", IMAGE, "infinity")
            self.created.append(self.names[r])
        for r in roles:
            self.ip[r] = cmd("docker", "inspect", self.names[r], "--format",
                             "{{range .NetworkSettings.Networks}}{{.IPAddress}}{{end}}")
        self.res["meta"]["ips"] = self.ip
        self.res["meta"]["effective_cpusets"] = {r: dex(self.names[r], "cat", "/sys/fs/cgroup/cpuset.cpus.effective") for r in roles}
        shutil.copy(HERE / "quic_probe.py", self.shared / "quic_probe.py")
        cmd("docker", "exec", "-d", self.names["srv"], "iperf3", "-s")
        cmd("docker", "exec", "-d", self.names["srv"], "sh", "-c", "exec python3 /shared/quic_probe.py server 4433 > /shared/quic-srv.log 2>&1")

    def start_knothop(self):
        a = self.a
        tune = (f"--mode tun --carrier datagram --dgram-mtu 1400 --cipher gcm --data-cap 4096 --chan-buf 1024 "
                f"--quic-initial-mtu 1452 --tun-mtu {TUN_MTU} --quic-cc {a.knothop_cc} --quic-cc-mbit {a.knothop_cc_mbit} "
                f"--tun-txqlen {a.tun_txqlen}" + (f" --tun-qdisc {a.tun_qdisc}" if a.tun_qdisc else ""))
        if a.knothop_buf_mb:
            mb = a.knothop_buf_mb << 20
            # chan-buf counts packets: size it for the same number of full-size packets as the byte buffers hold
            tune = tune.replace("--chan-buf 1024", f"--chan-buf {max(1024, mb // 1400)}")
            tune += f" --quic-dg-send-buf {mb} --quic-dg-recv-buf {mb}"
        e, c = self.names["e"], self.names["c"]
        multi = a.stack == "knothop-multi"
        hop = a.stack in ("knothop-hop", "knothop-multi")
        relays = ["a", "b"] if multi else ["a"]
        if multi:
            # Fast failure detection on every layer: QUIC path idle, and the client's own silence limit.
            tune += f" --path-idle-ms {a.path_idle_ms} --path-keepalive-ms {max(a.path_idle_ms // 3, 200)} --conn-idle-ms {a.conn_idle_ms}"
            if a.relay_debug:
                tune += " --relay-debug"
            if a.link_keepalive_s:
                tune += f" --link-keepalive-s {a.link_keepalive_s}"
        ctune = tune + (f" --fail-ms {a.fail_ms} --relink-timeout-ms {a.relink_ms}" if multi else "")
        if multi:
            tune_e = tune + f" --announce-s {a.announce_s} --announce-warmup-s 10"
        else:
            tune_e = tune
        cmd("docker", "exec", "-d", e, "sh", "-c",
            # стенд: выход lib::run без допуска по записям (enforce) разрешён только явным флагом (H18)
            f"KNOTHOP_LAB_EXIT_NO_ENFORCE=1 exec taskset -c {VPN_CORE['e']} /usr/local/bin/rns-iroh-node --role e --ip {self.ip['e']} --relay none {tune_e} "
            f"--tun-ip 10.99.0.1/24 > /shared/e.log 2>&1")
        if hop:
            # A (and B): pure RNS transport nodes, no TUN; they dial E and accept C. Wait for E's peer file like lev_cell.py.
            t0 = time.monotonic()
            while not (self.shared / "e.json").exists():
                if time.monotonic() - t0 > 30:
                    raise TimeoutError("E did not publish its address: " + (self.shared / "e.log").read_text()[-500:])
                time.sleep(0.2)
            for r in relays:
                cmd("docker", "exec", "-d", self.names[r], "sh", "-c",
                    f"exec taskset -c {VPN_CORE[r]} /usr/local/bin/rns-iroh-node --role {r} --ip {self.ip[r]} --relay none {tune} "
                    f"--dial e > /shared/{r}.log 2>&1")
            for r in relays:
                t0 = time.monotonic()
                while not (self.shared / f"{r}.json").exists():
                    if time.monotonic() - t0 > 30:
                        raise TimeoutError(f"{r} did not publish its address: " + (self.shared / f"{r}.log").read_text()[-500:])
                    time.sleep(0.2)
        cmd("docker", "exec", "-d", c, "sh", "-c",
            f"exec taskset -c {VPN_CORE['c']} /usr/local/bin/rns-iroh-node --role c --ip {self.ip['c']} --relay none {ctune} "
            f"--tun-ip 10.99.0.2/24 --dial {','.join(relays) if hop else 'e'} > /shared/c.log 2>&1")
        deadline = time.monotonic() + 90
        while not (self.shared / "ready").exists():
            if time.monotonic() > deadline:
                raise TimeoutError("KnotHop client never ready: " + (self.shared / "c.log").read_text()[-600:])
            for n in (e, c):
                if cmd("docker", "inspect", n, "--format", "{{.State.Running}}") != "true":
                    raise RuntimeError(f"{n} stopped")
            time.sleep(0.2)
        dex(c, "ip", "route", "add", f"{self.ip['srv']}/32", "via", "10.99.0.1", "dev", "tun0")
        dex(e, "iptables", "-t", "nat", "-A", "POSTROUTING", "-s", "10.99.0.0/24", "-o", "eth0", "-j", "MASQUERADE")
        self.vpn = {"c": host_pid(c, "rns-iroh-node"), "e": host_pid(e, "rns-iroh-node")}
        for r in (relays if hop else []):
            self.vpn[r] = host_pid(self.names[r], "rns-iroh-node")

    def start_awg(self):
        e, c = self.names["e"], self.names["c"]
        priv = {r: dex(self.names[r], "/opt/awg/awg", "genkey") for r in ("c", "e")}
        SECRETS.update(priv.values())
        pub = {r: dex(self.names[r], "/opt/awg/awg", "pubkey", data=priv[r] + "\n") for r in ("c", "e")}
        header = dex(c, "/opt/awg/awg", "genkey")
        SECRETS.add(header)
        tun = {"c": "10.201.0.1", "e": "10.201.0.2"}
        for r, other in (("c", "e"), ("e", "c")):
            allowed = f"{tun[other]}/32" + (f", {self.ip['srv']}/32" if r == "c" else "")
            conf = f"""[Interface]
PrivateKey = {priv[r]}
ListenPort = 51820
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
PublicKey = {pub[other]}
Endpoint = {self.ip[other]}:51820
AllowedIPs = {allowed}
PersistentKeepalive = 25
"""
            n = self.names[r]
            dex(n, "sh", "-c", f"taskset -c {VPN_CORE[r]} /opt/awg/amneziawg-go awg0")
            put(n, "/run/awg0.conf", conf)
            dex(n, "/opt/awg/awg", "setconf", "awg0", "/run/awg0.conf")
            dex(n, "ip", "address", "add", f"{tun[r]}/30", "dev", "awg0")
            dex(n, "ip", "link", "set", "dev", "awg0", "mtu", str(TUN_MTU), "txqueuelen", str(self.a.tun_txqlen), "up")
            if self.a.tun_qdisc:
                dex(n, "tc", "qdisc", "replace", "dev", "awg0", "root", self.a.tun_qdisc)
        dex(c, "ip", "route", "add", f"{self.ip['srv']}/32", "dev", "awg0")
        dex(e, "iptables", "-t", "nat", "-A", "POSTROUTING", "-s", "10.201.0.0/30", "-o", "eth0", "-j", "MASQUERADE")
        dex(c, "ping", "-c", "3", "-W", "3", tun["e"], timeout=20)
        self.vpn = {"c": host_pid(c, "amneziawg-go"), "e": host_pid(e, "amneziawg-go")}

    def start(self):
        self.vpn = {"c": None, "e": None}
        if self.a.stack in ("knothop", "knothop-hop", "knothop-multi"):
            self.start_knothop()
        elif self.a.stack == "awg":
            self.start_awg()
        if self.a.stack != "direct":
            # The tunnel is the only way to the target: no silent fallback over the carrier.
            dex(self.names["c"], "iptables", "-A", "OUTPUT", "-d", self.ip["srv"], "-o", "eth0", "-j", "REJECT")
        if self.a.netem:
            if self.a.stack == "direct":
                netem(self.names["c"], self.ip["srv"], self.a.netem)
                netem(self.names["srv"], self.ip["c"], self.a.netem)
            elif self.a.stack == "knothop-multi":
                # Both relays carry the full condition on both legs (C<->relay, relay<->E).
                for r in ("a", "b"):
                    (netem if r == "a" else netem_extra)(self.names["c"], self.ip[r], self.a.netem)
                    netem(self.names[r], self.ip["c"], self.a.netem)
                    netem_extra(self.names[r], self.ip["e"], self.a.netem)
                netem(self.names["e"], self.ip["a"], self.a.netem)
                netem_extra(self.names["e"], self.ip["b"], self.a.netem)
            elif self.a.stack == "knothop-hop":
                # Two carrier legs, each with the full condition: C<->A and A<->E. The e->srv leg stays clean.
                netem(self.names["c"], self.ip["a"], self.a.netem)
                netem(self.names["a"], self.ip["c"], self.a.netem)
                # A also sends towards E on the same eth0: route that destination into the same netem class.
                netem_extra(self.names["a"], self.ip["e"], self.a.netem)
                netem(self.names["e"], self.ip["a"], self.a.netem)
            else:
                netem(self.names["c"], self.ip["e"], self.a.netem)
                netem(self.names["e"], self.ip["c"], self.a.netem)
        # Warm the path (ARP, conntrack, first handshake) before anything is measured.
        dex(self.names["c"], "ping", "-c", "3", "-W", "3", self.ip["srv"], timeout=30, check=False)

    # ---------------------------------------------------------------- measurement
    def sample(self):
        s = {"a_vpn": proc_cpu_s(self.vpn["a"]) if self.vpn.get("a") else None,
             "b_vpn": proc_cpu_s(self.vpn["b"]) if self.vpn.get("b") else None,
             "c_vpn": proc_cpu_s(self.vpn["c"]) if self.vpn["c"] else None,
             "e_vpn": proc_cpu_s(self.vpn["e"]) if self.vpn["e"] else None,
             "e_cgroup": cgroup_cpu_s(self.names["e"]) if self.a.stack != "direct" else None,
             "c_ctxsw": ctx_switches(self.vpn["c"]) if self.vpn["c"] else None,
             "e_ctxsw": ctx_switches(self.vpn["e"]) if self.vpn["e"] else None}
        return s

    def measured(self, name, fn):
        before = self.sample()
        t0 = time.monotonic()
        out = fn()
        wall = time.monotonic() - t0
        after = self.sample()
        cpu = {k: round(after[k] - before[k], 3) if "ctxsw" not in k else after[k] - before[k]
               for k in before if before[k] is not None and after[k] is not None}
        out["wall_s"] = round(wall, 2)
        out["cpu_s"] = cpu
        self.res["tests"][name] = out
        return out

    def gen(self, *argv, timeout=120, check=True):
        return dex(self.names["c"], "taskset", "-c", GEN_CORE, *argv, timeout=timeout, check=check)

    def ping_times(self, count, interval=0.2):
        out = self.gen("ping", "-c", str(count), "-i", str(interval), "-W", "2", self.ip["srv"], timeout=count * 3 + 20, check=False)
        times = sorted(float(m) for m in re.findall(r"time=([\d.]+)", out))
        loss = re.search(r"([\d.]+)% packet loss", out)
        return {"n": len(times), "loss_pct": float(loss.group(1)) if loss else None,
                "p50_ms": percentile(times, 50), "p95_ms": percentile(times, 95), "max_ms": times[-1] if times else None,
                "min_ms": times[0] if times else None}

    def t_ping(self):
        return self.ping_times(40)

    def t_mtu(self):
        ok = {}
        for ip_size in (1200, 1280, 1300, 1327, 1328, 1400, 1472):
            payload = ip_size - 28
            out = self.gen("ping", "-c", "2", "-W", "2", "-M", "do", "-s", str(payload), self.ip["srv"], timeout=20, check=False)
            ok[str(ip_size)] = " 0% packet loss" in out
        passing = [int(k) for k, v in ok.items() if v]
        return {"df_ping_ok": ok, "largest_ip_packet_ok": max(passing) if passing else None}

    def iperf(self, *extra, secs):
        """One iperf3 run. The server handles one test at a time and needs a moment after the previous one
        (a client that connects too soon gets a busy/closed server and a result with zero bytes), so wait
        first and retry once if the run produced nothing."""
        j = {}
        for attempt in range(2):
            time.sleep(2.0)
            out = self.gen("iperf3", "-c", self.ip["srv"], "-t", str(secs), "-J", *extra, timeout=secs + 40, check=False)
            try:
                j = json.loads(out)
            except json.JSONDecodeError:
                j = {"error": out[-300:]}
            end = j.get("end", {})
            got = (end.get("sum_received") or end.get("sum") or {}).get("bytes", 0)
            if got and "error" not in j:
                break
            j["retried"] = attempt + 1
        return j

    def diagnose(self):
        """State snapshot taken the moment a transfer produced nothing."""
        d = {}
        def grab(key, container, *argv):
            try:
                d[key] = dex(self.names[container], *argv, check=False, timeout=15)[:1500]
            except Exception as exc:  # noqa: BLE001
                d[key] = f"error: {exc}"
        if "e" in self.names and self.a.stack != "direct":
            grab("e_tun0", "e", "ip", "-s", "link", "show", self.tun_dev())
            grab("e_conntrack_srv", "e", "sh", "-c", f"grep {self.ip['srv']} /proc/net/nf_conntrack | tail -6")
            grab("e_route_to_client", "e", "ip", "route", "get", self.client_tun_ip())
        grab("srv_tcp", "srv", "ss", "-tin")
        grab("srv_tcp_metrics", "srv", "ip", "tcp_metrics", "show")
        grab("c_tun0", "c", "ip", "-s", "link", "show", self.tun_dev())
        return d

    def tun_dev(self):
        return {"knothop": "tun0", "awg": "awg0"}.get(self.a.stack, "eth0")

    def client_tun_ip(self):
        return {"knothop": "10.99.0.2", "awg": "10.201.0.1"}.get(self.a.stack, self.ip["c"])

    def profile_during(self, role, fn, samples=140):
        """Run fn() while sampling the VPN process of `role` from inside its container. Frames are grouped so the
        layers (QUIC/UDP, ring, RNS core, driver, tokio, syscalls, allocator) can be compared."""
        import collections
        import threading
        name = self.names[role]
        stacks, stop = [], threading.Event()
        def sampler():
            while not stop.is_set() and len(stacks) < samples:
                out = cmd("docker", "exec", name, "sh", "-c", "eu-stack -p $(pidof rns-iroh-node) -n 22 2>/dev/null", check=False, timeout=20)
                if out:
                    stacks.append(out)
                time.sleep(0.03)
        th = threading.Thread(target=sampler, daemon=True)
        th.start()
        res = fn()
        stop.set()
        th.join(timeout=30)
        waiting = ("epoll_wait", "futex", "pthread_cond", "nanosleep", "poll", "park", "syscall", "recvmsg", "__GI_")
        leaf = collections.Counter()
        layer = collections.Counter()
        total_run = 0
        keys = (("noq_udp", "quic:udp-io"), ("noq_proto", "quic:proto"), ("noq::", "quic:api"), ("ring_core", "crypto:ring"),
                ("ghash", "crypto:ring"), ("aesni", "crypto:ring"), ("leviculum_core4link", "rns:link"), ("leviculum_core4node", "rns:node"),
                ("leviculum_core9transport", "rns:transport"), ("leviculum_core6packet", "rns:packet"), ("leviculum_core7framing", "rns:hdlc"),
                ("leviculum_std6driver", "rns:driver"), ("leviculum_std10interfaces", "rns:interface"), ("leviculum_core", "rns:other"),
                ("leviculum_std", "rns:std"), ("rns_iroh_node", "app:tun-glue"), ("tokio", "tokio"), ("alloc", "alloc"),
                ("malloc", "alloc"), ("__libc_write", "syscall:write"), ("__libc_read", "syscall:read"), ("sendmsg", "syscall:udp"),
                ("memcpy", "memcpy"), ("clock_gettime", "clock"))
        def group(fn_name):
            for key, lab in keys:
                if key in fn_name:
                    return lab
            return None
        for out in stacks:
            cur, per = None, {}
            for line in out.splitlines():
                m = re.match(r"TID (\d+):", line)
                if m:
                    cur = m.group(1); per[cur] = []; continue
                m = re.match(r"#\d+\s+0x[0-9a-f]+\s+(\S+)", line)
                if m and cur:
                    per[cur].append(m.group(1))
            for frames in per.values():
                if not frames or any(w in frames[0] for w in waiting):
                    continue
                total_run += 1
                leaf[frames[0][:90]] += 1
                layer[next((g for g in map(group, frames) if g), "other")] += 1
        self.res["profile"] = {"role": role, "samples": len(stacks), "run_thread_samples": total_run,
                               "by_layer": layer.most_common(), "top_leaves": leaf.most_common(18)}
        return res

    def t_tcp(self, extra, secs):
        j = self.iperf(*extra, secs=secs)
        end = j.get("end", {})
        recv = end.get("sum_received", {})
        sent = end.get("sum_sent", {})
        if not recv:
            return {"error": j.get("error", "no result")}
        out = {"mbit_s": round(recv.get("bits_per_second", 0) / 1e6, 1), "retransmits": sent.get("retransmits"),
               "bytes": recv.get("bytes")}
        if not out["bytes"]:
            out["diag"] = self.diagnose()
            # A zero must be explained, not recorded as a result: keep what iperf3 said.
            out["iperf_error"] = j.get("error")
            out["retried"] = j.get("retried")
            out["sent_bytes"] = sent.get("bytes")
            out["intervals"] = len(j.get("intervals", []))
        return out

    def t_udp(self, rate_mbit, length, secs):
        j = self.iperf("-u", "-b", f"{rate_mbit}M", "-l", str(length), secs=secs)
        s = j.get("end", {}).get("sum")
        if not s:
            return {"error": j.get("error", "no result"), "offered_mbit": rate_mbit}
        return {"offered_mbit": rate_mbit, "payload": length, "mbit_s": round(s["bits_per_second"] / 1e6, 1),
                "loss_pct": round(s.get("lost_percent", 0), 3), "jitter_ms": round(s.get("jitter_ms", 0), 3),
                "packets": s.get("packets"), "pps": round(s.get("packets", 0) / max(s.get("seconds", 1), 1e-6))}

    def t_loaded_ping(self, secs):
        bg = subprocess.Popen(["docker", "exec", self.names["c"], "taskset", "-c", GEN_CORE, "iperf3", "-c", self.ip["srv"],
                               "-t", str(secs), "-J"], stdout=subprocess.PIPE, stderr=subprocess.DEVNULL, text=True)
        time.sleep(1.5)
        ping = self.ping_times(int((secs - 3) / 0.2))
        try:
            j = json.loads(bg.communicate(timeout=secs + 30)[0])
            bulk = round(j["end"]["sum_received"]["bits_per_second"] / 1e6, 1)
        except Exception:  # noqa: BLE001
            bulk = None
        ping["bulk_mbit_s"] = bulk
        return ping

    def t_quic(self, secs):
        out = self.gen("python3", "/shared/quic_probe.py", "client", self.ip["srv"], "4433", str(secs), timeout=secs + 90, check=False)
        try:
            return json.loads(out.strip().splitlines()[-1])
        except (json.JSONDecodeError, IndexError):
            return {"error": out[-300:]}

    def t_failover(self, secs, reverse):
        """TCP bulk + a 5 Hz ping through the tunnel; mid-run the relay that carries the traffic is broken.

        fault: pause (the relay process freezes, as a dead host would), cut-e (relay<->E leg blackholed, relay and
        C still talk), cut-c (C<->relay leg blackholed). Outage = longest gap between ping replies around the
        fault (L3 view) and the span of iperf3 intervals below 10% of the pre-fault median (TCP view)."""
        a = self.a
        c = self.names["c"]
        iperf = subprocess.Popen(["docker", "exec", c, "taskset", "-c", GEN_CORE, "iperf3", "-c", self.ip["srv"], "-t", str(secs), "-i", "0.5", "-J",
                                  *(["-R"] if reverse else [])], stdout=subprocess.PIPE, stderr=subprocess.DEVNULL, text=True)
        n_ping = int(secs / 0.2)
        ping = subprocess.Popen(["docker", "exec", c, "taskset", "-c", GEN_CORE, "ping", "-D", "-c", str(n_ping), "-i", "0.2", "-W", "1", self.ip["srv"]],
                                stdout=subprocess.PIPE, stderr=subprocess.DEVNULL, text=True)
        time.sleep(a.fault_at - 2)
        cpu0 = {r: proc_cpu_s(self.vpn[r]) for r in ("a", "b")}
        time.sleep(1.5)
        cpu1 = {r: proc_cpu_s(self.vpn[r]) for r in ("a", "b")}
        busy = {r: round(cpu1[r] - cpu0[r], 3) for r in cpu0}
        victim = max(busy, key=busy.get)
        other = "b" if victim == "a" else "a"
        time.sleep(0.5)
        t_fault = time.time()
        vn = self.names[victim]
        if a.fault == "pause":
            cmd("docker", "pause", vn)
        elif a.fault == "cut-e":
            dex(vn, "iptables", "-A", "OUTPUT", "-d", self.ip["e"], "-j", "DROP")
            dex(vn, "iptables", "-A", "INPUT", "-s", self.ip["e"], "-j", "DROP")
        elif a.fault == "cut-c":
            dex(vn, "iptables", "-A", "OUTPUT", "-d", self.ip["c"], "-j", "DROP")
            dex(vn, "iptables", "-A", "INPUT", "-s", self.ip["c"], "-j", "DROP")
        else:
            raise ValueError(a.fault)
        time.sleep(max(1.0, secs - a.fault_at - 3))
        cpu2 = {r: proc_cpu_s(self.vpn[r]) for r in ("a", "b")}
        time.sleep(1.5)
        cpu3 = {r: proc_cpu_s(self.vpn[r]) for r in ("a", "b")}
        busy_after = {r: round(cpu3[r] - cpu2[r], 3) for r in cpu2}
        pout = ping.communicate(timeout=secs + 40)[0]
        try:
            j = json.loads(iperf.communicate(timeout=secs + 60)[0])
        except Exception:  # noqa: BLE001
            j = {}
        replies = sorted(float(m) for m in re.findall(r"^\[([\d.]+)\].*time=", pout, re.M))
        t_end = time.time()
        gaps = [(replies[i + 1] - replies[i], replies[i]) for i in range(len(replies) - 1)]
        if replies and t_end - replies[-1] > 1.0:
            gaps.append((t_end - replies[-1], replies[-1]))  # outage still running when the load ended
        after = [g for g in gaps if g[1] >= t_fault - 1.0]
        worst = max(after, default=(None, None))
        iv = []
        t0 = j.get("start", {}).get("timestamp", {}).get("timesecs")
        for i in j.get("intervals", []):
            sm = i["sum"]
            iv.append((round(t0 + sm["start"], 2) if t0 else None, round(sm["bits_per_second"] / 1e6, 1)))
        pre = sorted(v for t, v in iv if t is not None and t < t_fault - 0.5 and v > 0)
        base = pre[len(pre) // 2] if pre else None
        low = [t for t, v in iv if base and t is not None and t >= t_fault - 0.5 and v < 0.1 * base]
        total = (j.get("end", {}).get("sum_received") or {}).get("bytes")
        return {"fault": a.fault, "victim": victim, "reverse": reverse, "busy_cpu_before_s": busy, "busy_cpu_after_s": busy_after,
                "switched_relay": busy_after.get(other, 0) > busy_after.get(victim, 0),
                "ping_sent": n_ping, "ping_replies": len(replies), "ping_longest_gap_s": round(worst[0], 2) if worst[0] else None,
                "ping_gap_starts_after_fault_s": round(worst[1] - t_fault, 2) if worst[1] else None,
                "tcp_baseline_mbit_s": base, "tcp_low_intervals": len(low),
                "tcp_outage_s": round(len(low) * 0.5, 1), "tcp_bytes": total,
                "tcp_mbit_s": round((j.get("end", {}).get("sum_received") or {}).get("bits_per_second", 0) / 1e6, 1),
                "tcp_retransmits": (j.get("end", {}).get("sum_sent") or {}).get("retransmits"),
                "tcp_intervals_mbit_s": [v for _, v in iv]}

    def run_tests(self):
        a = self.a
        secs = a.duration
        wanted = a.tests.split(",")
        plan = [
            ("mtu", self.t_mtu, "mtu"),
            ("ping_idle", self.t_ping, "ping"),
            ("tcp_up", (lambda: self.profile_during(a.profile, lambda: self.t_tcp([], secs))) if a.profile else (lambda: self.t_tcp([], secs)), "tcp"),
            ("tcp_down", lambda: self.t_tcp(["-R"], secs), "tcp"),
            ("tcp_up_p4", lambda: self.t_tcp(["-P", "4"], secs), "tcp4"),
            ("udp_1200_100m", lambda: self.t_udp(100, 1200, secs), "udp"),
            ("udp_1200_300m", lambda: self.t_udp(300, 1200, secs), "udp300"),
            ("udp_200_40m", lambda: self.t_udp(40, 200, secs), "udpsmall"),
            ("ping_loaded", lambda: self.t_loaded_ping(max(secs, 8)), "loaded"),
            ("quic", lambda: self.t_quic(min(secs, 6)), "quic"),
            ("failover", lambda: self.t_failover(a.fail_duration, False), "failover"),
            ("failover_R", lambda: self.t_failover(a.fail_duration, True), "failoverR"),
        ]
        for name, fn, group in plan:
            if group in wanted or ("all" in wanted and not group.startswith("failover")):
                print(f"  .. {name}", flush=True)
                self.measured(name, fn)

    def finish_stats(self):
        mem = {}
        for r in ("c", "e"):
            if self.vpn.get(r):
                mem[r] = proc_rss_kb(self.vpn[r])
        self.res["meta"]["vpn_peak_rss_kb"] = mem
        if self.a.stack in ("knothop", "knothop-multi"):
            (self.shared / "fin").touch()
            time.sleep(1.5)
            for r in ("c", "e"):
                p = self.shared / f"result-{r}.json"
                if p.exists():
                    d = json.loads(p.read_text())
                    self.res["meta"][f"knothop_{r}"] = {"tun": d.get("tun"), "events_dropped": d.get("data_events_dropped"),
                                                      "link_mdu": d.get("link_mdu"), "quic_stats": d.get("quic_stats"),
                                                      "pc_drops": d.get("pc_drops"),
                                                      "log_tail": [f"{x['t_ms']} {x['msg']}" for x in (d.get("log") or [])[-40:]]}

    def down(self):
        for n in reversed(self.created):
            cmd("docker", "rm", "-f", n, check=False)
        if self.network:
            cmd("docker", "network", "rm", self.net, check=False)


def main():
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("stack", choices=["knothop", "knothop-hop", "knothop-multi", "awg", "direct"])
    ap.add_argument("tag")
    ap.add_argument("--netem", default="", help="tc netem on the carrier, e.g. 'delay 25ms loss 0.5%%'")
    ap.add_argument("--duration", type=int, default=8)
    ap.add_argument("--knothop-cc", choices=["default", "bbr3", "tunnel"], default="default", help="knothop: outer QUIC congestion control")
    ap.add_argument("--knothop-cc-mbit", type=int, default=1000, help="knothop: rate ceiling of the 'tunnel' controller, Mbit/s")
    ap.add_argument("--tun-txqlen", type=int, default=1000, help="knothop: TUN transmit queue length, packets")
    ap.add_argument("--tun-qdisc", default="", help="knothop: qdisc on the TUN (e.g. fq_codel); AWG gets the same one on awg0")
    ap.add_argument("--knothop-buf-mb", type=int, default=0, help="knothop: QUIC datagram send/receive buffers (MiB) and packet-interface queue sized to match; 0 = defaults")
    ap.add_argument("--rmem-mb", type=int, default=0, help="net.core.rmem_default/max (MiB) on the VPN nodes: UDP receive buffer of the carrier")
    ap.add_argument("--profile", default="", choices=["", "c", "e", "a"], help="sample eu-stack of the VPN process on this node during the tcp_up test")
    ap.add_argument("--hold", type=int, default=0, help="debug: keep the cell alive N seconds after the tests so it can be inspected with docker exec")
    ap.add_argument("--fault", choices=["pause", "cut-e", "cut-c"], default="pause", help="knothop-multi failover test: how the active relay is broken")
    ap.add_argument("--fault-at", type=float, default=25.0, help="failover test: seconds after the start of the load")
    ap.add_argument("--fail-duration", type=int, default=50, help="failover test: length of the load, s")
    ap.add_argument("--fail-ms", type=int, default=1000, help="knothop-multi: client declares the link dead after this much silence following its own sends")
    ap.add_argument("--relink-ms", type=int, default=5000, help="knothop-multi: how long one new-link attempt may take")
    ap.add_argument("--path-idle-ms", type=int, default=3000, help="knothop-multi: QUIC path idle timeout")
    ap.add_argument("--conn-idle-ms", type=int, default=5000, help="knothop-multi: QUIC connection idle timeout (a silent relay is dropped after this)")
    ap.add_argument("--announce-s", type=int, default=60, help="knothop-multi: how often the exit repeats its announce, s (frequent ones hit the relays' announce rate limiter)")
    ap.add_argument("--relay-debug", action="store_true", help="knothop-multi: relays print transport counters every 3 s")
    ap.add_argument("--link-keepalive-s", type=int, default=0, help="knothop-multi: RNS link keepalive override, s (0 = default)")
    ap.add_argument("--tests", default="all", help="comma list of: mtu ping tcp tcp4 udp udp300 udpsmall loaded quic | all")
    a = ap.parse_args()
    if not re.fullmatch(r"[a-zA-Z0-9_-]+", a.tag):
        ap.error("invalid tag")
    OUT.mkdir(parents=True, exist_ok=True)
    out = OUT / f"{a.tag}.json"
    if out.exists():
        raise FileExistsError(out)
    if a.stack == "awg":
        ensure_awg_bins()
    signal.signal(signal.SIGTERM, lambda *_: (_ for _ in ()).throw(KeyboardInterrupt()))
    cell = Cell(a)
    with tempfile.TemporaryDirectory(prefix="knothop-l3-", dir="/tmp/opencode") as sd:
        cell.shared = Path(sd)
        os.chmod(sd, 0o777)
        try:
            cell.up()
            cell.start()
            cell.run_tests()
            if a.hold:
                print("HOLD", json.dumps(cell.names), flush=True)
                time.sleep(a.hold)
            cell.finish_stats()
            cell.res["success"] = True
        except KeyboardInterrupt:
            cell.res["error"] = "interrupted"
        except Exception as e:  # noqa: BLE001
            cell.res["error"] = redact(f"{type(e).__name__}: {e}")
        finally:
            for f in ("e.log", "c.log", "a.log", "b.log", "quic-srv.log"):
                p = cell.shared / f
                if p.exists():
                    (OUT / f"{a.tag}.{f}").write_text(redact(p.read_text()[-5000:]))
            cell.down()
            SECRETS.clear()
    out.write_text(json.dumps(cell.res, indent=1) + "\n")
    t = cell.res["tests"]
    def g(k, *path):
        v = t.get(k, {})
        for p in path:
            v = (v or {}).get(p) if isinstance(v, dict) else None
        return v
    print(a.tag, "OK" if cell.res["success"] else "FAILED", cell.res.get("error", ""),
          "| mtu_ok", g("mtu", "largest_ip_packet_ok"), "| ping p50", g("ping_idle", "p50_ms"),
          "| tcp up/down", g("tcp_up", "mbit_s"), "/", g("tcp_down", "mbit_s"),
          "| udp1200@100 loss", g("udp_1200_100m", "loss_pct"), "| quic", g("quic", "goodput_mbit_s"))


if __name__ == "__main__":
    main()
