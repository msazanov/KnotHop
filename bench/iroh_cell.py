#!/usr/bin/env python3
"""Стенд iroh/QUIC: relay + server + client в изолированной docker-сети (без выхода в интернет).

  python3 iroh_cell.py <scenario> <tag> [--mode ...] [--loss PCT] [--mib N] [--secs N]

scenario:
  direct   прямой UDP путь, relay не используется (RelayMode::Disabled)
  relay    прямой путь заблокирован с первой секунды, весь трафик идёт через relay
  switch   relay доступен; прямой путь блокируется на [--block-at, --unblock-at] секунд
           (iptables DROP у клиента для адреса сервера, сервер и relay живы)

Блокировка прямого пути - тихое отбрасывание пакетов, а не отключение интерфейса:
для QUIC это «чёрная дыра», как при пропаже прямой видимости.
Бинарники собираются нативно (cargo) и монтируются в контейнеры archlinux:base (тот же glibc, что у хоста).
"""
import argparse
import json
import os
import subprocess
import sys
import tempfile
import threading
import time
from pathlib import Path

HERE = Path(__file__).resolve().parent
BENCH = Path(os.environ.get("IROH_BENCH_BIN", HERE / "iroh-bench/target/release/iroh-bench"))
RELAY = Path(os.environ.get("IROH_RELAY_BIN", "/tmp/opencode/iroh-src/target/release/iroh-relay"))
IMAGE = "archlinux:base"
IPERF_IMAGE = "knothop-bench:awg31"  # Debian + iperf3 (для базового TCP)
OUT = HERE / "results" / "iroh"


def sh(*argv, check=True, timeout=120, input=None):
    p = subprocess.run(argv, capture_output=True, text=True, timeout=timeout, input=input)
    if check and p.returncode:
        raise RuntimeError(f"{' '.join(argv[:4])} failed: {p.stderr.strip()[:600]}")
    return p.stdout.strip()


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("scenario", choices=["direct", "relay", "switch", "tcp"])
    ap.add_argument("tag")
    ap.add_argument("--mode", default="bulk-up", help="bulk-up|bulk-down|echo|timed-up|timed-down")
    ap.add_argument("--mib", type=int, default=256)
    ap.add_argument("--secs", type=int, default=30)
    ap.add_argument("--echo-n", type=int, default=300)
    ap.add_argument("--loss", type=float, default=0.0, help="потери netem на исходящем трафике клиента (проценты)")
    ap.add_argument("--delay-ms", type=float, default=0.0, help="задержка netem на исходящем трафике клиента, мс")
    ap.add_argument("--block-at", type=int, default=8)
    ap.add_argument("--unblock-at", type=int, default=20)
    ap.add_argument("--cores", type=int, default=2)
    ap.add_argument("--base-core", type=int, default=2)
    ap.add_argument("--verify", action="store_true")
    ap.add_argument("--path-idle-ms", type=int, default=0, help="таймаут простоя пути QUIC (0 = умолчание iroh: 15 с)")
    ap.add_argument("--nc-ms", type=int, default=0, help="вызывать network_change() на клиенте каждые N мс")
    ap.add_argument("--path-keepalive-ms", type=int, default=0, help="keep-alive пути (0 = умолчание iroh: 5 с)")
    a = ap.parse_args()
    OUT.mkdir(parents=True, exist_ok=True)
    result_path = OUT / f"{a.tag}.json"
    if result_path.exists():
        sys.exit(f"refusing to overwrite {result_path}")
    for b in (BENCH, RELAY):
        if not b.exists():
            sys.exit(f"missing binary {b}")

    net = f"knothop-iroh-{a.tag}"
    names = {r: f"{net}-{r}" for r in ("relay", "server", "client")}
    created = []
    res = {"cell": vars(a), "success": False, "events": []}
    t_zero = time.monotonic()

    def ev(msg):
        res["events"].append({"t": round(time.monotonic() - t_zero, 2), "event": msg})

    with tempfile.TemporaryDirectory(prefix="knothop-iroh-", dir="/tmp/opencode") as shared_s:
        shared = Path(shared_s)
        os.chmod(shared, 0o777)
        try:
            sh("docker", "network", "create", "--internal", net)
            for i, role in enumerate(("relay", "server", "client")):
                cores = f"{a.base_core + i * a.cores}-{a.base_core + (i + 1) * a.cores - 1}"
                sh("docker", "run", "-d", "--name", names[role], "--network", net, "--cpuset-cpus", cores,
                   "--cap-add", "NET_ADMIN", "--memory", "2g", "-v", f"{shared}:/shared",
                   "-v", f"{BENCH}:/usr/local/bin/iroh-bench:ro", "-v", f"{RELAY}:/usr/local/bin/iroh-relay:ro",
                   "--entrypoint", "sleep", IPERF_IMAGE if a.scenario == "tcp" else IMAGE, "infinity")
                created.append(names[role])
            ip = {r: sh("docker", "inspect", names[r], "--format",
                        "{{range .NetworkSettings.Networks}}{{.IPAddress}}{{end}}") for r in names}
            res["ips"] = ip
            relay_url = "none"
            if a.scenario == "tcp":
                netem = []
                if a.loss: netem += ["loss", f"{a.loss}%"]
                if a.delay_ms: netem += ["delay", f"{a.delay_ms}ms"]
                if netem:
                    sh("docker", "exec", names["client"], "tc", "qdisc", "add", "dev", "eth0", "root", "netem", *netem)
                sh("docker", "exec", "-d", names["server"], "iperf3", "-s")
                time.sleep(1)
                out = json.loads(sh("docker", "exec", names["client"], "iperf3", "-c", ip["server"], "-t", str(min(a.secs, 15)), "-J",
                                    timeout=a.secs + 60, check=False) or "{}")
                end = out.get("end", {})
                bps = end.get("sum_received", {}).get("bits_per_second", 0)
                res["client"] = {"mib_s": bps / 8 / 1048576, "ok": bps > 0, "retransmits": end.get("sum_sent", {}).get("retransmits"),
                                 "mode": "iperf3-tcp"}
                res["success"] = bps > 0
                raise StopIteration
            if a.scenario != "direct":
                sh("docker", "exec", "-d", names["relay"], "sh", "-c",
                   "exec iroh-relay --dev > /shared/relay.log 2>&1")
                relay_url = f"http://{ip['relay']}:3340"
                for _ in range(100):
                    if sh("docker", "exec", names["client"], "sh", "-c",
                          f"timeout 1 sh -c 'echo > /dev/tcp/{ip['relay']}/3340' && echo up || echo down",
                          check=False) == "up":
                        break
                    time.sleep(0.2)
                else:
                    raise RuntimeError("relay did not start: " + (shared / "relay.log").read_text()[-400:])
            ev(f"relay={relay_url}")
            srv_args = ["--relay", relay_url, "--ip", ip["server"]]
            if a.verify:
                srv_args.append("--verify")
            tune = []
            if a.path_idle_ms: tune += ["--path-idle-ms", str(a.path_idle_ms)]
            if a.path_keepalive_ms: tune += ["--path-keepalive-ms", str(a.path_keepalive_ms)]
            srv_args += tune
            sh("docker", "exec", "-d", names["server"], "sh", "-c",
               "exec iroh-bench server " + " ".join(srv_args) + " > /shared/server.log 2>&1")
            for _ in range(150):
                if (shared / "server.json").exists():
                    break
                time.sleep(0.2)
            else:
                raise RuntimeError("server did not start: " + (shared / "server.log").read_text()[-600:])
            ev("server ready")

            def block(on):
                op = "-A" if on else "-D"
                for chain, flag in (("OUTPUT", "-d"), ("INPUT", "-s")):
                    sh("docker", "exec", names["client"], "iptables", op, chain, flag, ip["server"], "-j", "DROP")
                ev("direct path BLOCKED" if on else "direct path RESTORED")

            if a.scenario == "relay":
                block(True)
            netem = []
            if a.loss:
                netem += ["loss", f"{a.loss}%"]
            if a.delay_ms:
                netem += ["delay", f"{a.delay_ms}ms"]
            if netem:
                sh("docker", "exec", names["client"], "tc", "qdisc", "add", "dev", "eth0", "root", "netem", *netem)
                ev("netem " + " ".join(netem))

            cli = ["iroh-bench", "client", "--relay", relay_url, "--mode", a.mode, "--mib", str(a.mib),
                   "--secs", str(a.secs), "--echo-n", str(a.echo_n), "--tag", "r"]
            if a.scenario == "relay":
                cli.append("--relay-only")
            if a.verify:
                cli.append("--verify")
            cli += tune
            if a.nc_ms: cli += ["--nc-ms", str(a.nc_ms)]

            timers = []
            if a.scenario == "switch":
                timers = [threading.Timer(a.block_at, block, [True]), threading.Timer(a.unblock_at, block, [False])]
            def nic():
                base = "/sys/class/net/eth0/statistics/"
                return {k: int(sh("docker", "exec", names["client"], "cat", base + k)) for k in ("rx_bytes", "tx_bytes", "rx_packets", "tx_packets")}
            nic0 = nic()
            cpu0 = {r: int(sh("docker", "exec", names[r], "sh", "-c", "awk '/^usage_usec/{print $2}' /sys/fs/cgroup/cpu.stat"))
                    for r in names}
            t0 = time.monotonic()
            [t.start() for t in timers]
            ev("client start")
            p = subprocess.run(["docker", "exec", names["client"], *cli], capture_output=True, text=True,
                               timeout=a.secs + 240 if a.mode.startswith("timed") else 600)
            wall = time.monotonic() - t0
            [t.cancel() for t in timers]
            ev("client done")
            nic1 = nic()
            res["client_nic_delta"] = {k: nic1[k] - nic0[k] for k in nic1}
            cpu1 = {r: int(sh("docker", "exec", names[r], "sh", "-c", "awk '/^usage_usec/{print $2}' /sys/fs/cgroup/cpu.stat"))
                    for r in names}
            res["cpu_percent_one_core"] = {r: round((cpu1[r] - cpu0[r]) / 1e4 / wall, 1) for r in names}
            res["wall_s"] = round(wall, 2)
            if p.returncode:
                res["error"] = (p.stderr or p.stdout)[-800:]
            cf = shared / "client-r.json"
            if cf.exists():
                res["client"] = json.loads(cf.read_text())
            sr = shared / "server-report.json"
            if sr.exists():
                res["server_report"] = json.loads(sr.read_text())
            res["success"] = bool(res.get("client", {}).get("ok"))
            for f in ("server.log", "relay.log"):
                if (shared / f).exists():
                    (OUT / f"{a.tag}.{f}").write_text((shared / f).read_text()[-4000:])
        except StopIteration:
            pass
        except Exception as exc:  # noqa: BLE001
            res["error"] = f"{type(exc).__name__}: {exc}"
        finally:
            try:
                result_path.write_text(json.dumps(res, indent=1) + "\n")
            finally:
                for n in created:
                    sh("docker", "rm", "-f", n, check=False)
                sh("docker", "network", "rm", net, check=False)
    c = res.get("client", {})
    print(a.tag, "ok" if res["success"] else "FAILED", "|", {k: c.get(k) for k in ("mib_s", "connect_ms", "rtt_ms") if k in c},
          res.get("error", ""))


if __name__ == "__main__":
    main()
