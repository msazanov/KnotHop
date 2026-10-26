#!/usr/bin/env python3
"""Стандартный Python RNS поверх iroh/QUIC через TCP-мосты (iroh-bench bridge-serve/bridge-dial).

  python3 iroh_rns_cell.py <scenario> <tag> [--duration S] [--bytes N]

scenario:
  plain    контроль: RNS TCPClient -> TCPServer напрямую, без моста и iroh
  direct   RNS -> bridge-dial -> iroh (прямой UDP) -> bridge-serve -> RNS
  switch   то же, relay доступен; прямой путь блокируется на [--block-at, --unblock-at] секунд
  relay    то же, прямой путь заблокирован с начала (только relay)

RNS не изменён: интерфейсы TCPClientInterface/TCPServerInterface на localhost, а между ними
один QUIC-поток (bidi) внутри ОДНОГО QUIC-соединения. Блокировка прямого пути - iptables DROP
у клиента (тихая «чёрная дыра», сервер и relay живы). Результат: пережили ли RNS Link и Resource
смену пути, длина паузы, целостность (SHA-256 каждого Resource).
"""
import argparse, collections, json, os, subprocess, sys, tempfile, threading, time
from pathlib import Path

HERE = Path(__file__).resolve().parent
BENCH = Path(os.environ.get("IROH_BENCH_BIN", "/tmp/opencode/iroh-target-exp/release/iroh-bench"))
RELAY = Path(os.environ.get("IROH_RELAY_BIN", "/tmp/opencode/iroh-src/target/release/iroh-relay"))
IMAGE = "knothop-bench:iroh-rns"
OUT = HERE / "results" / "iroh-rns"


def sh(*argv, check=True, timeout=120):
    p = subprocess.run(argv, capture_output=True, text=True, timeout=timeout)
    if check and p.returncode:
        raise RuntimeError(f"{' '.join(argv[:4])} failed: {p.stderr.strip()[:500]}")
    return p.stdout.strip()


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("scenario", choices=["plain", "direct", "switch", "relay"])
    ap.add_argument("tag")
    ap.add_argument("--duration", type=float, default=30)
    ap.add_argument("--bytes", type=int, default=16 * 1048576, help="размер одного Resource")
    ap.add_argument("--block-at", type=float, default=10)
    ap.add_argument("--unblock-at", type=float, default=30)
    ap.add_argument("--path-idle-ms", type=int, default=0)
    ap.add_argument("--path-keepalive-ms", type=int, default=0)
    ap.add_argument("--nc-ms", type=int, default=0)
    ap.add_argument("--cores", type=int, default=2)
    ap.add_argument("--base-core", type=int, default=2)
    ap.add_argument("--stall-timeout", type=int, default=90, help="сколько ждать завершения одного Resource")
    a = ap.parse_args()
    OUT.mkdir(parents=True, exist_ok=True)
    result_path = OUT / f"{a.tag}.json"
    if result_path.exists():
        sys.exit(f"refusing to overwrite {result_path}")
    for b in (BENCH, RELAY):
        if not b.exists():
            sys.exit(f"missing {b}")
    net = f"knothop-ir-{a.tag}"
    names = {r: f"{net}-{r}" for r in ("relay", "server", "client")}
    created, res = [], {"cell": vars(a), "success": False, "events": []}

    def ev(msg):
        res["events"].append({"unix": round(time.time(), 3), "event": msg})

    with tempfile.TemporaryDirectory(prefix="knothop-ir-", dir="/tmp/opencode") as sd:
        shared = Path(sd); os.chmod(shared, 0o777)
        try:
            sh("docker", "network", "create", "--internal", net)
            for i, role in enumerate(("relay", "server", "client")):
                cores = f"{a.base_core + i * a.cores}-{a.base_core + (i + 1) * a.cores - 1}"
                sh("docker", "run", "-d", "--name", names[role], "--network", net, "--cpuset-cpus", cores,
                   "--cap-add", "NET_ADMIN", "--memory", "3g", "-v", f"{shared}:/shared",
                   "-v", f"{BENCH}:/usr/local/bin/iroh-bench:ro", "-v", f"{RELAY}:/usr/local/bin/iroh-relay:ro",
                   "--entrypoint", "sleep", IMAGE, "infinity")
                created.append(names[role])
            ip = {r: sh("docker", "inspect", names[r], "--format",
                        "{{range .NetworkSettings.Networks}}{{.IPAddress}}{{end}}") for r in names}
            res["ips"] = ip
            tune = []
            if a.path_idle_ms: tune += ["--path-idle-ms", str(a.path_idle_ms)]
            if a.path_keepalive_ms: tune += ["--path-keepalive-ms", str(a.path_keepalive_ms)]
            relay_url = "none"
            ex = lambda role, cmd: sh("docker", "exec", "-d", names[role], "sh", "-c", cmd)
            if a.scenario in ("switch", "relay"):
                ex("relay", "exec iroh-relay --dev > /shared/relay.log 2>&1")
                relay_url = f"http://{ip['relay']}:3340"
                for _ in range(100):
                    if sh("docker", "exec", names["client"], "sh", "-c",
                          f"timeout 1 sh -c 'echo > /dev/tcp/{ip['relay']}/3340' && echo up || echo down", check=False) == "up":
                        break
                    time.sleep(0.2)
                else:
                    raise RuntimeError("relay did not start")
            common = ["--timeout", str(a.stall_timeout), "--dev", "eth0", "--wire-filter", "'udp port 4433 or tcp port 3340'"]
            if a.scenario == "plain":
                ex("server", "exec python3 /usr/local/bin/rnsbench.py server --iface tcp --left-port 4240 "
                   f"--listen-ip 0.0.0.0 --announce-every 2 {' '.join(common)} > /shared/rns-server.log 2>&1")
                target = ip["server"]
            else:
                ex("server", f"exec iroh-bench bridge-serve --relay {relay_url} --ip {ip['server']} --tcp 127.0.0.1:4240 "
                   f"{' '.join(tune)} > /shared/bridge-serve.log 2>&1")
                for _ in range(150):
                    if (shared / "bridge.json").exists(): break
                    time.sleep(0.2)
                else:
                    raise RuntimeError("bridge-serve did not start: " + (shared / "bridge-serve.log").read_text()[-500:])
                ex("server", "exec python3 /usr/local/bin/rnsbench.py server --iface tcp --left-port 4240 "
                   f"--listen-ip 127.0.0.1 --announce-every 2 {' '.join(common)} > /shared/rns-server.log 2>&1")
                def block(on):
                    op = "-A" if on else "-D"
                    for chain, flag in (("OUTPUT", "-d"), ("INPUT", "-s")):
                        sh("docker", "exec", names["client"], "iptables", op, chain, flag, ip["server"], "-j", "DROP")
                    ev("direct path BLOCKED" if on else "direct path RESTORED")
                if a.scenario == "relay":
                    block(True)
                dial = (f"exec iroh-bench bridge-dial --relay {relay_url} --listen 127.0.0.1:4240 {' '.join(tune)} "
                        + (f"--nc-ms {a.nc_ms} " if a.nc_ms else "") + ("--relay-only " if a.scenario == "relay" else "")
                        + "> /shared/bridge-dial.log 2>&1")
                ex("client", dial)
                for _ in range(100):
                    if "listening" in (shared / "bridge-dial.log").read_text() if (shared / "bridge-dial.log").exists() else False: break
                    time.sleep(0.2)
                else:
                    raise RuntimeError("bridge-dial did not start: " + (shared / "bridge-dial.log").read_text()[-500:] if (shared / "bridge-dial.log").exists() else "")
                target = "127.0.0.1"
            ex("client", f"exec python3 /usr/local/bin/rnsbench.py client --iface tcp --right-peer {target} --right-port 4240 "
               f"--bytes {a.bytes} --duration {a.duration} --continue-on-fail --idle 2 --echo-n 50 {' '.join(common)} > /shared/rns-client.log 2>&1")
            t_end = time.time() + 120
            while not (shared / "ready").exists():
                if (shared / "result.json").exists() or time.time() > t_end:
                    raise RuntimeError("client never ready: " + (shared / "rns-client.log").read_text()[-600:])
                time.sleep(0.2)
            ev("rns ready")
            nic = lambda: {k: int(sh("docker", "exec", names["client"], "cat", f"/sys/class/net/eth0/statistics/{k}")) for k in ("rx_bytes", "tx_bytes")}
            cpu = lambda: {r: int(sh("docker", "exec", names[r], "sh", "-c", "awk '/^usage_usec/{print $2}' /sys/fs/cgroup/cpu.stat")) for r in names}
            nic0, cpu0 = nic(), cpu()
            timers = []
            if a.scenario == "switch":
                timers = [threading.Timer(a.block_at, block, [True]), threading.Timer(a.unblock_at, block, [False])]
            t0 = time.time()
            (shared / "go").touch(); ev("go")
            [t.start() for t in timers]
            while not (shared / "done").exists():
                if time.time() - t0 > a.duration + a.stall_timeout + 60:
                    raise RuntimeError("transfer did not finish")
                time.sleep(0.3)
            wall = time.time() - t0
            [t.cancel() for t in timers]
            ev("done")
            nic1, cpu1 = nic(), cpu()
            res["wall_s"] = round(wall, 2)
            res["client_nic_delta"] = {k: nic1[k] - nic0[k] for k in nic1}
            res["cpu_percent_one_core"] = {r: round((cpu1[r] - cpu0[r]) / 1e4 / wall, 1) for r in names}
            (shared / "echo_go").touch()
            for _ in range(600):
                if (shared / "result.json").exists(): break
                time.sleep(0.5)
            (shared / "fin").touch()
            for _ in range(60):
                try:
                    if "resources" in json.loads((shared / "server.json").read_text()): break
                except (OSError, ValueError):
                    pass
                time.sleep(0.5)
            res["client"] = json.loads((shared / "result.json").read_text())
            try:
                srv = json.loads((shared / "server.json").read_text())
                res["server_resources"] = len(srv.get("resources", []))
                tr = res["client"].get("transfer", {})
                exp = collections.Counter((x["bytes"], x["sha256"]) for x in tr.get("expected_resources", []))
                got = collections.Counter((x["bytes"], x["sha256"]) for x in srv.get("resources", []))
                res["payload_verified"] = bool(exp) and all(got[k] >= v for k, v in exp.items())
            except Exception as e:  # noqa: BLE001
                res["payload_verified"] = False; res["verify_error"] = str(e)
            pl = shared / "bridge-path.log"
            if pl.exists():
                res["path_log"] = [(int(l.split()[0]) / 1000.0, l.split()[1]) for l in pl.read_text().splitlines() if l.strip()]
            tl = res["client"].get("transfer", {}).get("timeline", [])
            ends = [x["t_end"] for x in tl if x["ok"]]
            gaps = [(ends[i - 1], ends[i] - ends[i - 1]) for i in range(1, len(ends))]
            res["max_gap_s"] = round(max((g for _, g in gaps), default=0), 2)
            res["gaps_over_2s"] = [(round(t - t0, 1), round(g, 1)) for t, g in gaps if g > 2.0]
            res["link_closed"] = res["client"].get("link_closed")
            res["resources_failed"] = res["client"].get("resources_failed")
            res["recovered_after_failure"] = res["client"].get("recovered_after_failure")
            res["success"] = bool(res["client"].get("transfer", {}).get("ok") and res["payload_verified"] and not res["link_closed"])
            for f in ("rns-server.log", "rns-client.log", "bridge-serve.log", "bridge-dial.log", "relay.log"):
                if (shared / f).exists():
                    (OUT / f"{a.tag}.{f}").write_text((shared / f).read_text()[-5000:])
        except Exception as exc:  # noqa: BLE001
            res["error"] = f"{type(exc).__name__}: {exc}"
            for f in ("rns-server.log", "rns-client.log", "bridge-serve.log", "bridge-dial.log"):
                if (shared / f).exists():
                    (OUT / f"{a.tag}.{f}").write_text((shared / f).read_text()[-5000:])
        finally:
            try:
                result_path.write_text(json.dumps(res, indent=1) + "\n")
            finally:
                for n in created:
                    sh("docker", "rm", "-f", n, check=False)
                sh("docker", "network", "rm", net, check=False)
    tr = res.get("client", {}).get("transfer", {})
    mib = (tr.get("payload_bytes", 0) / 1048576 / tr["seconds"]) if tr.get("seconds") else None
    print(a.tag, "OK" if res["success"] else "FAILED", "| res_failed", res.get("resources_failed"), "| recovered", res.get("recovered_after_failure"), "| MiB/s", None if mib is None else round(mib, 2), "| max_gap_s", res.get("max_gap_s"),
          "| link_closed", res.get("link_closed"), "| verified", res.get("payload_verified"), res.get("error", ""))


if __name__ == "__main__":
    main()
