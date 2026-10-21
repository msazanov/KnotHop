#!/usr/bin/env python3
"""leviculum + iroh с нативным адаптером (rns-iroh-node): роли e (выход), a (RNS-транспорт), c (клиент).

  python3 lev_cell.py <scenario> <tag> [--duration S] [--bytes N] [--path-idle-ms N] [--path-keepalive-ms N] [--controller]

scenario:
  direct   C -> E по прямому UDP, без блокировок (скорость и overhead)
  switch   C -> E, relay доступен; прямой путь C<->E блокируется на [--block-at, --unblock-at] с.
           RNS видит один интерфейс, QUIC переключается direct->relay внутри себя.
  hop      relay НЕТ. C звонит и на E, и на A; A звонит на E (RNS-транспорт). Прямой путь C<->E
           блокируется (iptables DROP). QUIC C-E умирает, RNS-интерфейс исчезает, остаётся путь C->A->E.
           Это проверка СМЕНЫ RNS-УЗЛА: что происходит с Link и сколько занимает восстановление.
"""
import argparse, collections, json, os, re, subprocess, sys, tempfile, threading, time
from pathlib import Path

from measure import process_memory, rtt_summary

HERE = Path(__file__).resolve().parent
# По умолчанию - бинарь форка на диске: /tmp на этой машине переполняется каталогами сборки.
BIN = Path(os.environ.get("RNS_IROH_BIN", str(Path.home() / ".cache/rawg-target/bin/rns-iroh-node")))
RELAY = Path(os.environ.get("IROH_RELAY_BIN", "/tmp/opencode/iroh-src/target/release/iroh-relay"))
# Per-role override, for live cross-build interoperability checks (e.g. client on one AEAD backend, exit on the other):
# RNS_IROH_BIN_E / RNS_IROH_BIN_C / RNS_IROH_BIN_A. Unset -> the role uses RNS_IROH_BIN.
ROLE_BIN = {r: Path(os.environ[f"RNS_IROH_BIN_{r.upper()}"]) for r in ("e", "c", "a") if os.environ.get(f"RNS_IROH_BIN_{r.upper()}")}
IMAGE = "archlinux:base"
OUT = HERE / "results" / "lev-iroh"


def sh(*argv, check=True, timeout=120):
    p = subprocess.run(argv, capture_output=True, text=True, timeout=timeout)
    if check and p.returncode:
        raise RuntimeError(f"{' '.join(argv[:4])} failed: {p.stderr.strip()[:500]}")
    return p.stdout.strip()


def sample_stacks(name, stop, out, interval=0.25):
    """Снимает eu-stack у rns-iroh-node в контейнере `name` в его PID namespace.

    Инструмент берётся с хоста (в образе его нет), поэтому заходим внутрь через nsenter.
    Процесс должен быть запущен с RAWG_PTRACE_ANY=1 - тогда ptrace_scope его не закроет.
    Копятся только RUN-кадры: WAIT-строки показывают, кто ждёт, а не кто тратит CPU.
    """
    per_thread = collections.Counter(); leaf = collections.Counter(); states = collections.Counter()
    while not stop.is_set():
        # PID нужен в терминах ХОСТА: `docker exec` показывает нумерацию внутри контейнера.
        pid = sh("docker", "top", name, "-eo", "pid,comm", check=False, timeout=30)
        pid = next((l.split()[0] for l in pid.splitlines()
                    if len(l.split()) == 2 and l.split()[1] == "rns-iroh-node"), "")
        if not pid:
            time.sleep(interval); continue
        r = subprocess.run(["nsenter", "-t", pid, "-m", "-p", "eu-stack", "-p", pid, "-n", "24"],
                           capture_output=True, text=True)
        cur = None
        for line in r.stdout.splitlines():
            m = re.match(r"TID \d+: (.*)", line)
            if m:
                cur = m.group(1); states[cur] += 1; continue
            m = re.match(r"#\d+\s+0x[0-9a-f]+\s+(\S+)", line)
            if m and cur:
                per_thread[cur] += 1
                leaf[m.group(1)] += 1
        time.sleep(interval)
    out["threads"] = per_thread.most_common(); out["leaf_frames"] = leaf.most_common(25)
    out["states"] = states.most_common()


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("scenario", choices=["direct", "switch", "hop", "rns-hop"])
    ap.add_argument("tag")
    ap.add_argument("--duration", type=int, default=30)
    ap.add_argument("--bytes", type=int, default=262144)
    ap.add_argument("--block-at", type=float, default=10)
    ap.add_argument("--unblock-at", type=float, default=40)
    ap.add_argument("--path-idle-ms", type=int, default=0)
    ap.add_argument("--path-keepalive-ms", type=int, default=0)
    ap.add_argument("--conn-idle-ms", type=int, default=0, help="таймаут простоя QUIC-соединения (0 = умолчание iroh)")
    ap.add_argument("--link-keepalive-s", type=int, default=0, help="keepalive RNS Link, с (0 = умолчание leviculum)")
    ap.add_argument("--mode", default="resource", choices=["resource", "stream", "dgram"], help="нагрузка: Resource, LinkHandle::send (Channel) или dgram (пакеты по Link без Channel, как IP-туннель)")
    ap.add_argument("--chunk", type=int, default=400, help="stream: байт на один LinkHandle::send")
    ap.add_argument("--stream-bytes", type=int, default=0, help="stream: сколько байт отправить всего (0 = крутить до --duration)")
    ap.add_argument("--verify-sha", action="store_true", help="stream: сверить SHA-256 потока (нагружает CPU, для скорости выключено)")
    ap.add_argument("--echo", action="store_true", help="stream: RTT малого echo по отдельному Link под нагрузкой")
    ap.add_argument("--cipher", choices=["cbc", "gcm"], default="cbc", help="явный крипторежим Link")
    ap.add_argument("--cipher-e", choices=["cbc", "gcm"], default=None, help="крипторежим выхода отдельно для негативного контроля")
    ap.add_argument("--send-window", type=int, default=0, help="лимит in-flight записей клиента; 0 = 128")
    ap.add_argument("--netem", default="", help="tc netem на egress eth0 каждого узла перед стартом передачи, например "
                    "'delay 25ms loss 0.5%%'. RTT ≈ 2×delay, потери применяются в каждом направлении. Простой-RTT и "
                    "установление Link идут ДО включения, поэтому echo_idle показывает чистую сеть")
    ap.add_argument("--quic-initial-mtu", type=int, default=0, help="QUIC: начальный MTU пути (0 = 1200)")
    ap.add_argument("--quic-stream-window", type=int, default=0, help="QUIC: окно приёма на поток, байт (0 = умолчание 1,25 МБ)")
    ap.add_argument("--quic-conn-window", type=int, default=0, help="QUIC: окно приёма на соединение, байт")
    ap.add_argument("--quic-dg-send-buf", type=int, default=0, help="QUIC: буфер отправки датаграмм, байт")
    ap.add_argument("--quic-dg-recv-buf", type=int, default=0, help="QUIC: буфер приёма датаграмм, байт")
    ap.add_argument("--carrier", choices=["stream", "datagram"], default="stream", help="носитель RNS-интерфейса: поток QUIC (HDLC) или датаграммы QUIC")
    ap.add_argument("--dgram-mtu", type=int, default=1400, help="HW_MTU пакетного интерфейса при --carrier datagram")
    ap.add_argument("--data-cap", type=int, default=0, help="ёмкость очереди событий данных приложения (0 = умолчание)")
    ap.add_argument("--pps", type=int, default=0, help="dgram: целевое число пакетов/с (0 = как можно быстрее)")
    ap.add_argument("--window-only", action="store_true", help="оставить pacing QUIC, сохранив окно и ARQ RNS")
    ap.add_argument("--proof-binding-e", default=None, choices=["tag", "hash"],
                    help="привязка proof отдельно для выхода: негативный контроль, когда стороны не совпадают")
    ap.add_argument("--proof-binding", default=None, choices=["tag", "hash"],
                    help="чем привязан proof данных: tag (быстро) или hash (совместимость с ванильным Reticulum). "
                         "Не указывать, чтобы не передавать флаг вовсе - так собирается против сборки без этой опции")
    ap.add_argument("--sample", default="", choices=["", "c", "e", "a"], help="снимать eu-stack у этой роли во время передачи")
    ap.add_argument("--sample-interval", type=float, default=0.25)
    ap.add_argument("--hw-mtu", type=int, default=0, help="stream: HW_MTU byte channel (0 = умолчание leviculum 1064)")
    ap.add_argument("--chan-buf", type=int, default=0, help="stream: ёмкость channel (0 = умолчание 64)")
    ap.add_argument("--read-buf", type=int, default=0, help="stream: размер буфера чтения (0 = умолчание 1024)")
    ap.add_argument("--controller", action="store_true")
    ap.add_argument("--cores", type=int, default=1, help="logical CPU на роль; стандарт стенда — 1 на каждый узел")
    ap.add_argument("--server-cores", type=int, default=None, help="CPU на роль e/a/iroh-relay, отдельно от клиента")
    ap.add_argument("--client-cores", type=int, default=None, help="CPU клиента; прочие роли задаются --server-cores")
    ap.add_argument("--base-core", type=int, default=2)
    a = ap.parse_args()
    OUT.mkdir(parents=True, exist_ok=True)
    result_path = OUT / f"{a.tag}.json"
    if result_path.exists():
        sys.exit(f"refusing to overwrite {result_path}")
    for b in (BIN, RELAY):
        if not b.exists():
            sys.exit(f"missing {b}")
    roles = ["relay", "e", "c"] + (["a"] if a.scenario in ("hop", "rns-hop") else [])
    counts = {r: (a.client_cores if a.client_cores is not None else a.cores) if r == "c"
              else (a.server_cores if a.server_cores is not None else a.cores) for r in roles}
    if any(n < 1 for n in counts.values()):
        ap.error("CPU count must be positive")
    next_core = a.base_core
    cpusets = {}
    for role in roles:
        selected = list(range(next_core, next_core + counts[role]))
        if not set(selected).issubset(os.sched_getaffinity(0)):
            ap.error(f"unavailable CPU set for {role}: {selected}")
        cpusets[role] = str(selected[0]) if len(selected) == 1 else f"{selected[0]}-{selected[-1]}"
        next_core += counts[role]
    net = f"rawg-lev-{a.tag}"
    names = {r: f"{net}-{r}" for r in roles}
    created, res = [], {"cell": vars(a), "success": False, "events": [], "cpusets": cpusets}
    ev = lambda m: res["events"].append({"unix": round(time.time(), 3), "event": m})
    with tempfile.TemporaryDirectory(prefix="rawg-lev-", dir="/tmp/opencode") as sd:
        shared = Path(sd); os.chmod(shared, 0o777)
        try:
            sh("docker", "network", "create", "--internal", net)
            for role in roles:
                sh("docker", "run", "-d", "--name", names[role], "--network", net, "--cpuset-cpus", cpusets[role],
                   "--cap-add", "NET_ADMIN", "--memory", "3g", "-v", f"{shared}:/shared",
                   "-v", f"{ROLE_BIN.get(role, BIN)}:/usr/local/bin/rns-iroh-node:ro", "-v", f"{RELAY}:/usr/local/bin/iroh-relay:ro",
                   "--entrypoint", "sleep", IMAGE, "infinity")
                created.append(names[role])
            ip = {r: sh("docker", "inspect", names[r], "--format", "{{range .NetworkSettings.Networks}}{{.IPAddress}}{{end}}") for r in roles}
            res["ips"] = ip
            res["effective_cpusets"] = {r: sh("docker", "exec", names[r], "cat", "/sys/fs/cgroup/cpuset.cpus.effective") for r in roles}
            if res["effective_cpusets"] != cpusets:
                raise RuntimeError("effective cpusets differ from requested affinity")
            ex = lambda role, cmd: sh("docker", "exec", "-d", names[role], "sh", "-c", cmd)
            relay_url = "none"
            if a.scenario in ("direct", "switch"):
                relay_url = "none" if a.scenario == "direct" else f"http://{ip['relay']}:3340"
            if a.scenario == "switch":
                ex("relay", "exec iroh-relay --dev > /shared/relay.log 2>&1")
                for _ in range(100):
                    if sh("docker", "exec", names["e"], "sh", "-c", f"timeout 1 sh -c 'echo > /dev/tcp/{ip['relay']}/3340' && echo up || echo down", check=False) == "up":
                        break
                    time.sleep(0.2)
                else:
                    raise RuntimeError("relay did not start")
            tune = ""
            if a.path_idle_ms: tune += f" --path-idle-ms {a.path_idle_ms}"
            if a.path_keepalive_ms: tune += f" --path-keepalive-ms {a.path_keepalive_ms}"
            if a.conn_idle_ms: tune += f" --conn-idle-ms {a.conn_idle_ms}"
            if a.link_keepalive_s: tune += f" --link-keepalive-s {a.link_keepalive_s}"
            if a.hw_mtu: tune += f" --hw-mtu {a.hw_mtu}"
            if a.chan_buf: tune += f" --chan-buf {a.chan_buf}"
            if a.read_buf: tune += f" --read-buf {a.read_buf}"
            if a.data_cap: tune += f" --data-cap {a.data_cap}"
            tune += f" --carrier {a.carrier} --dgram-mtu {a.dgram_mtu}"
            for flag, val in (("--quic-initial-mtu", a.quic_initial_mtu), ("--quic-stream-window", a.quic_stream_window),
                              ("--quic-conn-window", a.quic_conn_window), ("--quic-dg-send-buf", a.quic_dg_send_buf),
                              ("--quic-dg-recv-buf", a.quic_dg_recv_buf)):
                if val:
                    tune += f" {flag} {val}"
            # хеш потока считают обе стороны, поэтому флаг общий, а не только клиентский
            if a.verify_sha: tune += " --verify-sha"
            if a.proof_binding:
                tune += f" --proof-binding {a.proof_binding}"
            tune += f" --cipher {a.cipher}"
            # RAWG_PTRACE_ANY нужен, чтобы eu-stack с хоста видел процесс в контейнере
            tune_e = tune
            if a.cipher_e:
                parts = tune_e.split()
                i = parts.index("--cipher")
                parts[i+1] = a.cipher_e
                tune_e = " " + " ".join(parts)
            if a.proof_binding_e:
                # общий tune уже может нести --proof-binding, а clap такой флаг дважды не принимает
                parts = tune_e.split()
                if "--proof-binding" in parts:
                    i = parts.index("--proof-binding")
                    del parts[i : i + 2]
                # ведущий пробел обязателен: строка подставляется сразу после --relay
                tune_e = " " + " ".join(parts) + f" --proof-binding {a.proof_binding_e}"
            base = lambda role, extra: (f"export RAWG_PTRACE_ANY=1; exec rns-iroh-node --role {role} --ip {ip[role]} "
                                        f"--relay {relay_url}{tune if role != 'e' else tune_e} {extra} > /shared/{role}.log 2>&1")
            ex("e", base("e", ""))
            for _ in range(150):
                if (shared / "e.json").exists(): break
                time.sleep(0.2)
            else:
                raise RuntimeError("E did not start: " + (shared / "e.log").read_text()[-600:])
            if a.scenario in ("hop", "rns-hop"):
                ex("a", base("a", "--dial e"))
                for _ in range(150):
                    if (shared / "a.json").exists(): break
                    time.sleep(0.2)
            dial = "a" if a.scenario == "rns-hop" else ("a,e" if a.scenario == "hop" else "e")
            if a.mode == "dgram":
                load = f"--mode dgram --chunk {a.chunk} --pps {a.pps}"
            elif a.mode == "stream":
                load = f"--mode {a.mode} --chunk {a.chunk} --stream-bytes {a.stream_bytes}"
            else:
                load = f"--bytes {a.bytes}"
            if a.echo:
                load += " --echo"
            if a.send_window:
                load += f" --send-window {a.send_window}"
            if a.window_only:
                load += " --window-only"
            ex("c", base("c", f"--dial {dial} --duration {a.duration} {load}" + (" --controller" if a.controller else "")))

            t_end = time.time() + 150
            while not (shared / "ready").exists():
                alive = "rns-iroh-node" in sh("docker", "top", names["c"], "-eo", "pid,args", check=False)
                if not alive or (shared / "result-c.json").exists() or time.time() > t_end:
                    raise RuntimeError("client never ready: " + (shared / "c.log").read_text()[-800:])
                time.sleep(0.2)
            ev("client ready")
            def block(on):
                op = "-A" if on else "-D"
                for chain, flag in (("OUTPUT", "-d"), ("INPUT", "-s")):
                    sh("docker", "exec", names["c"], "iptables", op, chain, flag, ip["e"], "-j", "DROP")
                ev("direct C<->E BLOCKED" if on else "direct C<->E RESTORED")
            timers = []
            if a.scenario in ("switch", "hop"):
                timers = [threading.Timer(a.block_at, block, [True]), threading.Timer(a.unblock_at, block, [False])]
            nic = lambda: {k: int(sh("docker", "exec", names["c"], "cat", f"/sys/class/net/eth0/statistics/{k}")) for k in ("rx_bytes", "tx_bytes")}
            cpu = lambda: {r: int(sh("docker", "exec", names[r], "sh", "-c", "awk '/^usage_usec/{print $2}' /sys/fs/cgroup/cpu.stat")) for r in roles}
            if a.netem:
                # Только данные: рукопожатие и зондирование простоя уже прошли по чистой сети.
                for role in roles:
                    if role != "relay":
                        sh("docker", "exec", names[role], "tc", "qdisc", "replace", "dev", "eth0", "root", "netem", *a.netem.split())
                res["netem"] = a.netem
                ev("netem on: " + a.netem)
            nic0, cpu0 = nic(), cpu()
            t0 = time.time()
            (shared / "go").touch(); ev("go")
            [t.start() for t in timers]
            while not (shared / "result-c.json").exists():
                alive = "rns-iroh-node" in sh("docker", "top", names["c"], "-eo", "pid,args", check=False)
                if not alive or time.time() - t0 > a.duration + 200:
                    raise RuntimeError("client did not finish: " + (shared / "c.log").read_text()[-800:])
                time.sleep(0.5)
            wall = time.time() - t0
            [t.cancel() for t in timers]
            stop_s = threading.Event()
            samp = {}
            th = None
            if a.sample:
                th = threading.Thread(target=sample_stacks, args=(names[a.sample], stop_s, samp, a.sample_interval), daemon=True)
                th.start()
            nic1, cpu1 = nic(), cpu()
            res["wall_s"] = round(wall, 1)
            if th is not None:
                stop_s.set(); th.join(timeout=60)
                res["stack_sample"] = samp
            res["client_nic_delta"] = {k: nic1[k] - nic0[k] for k in nic1}
            res["cpu_percent_one_core"] = {r: round((cpu1[r] - cpu0[r]) / 1e4 / wall, 1) for r in roles}
            res["cpu_seconds"] = {r: (cpu1[r] - cpu0[r]) / 1e6 for r in roles}
            # Память: что ещё живо — из /proc; клиент уже вышел и допишет себя сам (ниже).
            res["memory"] = {r: {"processes": process_memory(lambda *argv, r=r: sh("docker", "exec", names[r], *argv, check=False))}
                             for r in roles}
            (shared / "fin").touch()
            for _ in range(60):
                if (shared / "result-e.json").exists(): break
                time.sleep(0.3)
            res["client"] = json.loads((shared / "result-c.json").read_text())
            srv = json.loads((shared / "result-e.json").read_text())
            if not any(p["name"] == "rns-iroh-node" for p in res["memory"]["c"]["processes"]):
                res["memory"]["c"]["processes"].append({"pid": 0, "name": "rns-iroh-node(self-reported)",
                                                        "hwm_kb": res["client"].get("vm_hwm_kb", 0),
                                                        "rss_kb": res["client"].get("vm_rss_kb", 0)})
            for r in roles:
                res["memory"][r]["peak_kb"] = sum(p["hwm_kb"] for p in res["memory"][r]["processes"])
            if a.mode == "dgram":
                # Пакетный тракт: потери, перестановки, задержка и джиттер вместо скорости потока.
                d, c = srv["dgram"], res["client"]
                dur = max((d["last_us"] - d["first_us"]) / 1e6, 1e-6)
                sent = c["sent"]
                res["dgram"] = {
                    "packet": c["packet"], "pps_target": c["pps_target"], "sent": sent, "received": d["received"],
                    "send_errors": c["send_errors"], "loss_pct": round(100.0 * (sent - d["received"]) / max(sent, 1), 3),
                    "reordered": d["reordered"], "corrupt": d["corrupt"], "seconds": round(dur, 2),
                    "send_pps": round(sent / max(c["seconds"], 1e-6)), "recv_pps": round(d["received"] / dur),
                    "recv_mbit_s": round(d["bytes"] * 8 / dur / 1e6, 1),
                    "delay_ms": {"min": d["delay_min_us"] / 1000, "p50": d["delay_p50_us"] / 1000,
                                 "p95": d["delay_p95_us"] / 1000, "p99": d["delay_p99_us"] / 1000},
                    "jitter_ms": round(d["jitter_us"] / 1000, 3), "link_mdu": c.get("link_mdu"),
                    "rx_events_dropped": srv.get("data_events_dropped"),
                }
                res["rate_unreliable"] = dur < 1.0
                res["cpu_percent_window"] = {r: t / dur * 100 for r, t in res["cpu_seconds"].items()}
                res["verified"] = d["corrupt"] == 0 and d["received"] > 0
                if d["received"]:
                    res["cpu_us_per_packet"] = {r: round(t * 1e6 / d["received"], 2) for r, t in res["cpu_seconds"].items() if r != "relay"}
                res["e_received"] = d["received"]
            elif a.mode == "stream":
                # VPN-путь: сколько байт дошло на E, совпал ли поток и с какой скоростью шёл.
                st, c = srv["stream"], res["client"]
                dur = max((st["last_ms"] - st["first_ms"]) / 1000.0, 1e-6)
                # Узкое окно измерения даёт бессмысленную скорость: пачка из
                # нескольких пакетов проходит за миллисекунды. Помечаем, а не врём.
                res["rate_unreliable"] = dur < 1.0
                res["stream"] = {
                    "bytes_recv": st["bytes"], "bytes_sent": c["bytes_sent"], "mismatch_at": st["mismatch_at"],
                    "msgs": st["msgs"], "max_msg": st["max_msg"], "link_mdu": c.get("link_mdu"),
                    "seconds": round(dur, 2),
                    "mib_s": None if dur < 1.0 else round(st["bytes"] / 1048576 / dur, 2),
                    "msgs_per_s": round(st["msgs"] / dur),
                    "sends_over_50ms": c["sends_over_50ms"], "send_error": c["send_error"],
                    # сквозная сверка: хеш принятого на E потока против хеша отправленного на C
                    "sha256_e": st.get("sha256"), "sha256_c": c.get("sha256"),
                    # sha сравнивается только если его считали (--verify-sha)
                    "sha_match": None if not st.get("sha256") else st.get("sha256") == c.get("sha256"),
                    "marks": c.get("marks"),
                }
                nd = res.get("client_nic_delta") or {}
                if nd.get("tx_bytes") and st["bytes"]:
                    res["overhead_eth0"] = round(nd["tx_bytes"] / st["bytes"], 3)
                res["verified"] = (st["mismatch_at"] is None and st["bytes"] == c["bytes_sent"]
                                   and res["stream"]["sha_match"] is not False
                                   and (not a.verify_sha or res["stream"]["sha_match"] is True))
                res["e_received"] = st["msgs"]
                if st["bytes"]:
                    res["cpu_seconds_per_gib"] = {r: t * 1073741824 / st["bytes"] for r, t in res["cpu_seconds"].items()}
                if c.get("echo_rtt_ms"):
                    res["echo"] = rtt_summary(c["echo_rtt_ms"], c.get("echo_timeouts", 0))
                if c.get("echo_idle_rtt_ms"):
                    res["echo_idle"] = rtt_summary(c["echo_idle_rtt_ms"])
                # Процент ОДНОГО ядра по окну передачи — то же определение, что в protocol_compare.py.
                res["cpu_percent_window"] = {r: t / dur * 100 for r, t in res["cpu_seconds"].items()}
            else:
                exp = collections.Counter((x["bytes"], x["sha256"]) for x in res["client"]["expected"])
                got = collections.Counter((x["bytes"], x["sha256"]) for x in srv["resources"])
                res["verified"] = bool(exp) and all(got[k] >= v for k, v in exp.items())
                res["e_received"] = len(srv["resources"])
            res["e_log"] = srv["log"]
            c = res["client"]
            if a.mode == "dgram":
                completed = c["sent"] > 0 and c["send_errors"] == 0
            elif a.mode == "stream":
                completed = (c["bytes_sent"] > 0 and c["send_error"] is None
                             and (not a.stream_bytes or c["bytes_sent"] == a.stream_bytes))
            else:
                completed = c["resources_ok"] > 0
            res["success"] = bool(res["verified"] and completed)
            if a.mode == "resource":
                # разрывы между Resource — только для этого режима; в stream их нет
                tl = c["timeline"]
                ends = [x["t_end_ms"] / 1000 for x in tl if x["ok"]]
                gaps = [(ends[i - 1], ends[i] - ends[i - 1]) for i in range(1, len(ends))]
                res["max_gap_s"] = round(max((g for _, g in gaps), default=0), 2)
                res["gaps_over_2s"] = [(round(t - t0, 1), round(g, 1)) for t, g in gaps if g > 2.0]
        except Exception as exc:  # noqa: BLE001
            res["error"] = f"{type(exc).__name__}: {exc}"
        finally:
            for f in ("c.log", "e.log", "a.log", "relay.log"):
                if (shared / f).exists():
                    (OUT / f"{a.tag}.{f}").write_text((shared / f).read_text()[-6000:])
            try:
                result_path.write_text(json.dumps(res, indent=1) + "\n")
            finally:
                for n in created:
                    sh("docker", "rm", "-f", n, check=False)
                sh("docker", "network", "rm", net, check=False)
    c = res.get("client", {})
    if a.mode == "dgram":
        d = res.get("dgram") or {}
        print(a.tag, "OK" if res["success"] else "FAILED", "| pkt", d.get("packet"), "| send/recv pps", d.get("send_pps"), "/", d.get("recv_pps"),
              "| Mbit/s", d.get("recv_mbit_s"), "| loss%", d.get("loss_pct"), "| reord", d.get("reordered"),
              "| delay p50/p99 ms", (d.get("delay_ms") or {}).get("p50"), (d.get("delay_ms") or {}).get("p99"),
              "| jitter ms", d.get("jitter_ms"), "| rx_drop", d.get("rx_events_dropped"), "| cpu%", res.get("cpu_percent_window"), "| us/pkt", res.get("cpu_us_per_packet"),
              res.get("error", ""))
    elif a.mode == "stream":
        st = res.get("stream") or {}
        print(a.tag, "OK" if res["success"] else "FAILED", "| MiB/s", st.get("mib_s"), "| msgs/s", st.get("msgs_per_s"),
              "| chunk", a.chunk, "| link_mdu", st.get("link_mdu"), "| cpu", res.get("cpu_percent_one_core"),
              "| stalls>50ms", st.get("sends_over_50ms"), "| sha", st.get("sha_match"),
              "| overhead", res.get("overhead_eth0"), "| verified", res.get("verified"), res.get("error", ""))
    else:
        mib = (c.get("bytes_ok", 0) / 1048576 / c["seconds"]) if c.get("seconds") else None
        print(a.tag, "OK" if res["success"] else "FAILED", "| MiB/s", None if mib is None else round(mib, 2),
              "| ok/total", c.get("resources_ok"), "/", c.get("resources_total"), "| max_gap_s", res.get("max_gap_s"),
              "| relinks", [(r["kind"], r["recovered_after_ms"]) for r in c.get("relinks", [])], "| verified", res.get("verified"), res.get("error", ""))


if __name__ == "__main__":
    main()
