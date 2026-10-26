#!/usr/bin/env python3
"""Измерительный скрипт для стенда KnotHop (Python RNS).

Роли:
  node    - транспортный узел (пишет конфиг и запускает rnsd в этом процессе);
  server  - конечная точка: destination + приём Resource + echo-запросы;
  client  - конечная точка: path, link, прогрев, простой, передача Resource, echo-RTT.

Топология задаётся аргументами: у узла есть левый линк (в сторону клиента) и правый
(в сторону сервера). Правило ролей интерфейсов:
  tcp      - левый: TCPServerInterface (ждёт), правый: TCPClientInterface (подключается);
  backbone - то же, BackboneInterface / BackboneClientInterface;
  udp      - UDPInterface с обеих сторон, forward на соседа.
Клиент имеет только правый линк, сервер - только левый.
"""
import argparse, hashlib, json, os, random, statistics, sys, time, threading

CFG_DIR = "/root/.reticulum"
SHARED = "/shared"


def log(*a):
    print(time.strftime("%H:%M:%S"), *a, flush=True)


def iface_block(name, kind, **kw):
    lines = ["  [[%s]]" % name, "    type = %s" % kind, "    interface_enabled = True"]
    for k, v in kw.items():
        lines.append("    %s = %s" % (k, v))
    return "\n".join(lines) + "\n"


def write_config(args, transport):
    blocks = []
    mtu = {"fixed_mtu": args.fixed_mtu} if args.fixed_mtu else {}
    if args.bitrate:
        mtu["bitrate"] = args.bitrate
    if args.iface_mode:
        mtu["mode"] = args.iface_mode
    if args.left_peer is not None or args.left_port is not None:
        p = args.left_port
        if args.iface == "tcp":
            blocks.append(iface_block("left", "TCPServerInterface", listen_ip=args.listen_ip, listen_port=p, **mtu))
        elif args.iface == "backbone":
            blocks.append(iface_block("left", "BackboneInterface", listen_on=args.listen_ip, port=p, **mtu))
        elif args.iface == "udp":
            blocks.append(iface_block("left", "UDPInterface", listen_ip="0.0.0.0", listen_port=p,
                                      forward_ip=args.left_peer, forward_port=p, **({"mode": args.iface_mode} if args.iface_mode else {})))
    if args.right_peer is not None:
        p = args.right_port
        if args.iface == "tcp":
            blocks.append(iface_block("right", "TCPClientInterface", target_host=args.right_peer, target_port=p, **mtu))
        elif args.iface == "backbone":
            blocks.append(iface_block("right", "BackboneClientInterface", target_host=args.right_peer, target_port=p, **mtu))
        elif args.iface == "udp":
            blocks.append(iface_block("right", "UDPInterface", listen_ip="0.0.0.0", listen_port=p,
                                      forward_ip=args.right_peer, forward_port=p, **({"mode": args.iface_mode} if args.iface_mode else {})))
    cfg = "[reticulum]\n  enable_transport = %s\n  share_instance = No\n\n[logging]\n  loglevel = %d\n\n[interfaces]\n" % (
        "Yes" if transport else "No", args.loglevel)
    cfg += "".join(blocks)
    os.makedirs(CFG_DIR, exist_ok=True)
    with open(os.path.join(CFG_DIR, "config"), "w") as f:
        f.write(cfg)
    return cfg


def cpu_usec():
    try:
        for line in open("/sys/fs/cgroup/cpu.stat"):
            if line.startswith("usage_usec"):
                return int(line.split()[1])
    except Exception:
        pass
    return None


def veth_counters(dev="eth0"):
    base = "/sys/class/net/%s/statistics/" % dev
    out = {}
    for k in ("rx_bytes", "tx_bytes", "rx_packets", "tx_packets", "rx_dropped", "tx_dropped"):
        try:
            out[k] = int(open(base + k).read())
        except Exception:
            out[k] = None
    return out


def rns_counters(RNS):
    rx = tx = 0
    for i in RNS.Transport.interfaces:
        rx += getattr(i, "rxb", 0) or 0
        tx += getattr(i, "txb", 0) or 0
    return {"rns_rx_bytes": rx, "rns_tx_bytes": tx}


def snap(RNS, dev):
    d = veth_counters(dev)
    d.update(rns_counters(RNS))
    d["t"] = time.time()
    return d


def delta(a, b):
    return {k: (b[k] - a[k]) if (a.get(k) is not None and b.get(k) is not None) else None for k in b}


def parse_pcap(path, t_from, t_to):
    """Сумма длин кадров (L2, без FCS) и число пакетов в pcap за окно [t_from, t_to]."""
    import struct
    n = b = 0
    try:
        data = open(path, "rb").read()
        magic = data[:4]
        end = "<" if magic in (b"\xd4\xc3\xb2\xa1", b"\x4d\x3c\xb2\xa1") else ">"
        nano = magic in (b"\x4d\x3c\xb2\xa1", b"\xa1\xb2\x3c\x4d")
        off = 24
        while off + 16 <= len(data):
            sec, frac, incl, orig = struct.unpack(end + "IIII", data[off:off + 16])
            ts = sec + frac / (1e9 if nano else 1e6)
            if t_from <= ts <= t_to:
                n += 1; b += orig
            off += 16 + incl
    except Exception as e:
        return {"rns_port_wire_error": str(e)}
    return {"rns_port_wire_bytes": b, "rns_port_wire_packets": n}


def wait_file(path, timeout):
    t0 = time.time()
    while not os.path.exists(path):
        if time.time() - t0 > timeout:
            raise TimeoutError(path)
        time.sleep(0.05)


def touch(name):
    open(os.path.join(SHARED, name), "w").close()


# ---------------------------------------------------------------- node
def run_node(args):
    cfg = write_config(args, transport=True)
    log("node config:\n" + cfg)
    if os.environ.get("NODE_IMPL", "rnsd") == "lnsd":
        os.execvp("lnsd", ["lnsd", "--config", CFG_DIR])
    os.execvp("rnsd", ["rnsd", "--config", CFG_DIR])


# ---------------------------------------------------------------- server
def run_server(args):
    import RNS
    write_config(args, transport=False)
    r = RNS.Reticulum(CFG_DIR, loglevel=args.loglevel)
    ident = RNS.Identity()
    dest = RNS.Destination(ident, RNS.Destination.IN, RNS.Destination.SINGLE, "knothopbench", "node")
    state = {"link": None, "rx_bytes": 0, "resources": [], "t0": None, "t1": None, "cpu0": None, "cpu1": None}

    def echo(path, data, request_id, link_id, remote_identity, requested_at):
        return data

    dest.register_request_handler("/echo", response_generator=echo, allow=RNS.Destination.ALLOW_ALL)

    def res_started(resource):
        state["t0"] = time.time()
        state["cpu0"] = cpu_usec()

    def res_concluded(resource):
        state["t1"] = time.time()
        state["cpu1"] = cpu_usec()
        if resource.status == RNS.Resource.COMPLETE:
            data = resource.data.read() if hasattr(resource.data, "read") else b""
            state["rx_bytes"] += len(data)
            state["resources"].append({"bytes": len(data), "sha256": hashlib.sha256(data).hexdigest()})
            log("server: resource complete, %d bytes" % len(data))
        else:
            log("server: resource status", resource.status)

    def link_established(link):
        state["link"] = link
        link.set_resource_strategy(RNS.Link.ACCEPT_ALL)
        link.set_resource_started_callback(res_started)
        link.set_resource_concluded_callback(res_concluded)
        log("server: link established, mtu=%s" % getattr(link, "mtu", None))

    dest.set_link_established_callback(link_established)
    with open(os.path.join(SHARED, "server.hash"), "w") as f:
        f.write(RNS.hexrep(dest.hash, delimit=False))
    log("server: destination", RNS.prettyhexrep(dest.hash))
    dest.announce()
    last = time.time()
    while not os.path.exists(os.path.join(SHARED, "fin")):
        time.sleep(0.5)
        if time.time() - last > args.announce_every and state["link"] is None:
            dest.announce(); last = time.time()
    log("server: fin")
    with open(os.path.join(SHARED, ".server.json.tmp"), "w") as f:
        json.dump({k: v for k, v in state.items() if k != "link"}, f)
    os.replace(os.path.join(SHARED, ".server.json.tmp"), os.path.join(SHARED, "server.json"))
    sys.exit(0)


# ---------------------------------------------------------------- client
def pct(vals, p):
    if not vals:
        return None
    s = sorted(vals)
    k = max(0, min(len(s) - 1, int(round(p / 100.0 * (len(s) - 1)))))
    return s[k]


def run_client(args):
    import RNS
    res = {"args": {k: v for k, v in vars(args).items() if k != "func"}}
    write_config(args, transport=False)
    r = RNS.Reticulum(CFG_DIR, loglevel=args.loglevel)
    wait_file(os.path.join(SHARED, "server.hash"), 60)
    dest_hash = bytes.fromhex(open(os.path.join(SHARED, "server.hash")).read().strip())

    t_start = time.time()
    # Серверу нужно время анонсироваться; ждём path.
    if not RNS.Transport.has_path(dest_hash):
        RNS.Transport.request_path(dest_hash)
    t0 = time.time()
    while not RNS.Transport.has_path(dest_hash):
        if time.time() - t0 > args.timeout:
            res["error"] = "no path"; return finish(res)
        time.sleep(0.05)
    res["t_path_s"] = time.time() - t_start
    res["hops"] = RNS.Transport.hops_to(dest_hash)
    ident = RNS.Identity.recall(dest_hash)
    dest = RNS.Destination(ident, RNS.Destination.OUT, RNS.Destination.SINGLE, "knothopbench", "node")

    ev = threading.Event()
    link_box = {}
    t1 = time.time()
    link = RNS.Link(dest, established_callback=lambda l: ev.set(), closed_callback=lambda l: link_box.setdefault("closed", True))
    if not ev.wait(args.timeout):
        res["error"] = "link timeout"; return finish(res)
    res["t_link_s"] = time.time() - t1
    res["link_mtu"] = getattr(link, "mtu", None)
    res["link_mdu"] = getattr(link, "mdu", None)
    res["link_rtt_s"] = link.rtt
    res["interfaces"] = [{"class": type(i).__name__, "hw_mtu": getattr(i, "HW_MTU", None),
                          "bitrate": getattr(i, "bitrate", None)} for i in RNS.Transport.interfaces]
    log("client: link up hops=%s mtu=%s mdu=%s rtt=%.4f" % (res["hops"], res["link_mtu"], res["link_mdu"], link.rtt or -1))

    # Прогрев: небольшая передача, чтобы пути/окна были инициализированы.
    def transfer(nbytes, timeout, on_link=None):
        on_link = on_link or link
        done = threading.Event(); out = {}
        data = os.urandom(nbytes)
        out["sha256"] = hashlib.sha256(data).hexdigest()

        def concluded(resource):
            out["status"] = resource.status; out["t"] = time.time(); done.set()
        t = time.time()
        RNS.Resource(data, on_link, auto_compress=False, callback=concluded)
        ok = done.wait(timeout)
        return ok, out, t

    # Дополнительные независимые link для --parallel (каждый со своим Resource одновременно).
    extra_links = []
    for _ in range(max(0, args.parallel - 1)):
        e2 = threading.Event()
        l2 = RNS.Link(dest, established_callback=lambda l, e=e2: e.set())
        if not e2.wait(args.timeout):
            res["error"] = "extra link timeout"; return finish(res)
        extra_links.append(l2)
    all_links = [link] + extra_links

    ok, out, t = transfer(args.warmup_bytes, args.timeout)
    if not ok or out.get("status") != RNS.Resource.COMPLETE:
        res["error"] = "warmup failed"; return finish(res)

    # Простой: служебный трафик без полезной нагрузки.
    # Простой: на проводе считаем только трафик портов стенда (фильтр BPF), т.к. veth-счётчики
    # включают шум хоста (mDNS 5353, SSDP 1900, IPv6 MLD/ND) и не годятся для служебного overhead.
    import subprocess
    pcap_path = os.path.join(SHARED, "idle.pcap")
    cap = subprocess.Popen(["tcpdump", "-Z", "root", "-U", "-i", args.dev, "-n", "-w", pcap_path,
                            args.wire_filter],
                           stdout=subprocess.DEVNULL, stderr=open(os.path.join(SHARED, "tcpdump.err"), "w"))
    time.sleep(1)
    s0 = snap(RNS, args.dev)
    time.sleep(args.idle)
    s1 = snap(RNS, args.dev)
    cap.terminate(); cap.wait()
    res["idle"] = delta(s0, s1)
    res["idle"]["seconds"] = s1["t"] - s0["t"]
    res["idle"].update(parse_pcap(pcap_path, s0["t"], s1["t"]))

    # Синхронизация с оркестратором: снимок CPU всех контейнеров.
    touch("ready")
    wait_file(os.path.join(SHARED, "go"), 120)

    transfer_cap = None
    if args.capture_transfer:
        transfer_cap = subprocess.Popen(
            ["tcpdump", "-Z", "root", "-U", "-s", "96", "-i", args.dev, "-n", "-w",
             os.path.join(SHARED, "transfer.pcap"), args.wire_filter],
            stdout=subprocess.DEVNULL, stderr=open(os.path.join(SHARED, "transfer-tcpdump.err"), "w"))
        time.sleep(1)
    c0 = cpu_usec(); s0 = snap(RNS, args.dev)
    timeline = []
    exp_dur = []
    if args.duration > 0:
        # Непрерывные передачи по ОДНОМУ Link заданное время: нужна для проверки, что Link
        # и передача переживают смену нижележащего пути. Метки времени - unix, для сопоставления с событиями стенда.
        t = time.time(); stop_at = t + args.duration; ok = True; nbytes = 0; last_sha = ""
        consecutive = 0
        while time.time() < stop_at:
            ok1, out1, t1 = transfer(args.bytes, args.timeout)
            good = bool(ok1 and out1.get("status") == RNS.Resource.COMPLETE)
            timeline.append({"t_start": t1, "t_end": out1.get("t", time.time()), "ok": good, "bytes": args.bytes,
                             "link_status": getattr(link, "status", None)})
            if link_box.get("closed"):
                ok = False
                break
            if not good:
                ok = False
                consecutive += 1
                if not args.continue_on_fail or consecutive >= 10:
                    break
                time.sleep(1.0)
                continue
            consecutive = 0
            exp_dur.append({"bytes": args.bytes, "sha256": out1["sha256"]}); nbytes += args.bytes; last_sha = out1["sha256"]
        out = {"status": RNS.Resource.COMPLETE if ok else RNS.Resource.FAILED, "sha256": last_sha}
        t_end = time.time(); args.bytes = nbytes
    elif len(all_links) == 1:
        ok, out, t = transfer(args.bytes, args.timeout)
        t_end = out.get("t", time.time())
    else:
        per = args.bytes // len(all_links)
        results = [None] * len(all_links)

        def worker(i):
            results[i] = transfer(per, args.timeout, all_links[i])
        t = time.time()
        th = [threading.Thread(target=worker, args=(i,)) for i in range(len(all_links))]
        [x.start() for x in th]; [x.join() for x in th]
        ok = all(r[0] and r[1].get("status") == RNS.Resource.COMPLETE for r in results)
        out = {"status": RNS.Resource.COMPLETE if ok else RNS.Resource.FAILED}
        t_end = max(r[1].get("t", time.time()) for r in results)
        args.bytes = per * len(all_links)
    s1 = snap(RNS, args.dev); c1 = cpu_usec()
    res["transfer"] = {"ok": bool(ok and out.get("status") == RNS.Resource.COMPLETE),
                       "payload_bytes": args.bytes, "parallel_links": len(all_links),
                       "seconds": (t_end - t),
                       "expected_resources": [{"bytes": args.bytes, "sha256": out["sha256"]}] if len(all_links) == 1 else
                                             [{"bytes": per, "sha256": r[1]["sha256"]} for r in results],
                       "counters": delta(s0, s1),
                       "client_cpu_usec": (c1 - c0) if (c0 is not None and c1 is not None) else None}
    if timeline:
        res["transfer"]["timeline"] = timeline
        res["transfer"]["expected_resources"] = exp_dur
        res["link_closed"] = bool(link_box.get("closed", False))
        fails = [i for i, x in enumerate(timeline) if not x["ok"]]
        res["resources_failed"] = len(fails)
        res["recovered_after_failure"] = bool(fails) and any(x["ok"] for x in timeline[fails[0]:])
        res["link_status_end"] = getattr(link, "status", None)
    if transfer_cap:
        transfer_cap.terminate(); transfer_cap.wait()
        res["transfer"]["filtered_wire"] = parse_pcap(os.path.join(SHARED, "transfer.pcap"), s0["t"], s1["t"])
        with open(os.path.join(SHARED, "transfer-tcpdump.err")) as f:
            res["transfer"]["capture_stats"] = f.read()
    touch("done")
    wait_file(os.path.join(SHARED, "echo_go"), 120)   # оркестратор снял CPU, можно мерить задержку
    if not res["transfer"]["ok"]:
        res["error"] = "transfer failed or timed out"
        res["echo"] = {"n": 0, "lost": 0, "skipped": True}
        return finish(res)

    # Задержка: последовательные echo-запросы (RTT приложения).
    rtts = []
    lost = 0
    for i in range(args.echo_n):
        e = threading.Event(); box = {}

        def ok_cb(receipt): box["t"] = time.time(); e.set()
        def fail_cb(receipt): e.set()
        t = time.time()
        link.request("/echo", data=os.urandom(args.echo_size), response_callback=ok_cb, failed_callback=fail_cb, timeout=10)
        if e.wait(12) and "t" in box:
            rtts.append((box["t"] - t) * 1000.0)
        else:
            lost += 1
    res["echo"] = {"n": args.echo_n, "lost": lost, "size": args.echo_size,
                   "p50_ms": pct(rtts, 50), "p95_ms": pct(rtts, 95), "min_ms": min(rtts) if rtts else None,
                   "max_ms": max(rtts) if rtts else None, "mean_ms": statistics.mean(rtts) if rtts else None}
    try:
        link.teardown()
    except Exception:
        pass
    return finish(res)


def finish(res):
    path = os.path.join(SHARED, "result.json")
    with open(path + ".tmp", "w") as f:
        json.dump(res, f, indent=1)
    os.replace(path + ".tmp", path)
    if not os.path.exists(os.path.join(SHARED, "done")):
        touch("done")
    log("client: result written", json.dumps(res)[:400])
    try:
        wait_file(os.path.join(SHARED, "fin"), 120)   # контейнер живёт до снятия метрик
    except TimeoutError:
        pass
    sys.exit(0)


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("role", choices=["node", "server", "client"])
    ap.add_argument("--iface", choices=["tcp", "udp", "backbone"], default="tcp")
    ap.add_argument("--left-peer"); ap.add_argument("--left-port", type=int)
    ap.add_argument("--right-peer"); ap.add_argument("--right-port", type=int)
    ap.add_argument("--fixed-mtu", type=int, default=0)
    ap.add_argument("--bitrate", type=int, default=0, help="объявленная скорость интерфейса, влияет на согласование MTU")
    ap.add_argument("--listen-ip", default="0.0.0.0", help="явная привязка listener к адресу туннеля")
    ap.add_argument("--iface-mode", default="", help="mode интерфейса RNS: full|gateway|access_point|roaming|boundary")
    ap.add_argument("--bytes", type=int, default=4 * 1024 * 1024)
    ap.add_argument("--parallel", type=int, default=1, help="число одновременных link/Resource")
    ap.add_argument("--continue-on-fail", action="store_true", help="в режиме --duration продолжать на том же Link после неудачного Resource (до 10 подряд)")
    ap.add_argument("--duration", type=float, default=0, help="непрерывные передачи по одному Link N секунд (--bytes на передачу)")
    ap.add_argument("--warmup-bytes", type=int, default=256 * 1024)
    ap.add_argument("--idle", type=float, default=30)
    ap.add_argument("--echo-n", type=int, default=200)
    ap.add_argument("--echo-size", type=int, default=32)
    ap.add_argument("--timeout", type=float, default=180)
    ap.add_argument("--announce-every", type=float, default=5)
    ap.add_argument("--dev", default="eth0")
    ap.add_argument("--wire-filter", default="(tcp or udp) and portrange 4240-4249")
    ap.add_argument("--capture-transfer", action="store_true", help="pcap по фильтру в окне передачи (влияет на CPU)")
    ap.add_argument("--loglevel", type=int, default=3)
    args = ap.parse_args()
    {"node": run_node, "server": run_server, "client": run_client}[args.role](args)


if __name__ == "__main__":
    main()
