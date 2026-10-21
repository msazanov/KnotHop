#!/usr/bin/env python3
"""Нативный прогон rns-iroh-node на хосте (loopback), для профилирования и быстрой итерации тюнинга.

  python3 lev_native.py <tag> [--bin PATH] [--duration S] [--bytes N] [--hw-mtu N] [--chan-buf N] [--read-buf N]
                        [--profile e|c]  [--runs N]

E и C запускаются как обычные процессы, закреплены на разные ядра (taskset), общаются по UDP через 127.0.0.1.
Это быстрее и точнее для профиля, чем контейнеры, но числа НЕ сопоставимы с docker-стендом напрямую
(нет veth/bridge); сравнивать нужно только внутри этой серии. Результаты: bench/results/lev-native/<tag>.json
"""
import argparse, collections, json, os, shutil, statistics as st, subprocess, sys, tempfile, time
from pathlib import Path

HERE = Path(__file__).resolve().parent
OUT = HERE / "results" / "lev-native"
# Бинарь форка по умолчанию лежит на диске: /tmp переполняется каталогами сборки.
DEFAULT_BIN = str(Path.home() / ".cache/rawg-target/bin/rns-iroh-node")


def one_run(a, run_idx):
    work = Path(tempfile.mkdtemp(prefix="rawg-native-", dir="/tmp/opencode"))
    state = work / "state"; state.mkdir()
    procs = []
    try:
        tun = []
        if a.hw_mtu: tun += ["--hw-mtu", str(a.hw_mtu)]
        if a.chan_buf: tun += ["--chan-buf", str(a.chan_buf)]
        if a.read_buf: tun += ["--read-buf", str(a.read_buf)]
        extra = a.extra.split() if a.extra else []
        def start(role, cores, extra_args, prof):
            cmd = ["taskset", "-c", cores, a.bin, "--role", role, "--state", str(state), "--ip", "127.0.0.1", "--relay", "none",
                   "--port", "4433", *tun, *extra, *extra_args]
            if prof:
                cmd = ["taskset", "-c", cores, "samply", "record", "--save-only", "--no-open", "--rate", "2000", "--unstable-presymbolicate",
                       "-o", str(OUT / f"{a.tag}.{role}.profile.json.gz"), "--", *cmd[3:]]
            log = open(state / f"{role}.log", "w")
            p = subprocess.Popen(cmd, stdout=log, stderr=subprocess.STDOUT, cwd=work)
            procs.append(p); return p
        start("e", a.cores_e, [], a.profile == "e")
        for _ in range(100):
            if (state / "e.json").exists(): break
            time.sleep(0.2)
        else:
            raise RuntimeError("E did not start: " + (state / "e.log").read_text()[-500:])
        start("c", a.cores_c, ["--dial", "e", "--duration", str(a.duration), "--bytes", str(a.bytes), "--mode", a.mode, "--chunk", str(a.chunk)], a.profile == "c")
        t0 = time.time()
        while not (state / "ready").exists():
            if time.time() - t0 > 90: raise RuntimeError("client never ready: " + (state / "c.log").read_text()[-500:])
            time.sleep(0.1)
        (state / "go").touch()
        t0 = time.time()
        while not (state / "result-c.json").exists():
            if time.time() - t0 > a.duration + 60: raise RuntimeError("client did not finish: " + (state / "c.log").read_text()[-500:])
            time.sleep(0.2)
        (state / "fin").touch()
        for _ in range(100):
            if (state / "result-e.json").exists(): break
            time.sleep(0.2)
        for p in procs:
            try: p.wait(timeout=30 if a.profile else 10)
            except subprocess.TimeoutExpired: p.terminate()
        c = json.loads((state / "result-c.json").read_text()); e = json.loads((state / "result-e.json").read_text())
        if a.mode == "stream":
            st_ = e["stream"]; dur = max((st_["last_ms"] - st_["first_ms"]) / 1000.0, 1e-6)
            if dur < 1.0:  # пачка проходит за миллисекунды - скорость недостоверна
                return {"mib_s": 0.0, "rate_unreliable": True, "bytes_recv": st_["bytes"], "verified": False}
            return {"mib_s": st_["bytes"] / 1048576 / dur, "bytes_recv": st_["bytes"], "bytes_sent": c["bytes_sent"],
                    "msgs": st_["msgs"], "max_msg": st_["max_msg"], "link_mdu": c.get("link_mdu"),
                    "sends_over_50ms": c["sends_over_50ms"], "send_error": c["send_error"],
                    "verified": st_["mismatch_at"] is None and st_["bytes"] == c["bytes_sent"], "mismatch_at": st_["mismatch_at"]}
        exp = collections.Counter((x["bytes"], x["sha256"]) for x in c["expected"])
        got = collections.Counter((x["bytes"], x["sha256"]) for x in e["resources"])
        verified = bool(exp) and all(got[k] >= v for k, v in exp.items())
        return {"mib_s": c["bytes_ok"] / 1048576 / c["seconds"], "ok": c["resources_ok"], "total": c["resources_total"], "verified": verified}
    finally:
        for p in procs:
            if p.poll() is None: p.kill()
        shutil.rmtree(work, ignore_errors=True)


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("tag")
    ap.add_argument("--bin", default=DEFAULT_BIN)
    ap.add_argument("--duration", type=int, default=15)
    ap.add_argument("--bytes", type=int, default=262144)
    ap.add_argument("--mode", default="resource", choices=["resource", "stream"])
    ap.add_argument("--chunk", type=int, default=400, help="режим stream: байт на LinkHandle::send")
    ap.add_argument("--hw-mtu", type=int, default=0)
    ap.add_argument("--chan-buf", type=int, default=0)
    ap.add_argument("--read-buf", type=int, default=0)
    ap.add_argument("--extra", default="", help="доп. аргументы rns-iroh-node")
    ap.add_argument("--profile", choices=["e", "c"], default="")
    ap.add_argument("--runs", type=int, default=3)
    ap.add_argument("--cores-e", default="2,3")
    ap.add_argument("--cores-c", default="4,5")
    a = ap.parse_args()
    OUT.mkdir(parents=True, exist_ok=True)
    rp = OUT / f"{a.tag}.json"
    if rp.exists(): sys.exit(f"refusing to overwrite {rp}")
    runs = []
    for i in range(a.runs):
        try: runs.append(one_run(a, i))
        except Exception as ex:  # noqa: BLE001
            runs.append({"error": f"{type(ex).__name__}: {ex}"})
    v = [r["mib_s"] for r in runs if "mib_s" in r]
    doc = {"cell": vars(a), "runs": runs, "median_mib_s": st.median(v) if v else None, "all_verified": all(r.get("verified") for r in runs),
           "load": os.getloadavg()}
    rp.write_text(json.dumps(doc, indent=1) + "\n")
    print(f"{a.tag}: median {doc['median_mib_s'] and round(doc['median_mib_s'],2)} MiB/s  runs {[round(x,2) for x in v]}  verified {doc['all_verified']}"
          + (f"  ERR {[r['error'] for r in runs if 'error' in r][:1]}" if len(v) < len(runs) else ""))


if __name__ == "__main__":
    main()
