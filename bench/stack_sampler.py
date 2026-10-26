#!/usr/bin/env python3
"""Сэмплер стеков по реальному времени (wall-clock), включая ожидания.

Запускает пару E/C нативно (как lev_native.py), во время передачи N раз снимает `eu-stack -p <pid>`
у выбранной роли и агрегирует: по потокам (имя, состояние) и по верхним «осмысленным» кадрам.
Требует KNOTHOP_PTRACE_ANY=1 (узел сам разрешает ptrace, см. main.rs) и eu-stack (elfutils).
Бинарь должен быть собран с debuginfo (line-tables-only).

  python3 stack_sampler.py <tag> --role e|c [--samples 60] [--bin ...] [--hw-mtu N] ...
"""
import argparse, collections, json, os, re, subprocess, sys, tempfile, time, shutil
from pathlib import Path
HERE = Path(__file__).resolve().parent
OUT = HERE / "results" / "lev-native"
BIN = str(Path.home() / ".cache/knothop-target/bin/rns-iroh-node-prof")

def thread_state(pid, tid):
    try:
        st = open(f"/proc/{pid}/task/{tid}/stat").read()
        comm = re.search(r"\((.*)\)", st).group(1); rest = st[st.rindex(")") + 2:].split()
        return comm, rest[0], int(rest[11]) + int(rest[12])   # state, utime+stime (ticks)
    except OSError:
        return None, None, 0

def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("tag"); ap.add_argument("--role", choices=["e", "c"], required=True)
    ap.add_argument("--bin", default=BIN); ap.add_argument("--samples", type=int, default=60)
    ap.add_argument("--duration", type=int, default=25); ap.add_argument("--bytes", type=int, default=262144)
    ap.add_argument("--hw-mtu", type=int, default=0); ap.add_argument("--extra", default="")
    ap.add_argument("--client-extra", default="", help="доп. аргументы клиента (например --mode stream --chunk 16000)")
    a = ap.parse_args()
    work = Path(tempfile.mkdtemp(prefix="knothop-stk-", dir="/tmp/opencode")); state = work / "state"; state.mkdir()
    env = dict(os.environ, KNOTHOP_PTRACE_ANY="1")
    tun = (["--hw-mtu", str(a.hw_mtu)] if a.hw_mtu else []) + (a.extra.split() if a.extra else [])
    procs = {}
    try:
        for role, cores, ex in (("e", "2,3", []), ("c", "4,5", ["--dial", "e", "--duration", str(a.duration), "--bytes", str(a.bytes), *(a.client_extra.split() if a.client_extra else [])])):
            cmd = ["taskset", "-c", cores, a.bin, "--role", role, "--state", str(state), "--ip", "127.0.0.1", "--relay", "none", *tun, *ex]
            procs[role] = subprocess.Popen(cmd, stdout=open(state / f"{role}.log", "w"), stderr=subprocess.STDOUT, env=env, cwd=work)
            if role == "e":
                for _ in range(100):
                    if (state / "e.json").exists(): break
                    time.sleep(0.2)
        for _ in range(300):
            if (state / "ready").exists(): break
            time.sleep(0.1)
        (state / "go").touch(); time.sleep(3)
        pid = procs[a.role].pid
        threads0 = {t: thread_state(pid, t) for t in os.listdir(f"/proc/{pid}/task")}
        top_by_thread = collections.defaultdict(collections.Counter); leaf = collections.Counter(); n_ok = 0
        blocked = collections.Counter()
        t_start = time.time()
        for i in range(a.samples):
            r = subprocess.run(["eu-stack", "-p", str(pid), "-n", "14"], capture_output=True, text=True)
            if r.returncode and not r.stdout: continue
            n_ok += 1
            cur = None
            for line in r.stdout.splitlines():
                m = re.match(r"TID (\d+):", line)
                if m:
                    cur = int(m.group(1)); comm, stt, _ = thread_state(pid, cur); cur = (comm or "?"); continue
                m = re.match(r"#\d+\s+0x[0-9a-f]+\s+(.*)", line)
                if m and cur:
                    fn = m.group(1).split(" ")[0] if m.group(1).split(" ")[0] != "" else "?"
                    pass  # (разбор по потокам — во втором проходе ниже)
            # распарсить по потокам: первый кадр = листовая функция
            frames_by_thread = {}; cur = None
            for line in r.stdout.splitlines():
                m = re.match(r"TID (\d+):", line)
                if m: cur = int(m.group(1)); frames_by_thread[cur] = []; continue
                m = re.match(r"#(\d+)\s+0x[0-9a-f]+\s+(.*)", line)
                if m and cur is not None: frames_by_thread[cur].append(m.group(2).strip())
            for tid, fr in frames_by_thread.items():
                comm, stt, _ = thread_state(pid, tid)
                if not fr: continue
                names = [re.sub(r"\s+\S+:\d+.*$", "", f) for f in fr]
                names = [re.sub(r"^\S+\s", "", f) if f.startswith("0x") else f for f in names]
                lf = names[0]
                # ожидание: листья ядра/futex/epoll
                waiting = any(k in lf for k in ("epoll_wait", "futex", "syscall", "pthread_cond", "recvmsg", "__GI_", "poll", "park", "sleep", "nanosleep"))
                key = (comm, "WAIT" if waiting else "RUN")
                blocked[key] += 1
                # первая «наша» функция в стеке
                mine = next((f for f in names if any(k in f for k in ("leviculum", "rns_iroh", "iroh::", "noq", "sha2", "aes", "hmac", "curve", "chacha", "ed25519", "x25519", "cbc"))), names[0])
                top_by_thread[(comm, "WAIT" if waiting else "RUN")][mine[:110]] += 1
            time.sleep(0.05)
        t_end = time.time()
        threads1 = {t: thread_state(pid, t) for t in os.listdir(f"/proc/{pid}/task")}
        cpu = collections.Counter()
        for t, (comm, st, ticks) in threads1.items():
            d = ticks - (threads0.get(t, (None, None, 0))[2]); cpu[comm] += d
        hz = os.sysconf("SC_CLK_TCK")
        (state / "fin").touch()
        doc = {"role": a.role, "samples_ok": n_ok, "wall_s": round(t_end - t_start, 1),
               "thread_cpu_percent_of_one_core": {k: round(100 * v / hz / (t_end - t_start), 1) for k, v in cpu.most_common() if v},
               "thread_states": {f"{k[0]}|{k[1]}": v for k, v in blocked.most_common()},
               "top": {f"{k[0]}|{k[1]}": v.most_common(8) for k, v in top_by_thread.items()}}
        (OUT / f"{a.tag}.json").write_text(json.dumps(doc, indent=1))
        print(json.dumps({k: doc[k] for k in ("role", "samples_ok", "wall_s", "thread_cpu_percent_of_one_core")}, indent=1))
        for k, v in list(doc["thread_states"].items())[:14]: print(f"  {v:4d}  {k}")
        for k, v in doc["top"].items():
            if k.endswith("RUN"):
                print(" ", k)
                for fn, c in v[:5]: print(f"      {c:3d}  {fn}")
    finally:
        for p in procs.values():
            if p.poll() is None: p.kill()
        shutil.rmtree(work, ignore_errors=True)

if __name__ == "__main__": main()
