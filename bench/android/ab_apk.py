#!/usr/bin/env python3
"""A/B разных APK на телефоне (вперемешку): ab_apk.py --apks base=/path/a.apk mi=/path/b.apk --rounds 3 [--args "--workers 2"] [--dir both]
Каждый раунд: установить APK (тот же ключ, разрешение VPN сохраняется), подключиться, прогреть, снять CPU/ГиБ и скорость."""
import argparse, json, statistics as st, subprocess, sys, time
sys.path.insert(0, __file__.rsplit("/", 1)[0])
import phone_ab as p

ap = argparse.ArgumentParser()
ap.add_argument("--apks", nargs="+", required=True)
ap.add_argument("--rounds", type=int, default=3)
ap.add_argument("--mb", type=int, default=120)
ap.add_argument("--dir", default="both", choices=["down", "up", "both"])
ap.add_argument("--args", default="")
ap.add_argument("--out", default="")
a = ap.parse_args()
apks = [x.split("=", 1) for x in a.apks]
dirs = ["down", "up"] if a.dir == "both" else [a.dir]
res = []
for r in range(a.rounds):
    for name, path in apks:
        subprocess.run(["adb", "install", "-r", path], capture_output=True)
        subprocess.run(["adb", "shell", "pm", "grant", p.PKG, "android.permission.POST_NOTIFICATIONS"], capture_output=True)
        if not p.start(a.args):
            print(name, "не поднялся", flush=True); continue
        time.sleep(3); pid = p.app_pid()
        p.sh(f"curl -s -m 20 -o /dev/null http://{p.HOST}/down?mb=8")
        for d in dirs:
            m = p.run_load(d, a.mb, pid); m.update(cfg=name, round=r); res.append(m)
            print(json.dumps(m, ensure_ascii=False), flush=True)
print("\nмедианы:")
for d in dirs:
    for name, _ in apks:
        v = [x for x in res if x["cfg"] == name and x["dir"] == d and x["cpu_s_per_gib"]]
        v = [x for x in v if x.get("gcyc_per_gib")]
        if v:
            print(f"{d:5s} {name:10s} n={len(v)}  {st.median(x['mbit_s'] for x in v):7.1f} Мбит/с  {st.median(x['gcyc_per_gib'] for x in v):6.1f} Гцикл/ГиБ (ядро {st.median(x['gcyc_k_per_gib'] for x in v):.1f}, польз. {st.median(x['gcyc_u_per_gib'] for x in v):.1f}; разброс {min(x['gcyc_per_gib'] for x in v):.0f}-{max(x['gcyc_per_gib'] for x in v):.0f})  cpu {st.median(x['cpu_s_per_gib'] for x in v):.0f} с/ГиБ")
if a.out: open(a.out, "w").write(json.dumps(res, indent=1, ensure_ascii=False))
