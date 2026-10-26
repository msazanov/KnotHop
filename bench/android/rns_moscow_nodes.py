#!/usr/bin/env python3
"""Список публичных TCP-узлов RNS из каталога rns.moscow -> файл для `knothopd node --public-rns-file` (по строке host:порт).

  rns_moscow_nodes.py [--url https://rns.moscow/nodelist/nodes.json] [--out FILE] [--only-ok]

Берутся все записи с протоколом TCP (I2P и Yggdrasil пропускаются: нужны отдельные интерфейсы). По умолчанию - вся пачка, как просил владелец;
--only-ok оставляет только узлы, у которых каталог видит ответ по RNS (rns_ok). Каталог обновляется раз в 10 минут; адреса в код не зашиваются.
"""
import argparse
import json
import sys
import urllib.request

ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
ap.add_argument("--url", default="https://rns.moscow/nodelist/nodes.json")
ap.add_argument("--out", default="-")
ap.add_argument("--only-ok", action="store_true")
a = ap.parse_args()
d = json.load(urllib.request.urlopen(a.url, timeout=20))
lines = [f"# источник {a.url}, обновлено {d.get('updated')}, регион {d.get('region')}"]
n = 0
for x in d["nodes"]:
    if "TCP" not in x.get("protocols", []) or not x.get("port"):
        continue
    if a.only_ok and not x.get("rns_ok"):
        continue
    host = x["host"]
    host = f"[{host}]" if ":" in host else host
    lines.append(f"{host}:{x['port']}  # {x.get('display_name')} status={x.get('status')} rns_ok={x.get('rns_ok')}")
    n += 1
out = "\n".join(lines) + "\n"
(sys.stdout.write(out) if a.out == "-" else open(a.out, "w").write(out))
print(f"узлов TCP: {n}", file=sys.stderr)
