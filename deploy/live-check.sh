#!/usr/bin/env bash
# Сквозная проверка одной командой (телефоны по adb, узлы по ssh как rollout.sh).
#   deploy/live-check.sh [--phones-only | --nodes-only] [--nodes LABEL,...]
# stdout: ровно одна JSON-строка на телефон и на узел; пояснения — только в stderr.
# Телефон: ok=false при нет tun, неразобранном ping, отсутствии/сбое netprobe или ошибке adb; сырой вывод не публикуется.
# netprobe: /data/local/tmp/{knothop-netprobe,rawg-netprobe,netprobe}; отсутствие — явный не-pass, не «пропущено удачно».
# up 10 МБ — короткий тест передачи, не ёмкость (capacity=false): буфер может завысить mbit_s.
# Узел: ok=false при ошибке ssh, отсутствующем/битом status.json или пустых счётчиках; нули и false счётчиков сохраняются.
# В JSON нет адресов, сырого stderr и текста удалённых ошибок: только метки и безопасные коды.
# Код выхода: 0 — все выбранные телефоны и узлы ok; 1 — есть не-ok или пропущенный телефон; 2 — ошибка аргументов.
# VPN включается deploy/phones.sh vpn-on; при tun=0 измерения не делаются (ok=false, no-tun).
# SSH: BatchMode=yes, StrictHostKeyChecking=yes; опции из 4-й колонки hosts.tsv не могут отключить проверку ключа.
set -euo pipefail

HERE="$(cd "$(dirname "$0")" && pwd)"
HOSTS="${HOSTS_FILE:-$HERE/hosts.tsv}"
NETPROBE_DIR=/data/local/tmp
PING_TARGET=1.1.1.1
SSHB=(-o BatchMode=yes -o StrictHostKeyChecking=yes -o ConnectTimeout=15 -o ServerAliveInterval=10)

DO_PHONES=1
DO_NODES=1
WANT_NODES=""
FAIL=0
SKIPPED=0
DEVICES=()

die() { echo "live-check: $*" >&2; exit 1; }
note() { echo "live-check: $*" >&2; }

usage() { sed -n '2,12p' "$0" | sed 's/^# \{0,1\}//'; }

while [ $# -gt 0 ]; do
  case "$1" in
    --phones-only) DO_NODES=0 ;;
    --nodes-only) DO_PHONES=0 ;;
    --nodes)
      [ $# -ge 2 ] || { usage >&2; exit 2; }
      WANT_NODES=$2; shift ;;
    --nodes=*) WANT_NODES=${1#--nodes=} ;;
    -h|--help) usage; exit 0 ;;
    *) usage >&2; exit 2 ;;
  esac
  shift
done
[ "$DO_PHONES" = 1 ] || [ "$DO_NODES" = 1 ] || {
  note "--phones-only и --nodes-only вместе не дают ничего проверять"
  usage >&2
  exit 2
}

# Телефоны в state=device (DEVICES) и число пропущенных (SKIPPED). Работает в текущем shell, stdin не читает.
refresh_devices() {
  DEVICES=()
  SKIPPED=0
  local out line serial state
  out=$(adb devices 2>&1) || { note "adb devices завершился ошибкой"; FAIL=1; return; }
  while IFS= read -r line; do
    line=${line%$'\r'}
    [ -n "$line" ] || continue
    case "$line" in
      "List of devices attached"*|"adb server"*|"*"*) continue ;;
    esac
    read -r serial state _ <<<"$line"
    [ -n "${serial:-}" ] || continue
    if [ "${state:-}" = device ]; then
      DEVICES+=("$serial")
    else
      note "пропущен $serial (state=${state:-?}): телефон не проверен"
      SKIPPED=$((SKIPPED + 1))
    fi
  done <<<"$out"
}

# Разбор в одну JSON-строку: ping (числа), netprobe (свой JSON), явные problems. Сырой вывод не печатается.
PY_PHONE='
import json, sys

serial, tun_s, ping_rc_s, ping_out, np_name, down_rc_s, down_out, up_rc_s, up_out = sys.argv[1:10]
NP_NAMES = ["knothop-netprobe", "rawg-netprobe", "netprobe"]
DOWN_BYTES, UP_BYTES = 50000000, 10000000

def as_int(v, d):
    try:
        return int(v)
    except Exception:
        return d

def parse_ping(t):
    import re
    m = re.search(r"(\d+) packets transmitted, (\d+) (?:packets )?received, ([\d.]+)% packet loss", t)
    if not m:
        return None
    p = {"sent": int(m.group(1)), "recv": int(m.group(2)), "loss_pct": float(m.group(3))}
    r = re.search(r"= ([\d.]+)/([\d.]+)/([\d.]+)(?:/([\d.]+))? ms", t)
    if r:
        p.update({"rtt_min": float(r.group(1)), "rtt_avg": float(r.group(2)), "rtt_max": float(r.group(3))})
        if r.group(4):
            p["rtt_mdev"] = float(r.group(4))
    return p

def np_result(raw, rc, field, need):
    if rc != 0:
        return {"status": "failed", "exit": rc}
    lines = [l for l in raw.splitlines() if l.strip()]
    if not lines:
        return {"status": "failed", "error": "no-output"}
    try:
        j = json.loads(lines[-1])
    except Exception:
        return {"status": "failed", "error": "bad-json"}
    if not isinstance(j, dict):
        return {"status": "failed", "error": "bad-json"}
    if j.get("status") != 200:
        return {"status": "failed", "error": "http-status"}
    if j.get(field) != need:
        return {"status": "failed", "error": "incomplete"}
    sel = {"status": "ok"}
    for k in ("seconds", "connect_seconds", "body_seconds", "send_seconds", "mbit_s", "tcp_rtt_us", "tcp_total_retrans"):
        v = j.get(k)
        if isinstance(v, (int, float)) and not isinstance(v, bool):
            sel[k] = v
    return sel

tun = as_int(tun_s, -1)
out = {"phone": serial, "ok": True, "problems": [], "tun": None}

def bad(code):
    out["ok"] = False
    out["problems"].append(code)

if tun < 0:
    bad("adb-error")
elif tun == 0:
    out["tun"] = False
    bad("no-tun")
else:
    out["tun"] = True
    p = parse_ping(ping_out) if as_int(ping_rc_s, 1) == 0 else None
    if p is None:
        out["ping"] = {"status": "failed"}
        bad("ping-failed")
    elif p.get("recv", 0) == 0:
        out["ping"] = dict(p, status="failed")
        bad("ping-failed")   # rc 0 при 100% потерь (некоторые toybox-сборки) — не успех
    else:
        out["ping"] = dict(status="ok", **p)

np = {"status": "skipped"}
if tun > 0:
    if np_name not in NP_NAMES:
        np = {"status": "missing", "looked_for": NP_NAMES}
        bad("netprobe-missing")
    else:
        np = {"status": "found", "name": np_name}
out["netprobe"] = np

skipped = {"status": "skipped"}
if tun <= 0 or np.get("status") != "found":
    out["download_50MB"] = dict(skipped)
    out["upload_10MB"] = dict(skipped)
else:
    d = np_result(down_out, as_int(down_rc_s, 1), "body_received", DOWN_BYTES)
    out["download_50MB"] = d
    if d["status"] != "ok":
        bad("download-failed")
    u = np_result(up_out, as_int(up_rc_s, 1), "bytes_sent", UP_BYTES)
    if u["status"] == "ok":
        u.update({"kind": "short-transfer-test", "capacity": False,
                  "note": "10 МБ — короткий тест передачи, не ёмкость: буфер может завысить mbit_s"})
    else:
        bad("upload-failed")
    out["upload_10MB"] = u

print(json.dumps(out, ensure_ascii=False))
sys.exit(0)
'

# Скрипт для узла идёт через stdin. Печатает ровно одну строку с префиксом; всё остальное не публикуется.
PY_NODE='
import json, sys

PREFIX = "KNOTHOP_STATUS "

def pack(v):
    if not isinstance(v, dict):
        return None
    out = {}
    for k, x in v.items():
        if not isinstance(k, str):
            continue
        if isinstance(x, bool) or isinstance(x, (int, float)):
            out[k] = x
    return out or None

try:
    with open("/opt/knothop/state/status.json") as f:
        st = json.load(f)
except FileNotFoundError:
    print(PREFIX + json.dumps({"ok": False, "error": "status-json-missing"}))
    sys.exit(0)
except Exception:
    print(PREFIX + json.dumps({"ok": False, "error": "status-json-invalid"}))
    sys.exit(0)

if isinstance(st, dict) and (st.get("state") == "error" or st.get("error")):
    print(PREFIX + json.dumps({"ok": False, "error": "status-error"}))
    sys.exit(0)

t = st.get("tun") if isinstance(st, dict) else None
dp = pack(t.get("dataplane")) if isinstance(t, dict) else None
mesh = pack(t.get("mesh")) if isinstance(t, dict) else None
if dp is None and mesh is None:
    print(PREFIX + json.dumps({"ok": False, "error": "stats-missing"}))
else:
    print(PREFIX + json.dumps({"ok": True, "dataplane": dp, "mesh": mesh}, sort_keys=True))
'

# Разбор ответа узла: только строка с префиксом, только безопасные коды; адреса/сырой stderr не публикуются.
PY_NODE_OUT='
import json, sys

PREFIX = "KNOTHOP_STATUS "
ERRORS = {"status-json-missing", "status-json-invalid", "status-error", "stats-missing"}

def clean(v):
    if not isinstance(v, dict):
        return None
    out = {}
    for k, x in v.items():
        if not isinstance(k, str):
            continue
        if isinstance(x, bool) or isinstance(x, (int, float)):
            out[k] = x
    return out or None

label, rc_s, raw = sys.argv[1], int(sys.argv[2]), sys.argv[3]
res = {"node": label, "ok": False}
lines = [l for l in raw.splitlines() if l.startswith(PREFIX)]
if rc_s != 0:
    res["error"] = "ssh-failed"
    res["rc"] = rc_s
elif not lines:
    res["error"] = "no-json"
else:
    try:
        j = json.loads(lines[-1][len(PREFIX):])
    except Exception:
        j = None
    if not isinstance(j, dict):
        res["error"] = "bad-json"
    elif j.get("ok") is True:
        dp, mesh = clean(j.get("dataplane")), clean(j.get("mesh"))
        if dp is None and mesh is None:
            res["error"] = "stats-missing"
        else:
            res["ok"] = True
            res["dataplane"] = dp
            res["mesh"] = mesh
    else:
        e = j.get("error")
        res["error"] = e if isinstance(e, str) and e in ERRORS else "node-error"
print(json.dumps(res, ensure_ascii=False, sort_keys=True))
sys.exit(0)
'

# Код 0 — в JSON "ok": true; 1 — "ok": false; 2 — строку не разобрать (внутренняя ошибка).
json_ok() {
  python3 -I -c '
import json, sys
try:
    d = json.load(sys.stdin)
except Exception:
    sys.exit(2)
sys.exit(0 if isinstance(d, dict) and d.get("ok") is True else 1)
'
}

# adb shell с закрытым stdin: не должен съедать stdin скрипта.
ad() { adb -s "$1" shell "$2" </dev/null; }

# Первый доступный netprobe из согласованных имён; пусто — бинарника нет.
probe_netprobe() {
  local out
  out=$(ad "$1" 'for p in knothop-netprobe rawg-netprobe netprobe; do [ -x /data/local/tmp/$p ] && { echo $p; break; }; done' 2>/dev/null | tr -d '\r') || true
  out=${out%%$'\n'*}
  case "$out" in
    knothop-netprobe|rawg-netprobe|netprobe) printf '%s' "$out" ;;
  esac
}

# Запуск netprobe: NP_RC — код, NP_OUT — только stdout (stderr не публикуется).
NP_RC=0
NP_OUT=""
np_run() { # СЕРИЙНЫЙ ИМЯ ТАЙМАУТ АРГ...
  local s=$1 name=$2 tmo=$3
  shift 3
  NP_RC=0
  NP_OUT=$(timeout "$tmo" adb -s "$s" shell "$NETPROBE_DIR/$name" "$@" </dev/null 2>/dev/null) || NP_RC=$?
}

phone_check() {
  local s=$1 tun=-1 link ping_rc=0 ping_out="" np="" down_rc=1 down_out="" up_rc=1 up_out="" json
  if link=$(timeout 30 adb -s "$s" shell 'ip -o link 2>/dev/null' </dev/null 2>/dev/null); then
    tun=$(grep -cE '^[0-9]+: tun[0-9]+[:@]' <<<"$link" || true)
  else
    tun=-1
  fi
  if [ "$tun" -gt 0 ]; then
    ping_out=$(timeout 90 adb -s "$s" shell "ping -c 20 -i 0.2 $PING_TARGET" </dev/null 2>/dev/null) || ping_rc=$?
    np=$(probe_netprobe "$s")
    if [ -n "$np" ]; then
      np_run "$s" "$np" 900 down speed.cloudflare.com 80 '/__down?bytes=50000000' 50000000
      down_rc=$NP_RC; down_out=$NP_OUT
      np_run "$s" "$np" 600 up speed.cloudflare.com 80 /__up 10000000
      up_rc=$NP_RC; up_out=$NP_OUT
    else
      note "$s: netprobe не найден (искали $NETPROBE_DIR/{knothop-netprobe,rawg-netprobe,netprobe})"
    fi
  fi
  if ! json=$(python3 -I -c "$PY_PHONE" "$s" "$tun" "$ping_rc" "$ping_out" "$np" "$down_rc" "$down_out" "$up_rc" "$up_out"); then
    FAIL=1
    json=$(printf '{"phone":"%s","ok":false,"problems":["internal-error"]}' "${s//\"/}")
  elif ! json_ok <<<"$json"; then
    FAIL=1
  fi
  printf '%s\n' "$json"
  if [ "$tun" -lt 0 ]; then
    note "$s: adb не ответил при чтении интерфейсов (offline/unauthorized?)"
  elif [ "$tun" -eq 0 ]; then
    note "$s: нет tun: VPN выключен или режим «Сеть» (включите: deploy/phones.sh vpn-on)"
  fi
}

node_check() {
  local label=$1 target=$2 opts=$3 sudo_cmd="" raw="" rc=0 json jrc=0
  local -a OPTS=()
  read -r -a OPTS <<< "${opts:-}"
  case "$target" in root@*) ;; *@*) sudo_cmd="sudo -n " ;; esac
  # stderr ssh не читаем вовсе: в stdout идут только метка и безопасные коды
  raw=$(ssh "${OPTS[@]}" "${SSHB[@]}" "$target" "${sudo_cmd}python3 -" <<<"$PY_NODE" 2>/dev/null) || rc=$?
  if ! json=$(python3 -I -c "$PY_NODE_OUT" "$label" "$rc" "$raw"); then
    jrc=1
    json=$(printf '{"node":"%s","ok":false,"error":"internal-error"}' "${label//\"/}")
  elif ! json_ok <<<"$json"; then
    jrc=1
  fi
  printf '%s\n' "$json"
  [ "$jrc" = 0 ] || FAIL=1
}

if [ "$DO_PHONES" = 1 ]; then
  command -v adb >/dev/null || die "нет программы: adb"
  command -v python3 >/dev/null || die "нет программы: python3"
  refresh_devices
  if [ "${#DEVICES[@]}" -eq 0 ]; then
    note "нет телефонов в состоянии device"
    FAIL=1
  else
    for s in "${DEVICES[@]}"; do
      phone_check "$s"
    done
  fi
  [ "$SKIPPED" = 0 ] || FAIL=1
fi

if [ "$DO_NODES" = 1 ]; then
  [ -f "$HOSTS" ] || die "нет $HOSTS"
  command -v ssh >/dev/null || die "нет программы: ssh"
  command -v python3 >/dev/null || die "нет программы: python3"
  # --nodes: все метки должны существовать в hosts.tsv
  declare -A WANT=()
  if [ -n "$WANT_NODES" ]; then
    IFS=, read -r -a LIST <<< "$WANT_NODES"
    for l in "${LIST[@]}"; do [ -n "$l" ] && WANT[$l]=1; done
  fi
  declare -A FOUND=()
  while IFS=$'\t' read -r -u3 label target _variant opts; do
    [ -n "$target" ] || die "пустая ssh-цель в $HOSTS (метка $label)"
    if [ -n "$WANT_NODES" ] && [ -z "${WANT[$label]:-}" ]; then continue; fi
    FOUND[$label]=1
    # как в rollout.sh: StrictHostKeyChecking и подмена known_hosts в опциях запрещены
    if printf '%s\n' "${opts:-}" | grep -qiE 'StrictHostKeyChecking|UserKnownHostsFile=? *(/dev/null|none)\b|GlobalKnownHostsFile'; then
      die "метка $label: в колонке опций нельзя переопределять StrictHostKeyChecking или отключать known_hosts"
    fi
    node_check "$label" "$target" "${opts:-}"
  done 3< <(grep -vE '^\s*(#|$)' "$HOSTS")
  for l in "${!WANT[@]}"; do
    [ -n "${FOUND[$l]:-}" ] || die "нет метки $l в $HOSTS"
  done
fi

[ "$FAIL" = 0 ] || { note "есть телефоны/узлы с ошибкой или пропущенные"; exit 1; }
