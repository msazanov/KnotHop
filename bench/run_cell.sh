#!/usr/bin/env bash
# Одна ячейка матрицы: цепочка client -> N transport -> server, один интерфейс на всех звеньях.
#
# Использование:
#   run_cell.sh <hops 0|1|2> <iface tcp|udp|backbone> <mtu default|aligned> <loss_pct> <bytes> <tag>
#
# Результат: bench/results/raw/<tag>.json
set -u
HOPS=${1:?hops}; IFACE=${2:?iface}; MTUMODE=${3:-default}; LOSS=${4:-0}; BYTES=${5:-4194304}; TAG=${6:?tag}
IMAGE=${IMAGE:-rawg-bench:rns1.5.7}
IDLE=${IDLE:-30}
ECHO_N=${ECHO_N:-200}
BASE_CORE=${BASE_CORE:-4}
CORES=${CORES:-1}   # ядер на контейнер (по умолчанию 1)
CELL_TIMEOUT=${CELL_TIMEOUT:-420}
HERE=$(cd "$(dirname "$0")" && pwd)
OUT="$HERE/results/raw"; mkdir -p "$OUT"
SHARED=/tmp/opencode/bench/$TAG; rm -rf "$SHARED"; mkdir -p "$SHARED"; chmod 777 "$SHARED"
N=$((HOPS + 2))            # число узлов: client + HOPS транспортов + server
LINKS=$((N - 1))
FIXED=0; [ "$MTUMODE" = aligned ] && FIXED=500
subnet() { echo "10.77.$(( (RANDOM % 150) + 50 )).0/24"; }

name() { echo "bench-$TAG-n$1"; }
net()  { echo "bench-$TAG-l$1"; }

cleanup() {
  for i in $(seq 0 $((N - 1))); do docker rm -f "$(name $i)" >/dev/null 2>&1; done
  for i in $(seq 0 $((LINKS - 1))); do docker network rm "$(net $i)" >/dev/null 2>&1; done
}
trap cleanup EXIT
cleanup

cpu_snap() { # печатает "<container> <usage_usec>"
  for i in $(seq 0 $((N - 1))); do
    v=$(docker exec "$(name $i)" cat /sys/fs/cgroup/cpu.stat 2>/dev/null | awk '/^usage_usec/{print $2}')
    echo "$i ${v:-0}"
  done
}

# --- сети
for i in $(seq 0 $((LINKS - 1))); do
  docker network create --driver bridge --subnet "10.77.$((100 + i)).0/24" "$(net $i)" >/dev/null || { echo "network fail"; exit 2; }
done

# --- контейнеры
for i in $(seq 0 $((N - 1))); do
  args=(--iface "$IFACE" --fixed-mtu "$FIXED")
  if [ "$i" -gt 0 ]; then args+=(--left-peer "$(name $((i - 1)))" --left-port $((4240 + i - 1))); fi
  if [ "$i" -lt $((N - 1)) ]; then args+=(--right-peer "$(name $((i + 1)))" --right-port $((4240 + i))); fi
  if [ "$i" -eq 0 ]; then role=client; args+=(--bytes "$BYTES" --idle "$IDLE" --echo-n "$ECHO_N" --parallel "${PARALLEL:-1}")
  elif [ "$i" -eq $((N - 1)) ]; then role=server; args+=(--announce-every "${ANNOUNCE_EVERY:-5}")
  else role=node; [ -n "${IFACE_MODE:-}" ] && args+=(--iface-mode "$IFACE_MODE"); fi
  first_net=$(net $([ "$i" -gt 0 ] && echo $((i - 1)) || echo 0))
  docker create --name "$(name $i)" --network "$first_net" --cpuset-cpus "$((BASE_CORE + i * CORES))-$((BASE_CORE + i * CORES + CORES - 1))" \
     --cap-add NET_ADMIN ${EXTRA_DOCKER_ARGS:-} -e NODE_IMPL="${NODE_IMPL:-rnsd}" -e PCAP_IDLE="${PCAP_IDLE:-}" -v "$SHARED:/shared" "$IMAGE" "$role" "${args[@]}" >/dev/null || { echo "create fail $i"; exit 2; }
  if [ "$i" -gt 0 ] && [ "$i" -lt $((N - 1)) ]; then docker network connect "$(net $i)" "$(name $i)"; fi
  if [ "$i" -eq 0 ] && [ "$N" -eq 2 ]; then :; fi
done
# server (последний) подключён только к своему левому линку; client - к правому (net 0)

# порядок запуска: сервер, транспорты справа налево, клиент
for i in $(seq $((N - 1)) -1 0); do docker start "$(name $i)" >/dev/null; sleep 0.5; done

if [ "$LOSS" != "0" ]; then
  sleep 1
  docker exec "$(name 0)" tc qdisc add dev eth0 root netem loss "${LOSS}%" 2>&1 | head -2
fi

# --- ожидание готовности клиента (link + прогрев + простой)
t0=$(date +%s)
while [ ! -e "$SHARED/ready" ] && [ ! -e "$SHARED/result.json" ]; do
  sleep 0.5
  if [ $(( $(date +%s) - t0 )) -gt "$CELL_TIMEOUT" ]; then echo "TIMEOUT ready"; break; fi
done

if [ -e "$SHARED/ready" ]; then
  cpu_snap > "$SHARED/cpu0.txt"; w0=$(date +%s.%N)
  touch "$SHARED/go"
  t1=$(date +%s)
  while [ ! -e "$SHARED/done" ]; do
    sleep 0.3
    if [ $(( $(date +%s) - t1 )) -gt "$CELL_TIMEOUT" ]; then echo "TIMEOUT transfer"; break; fi
  done
  w1=$(date +%s.%N); cpu_snap > "$SHARED/cpu1.txt"
  echo "$w0 $w1" > "$SHARED/wall.txt"
  touch "$SHARED/echo_go"
fi

# --- ожидание записи итогового result.json (после echo-фазы)
t2=$(date +%s)
while [ ! -s "$SHARED/result.json" ]; do
  sleep 0.5
  if [ $(( $(date +%s) - t2 )) -gt 180 ]; then echo "TIMEOUT result"; break; fi
done
touch "$SHARED/fin"; sleep 1

for i in $(seq 0 $((N - 1))); do docker logs "$(name $i)" > "$OUT/$TAG.n$i.log" 2>&1; done

python3 - "$TAG" "$SHARED" "$OUT" "$HOPS" "$IFACE" "$MTUMODE" "$LOSS" "$BYTES" "$IMAGE" <<'PY'
import json, os, sys, subprocess, platform, time
tag, shared, out, hops, iface, mtumode, loss, nbytes, image = sys.argv[1:10]
def rd(p, d=None):
    try: return json.load(open(os.path.join(shared, p)))
    except Exception: return d
res = rd("result.json", {"error": "no result"})
srv = rd("server.json", {})
cpu = {}
try:
    c0 = dict(l.split() for l in open(os.path.join(shared, "cpu0.txt")))
    c1 = dict(l.split() for l in open(os.path.join(shared, "cpu1.txt")))
    w0, w1 = map(float, open(os.path.join(shared, "wall.txt")).read().split())
    wall = w1 - w0
    for k in c0:
        cpu[k] = round(100.0 * (int(c1[k]) - int(c0[k])) / 1e6 / wall, 1) if wall > 0 else None
    cpu = {"wall_s": round(wall, 3), "cpu_percent_of_one_core_by_node": cpu}
except Exception as e:
    cpu = {"error": str(e)}
dig = subprocess.run(["docker", "image", "inspect", image, "--format", "{{.Id}}"], capture_output=True, text=True).stdout.strip()
doc = {"tag": tag, "cell": {"hops_requested": int(hops), "iface": iface, "mtu_mode": mtumode, "loss_pct": float(loss), "payload_bytes": int(nbytes),
                            "iface_mode": os.environ.get("IFACE_MODE", "") or "full", "node_impl": os.environ.get("NODE_IMPL", "rnsd"), "announce_every_s": float(os.environ.get("ANNOUNCE_EVERY", "5"))},
       "client": res, "server": srv, "cpu": cpu,
       "env": {"image": image, "image_id": dig, "kernel": platform.release(), "date": time.strftime("%Y-%m-%dT%H:%M:%S%z"),
               "loadavg_at_end": os.getloadavg()}}
json.dump(doc, open(os.path.join(out, tag + ".json"), "w"), indent=1)
t = res.get("transfer", {})
print("RESULT", tag, "ok=", t.get("ok"), "sec=", t.get("seconds"), "err=", res.get("error"))
PY
