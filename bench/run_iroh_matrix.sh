#!/usr/bin/env bash
# Матрица iroh/QUIC: скорость, relay, потери/задержка (QUIC против TCP), переключение пути.
# Повторы - внешний цикл. Существующие результаты пропускаются.
set -u
HERE=$(cd "$(dirname "$0")" && pwd); cd "$HERE"
REPS=${REPS:-3}; SET=${1:-main}
run() { tag=$1; shift; [ -s "results/iroh/$tag.json" ] && { echo "skip $tag"; return; }; python3 iroh_cell.py "$@" "$tag" 2>&1 | tail -1; }
cell() { # scenario tag args...
  local sc=$1 tag=$2; shift 2
  [ -s "results/iroh/$tag.json" ] && { echo "skip $tag"; return; }
  python3 iroh_cell.py "$sc" "$tag" "$@" 2>&1 | tail -1
}
for r in $(seq 1 "$REPS"); do
  if [ "$SET" = main ]; then
    cell direct  "m-direct-up-r$r"    --mode bulk-up   --mib 1024
    cell direct  "m-direct-down-r$r"  --mode bulk-down --mib 1024
    cell direct  "m-direct-echo-r$r"  --mode echo --echo-n 300
    cell relay   "m-relay-up-r$r"     --mode bulk-up   --mib 256
    cell relay   "m-relay-down-r$r"   --mode bulk-down --mib 256
    cell relay   "m-relay-echo-r$r"   --mode echo --echo-n 300
  elif [ "$SET" = loss ]; then
    for l in 0 1 5; do
      cell direct "l-quic-l${l}-d0-r$r"  --mode bulk-up --mib 256 --loss $l
      cell tcp    "l-tcp-l${l}-d0-r$r"   --secs 8 --loss $l
      cell direct "l-quic-l${l}-d20-r$r" --mode bulk-up --mib 256 --loss $l --delay-ms 20
      cell tcp    "l-tcp-l${l}-d20-r$r"  --secs 8 --loss $l --delay-ms 20
    done
  elif [ "$SET" = switch ]; then
    cell switch "s-down-r$r" --mode timed-down --secs 40 --block-at 10 --unblock-at 25 --verify
    cell switch "s-up-r$r"   --mode timed-up   --secs 40 --block-at 10 --unblock-at 25 --verify
  fi
done
echo "IROH MATRIX $SET DONE"
