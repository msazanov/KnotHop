#!/usr/bin/env bash
# RNS поверх iroh: переключение direct->relay->direct при разных таймерах пути QUIC. Повторы - внешний цикл.
set -u
HERE=$(cd "$(dirname "$0")" && pwd); cd "$HERE"
REPS=${REPS:-3}
cfgs=("def 0 0" "t8 8000 2000" "t3 3000 1000" "t15 1500 500")
for r in $(seq 1 "$REPS"); do
  for cfg in "${cfgs[@]}"; do
    set -- $cfg
    tag="sw-$1-r$r"
    [ -s "results/iroh-rns/$tag.json" ] && { echo "skip $tag"; continue; }
    python3 iroh_rns_cell.py switch "$tag" --duration 70 --block-at 10 --unblock-at 40 --path-idle-ms "$2" --path-keepalive-ms "$3" 2>&1 | tail -1
  done
done
echo "RNS SWITCH DONE"
