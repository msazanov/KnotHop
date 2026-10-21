#!/usr/bin/env bash
# leviculum + iroh (нативный адаптер): смена пути внутри QUIC (switch), смена RNS-узла (hop), скорость (direct).
# Повторы - внешний цикл; существующие результаты пропускаются.
set -u
HERE=$(cd "$(dirname "$0")" && pwd); cd "$HERE"
REPS=${REPS:-3}
cell() { sc=$1; tag=$2; shift 2; [ -s "results/lev-iroh/$tag.json" ] && { echo "skip $tag"; return; }; python3 lev_cell.py "$sc" "$tag" "$@" 2>&1 | tail -1; }
T3="--path-idle-ms 3000 --path-keepalive-ms 1000"
for r in $(seq 1 "$REPS"); do
  # 1) потеря прямого пути, relay доступен: RNS видит один интерфейс
  cell switch "sw-def-r$r" --duration 70 --block-at 10 --unblock-at 40
  cell switch "sw-t3-r$r"  --duration 70 --block-at 10 --unblock-at 40 $T3
  # 2) смена RNS-узла C->E => C->A->E, relay нет
  cell hop "hop-naive-r$r" --duration 60 --block-at 10 --unblock-at 40 $T3 --conn-idle-ms 4000
  cell hop "hop-ctl4-r$r"  --duration 60 --block-at 10 --unblock-at 40 $T3 --conn-idle-ms 4000 --controller
  cell hop "hop-ctl2-r$r"  --duration 60 --block-at 10 --unblock-at 40 $T3 --conn-idle-ms 2000 --controller
  # 3) скорость, прямой путь, разные размеры Resource
  cell direct "sp-64k-r$r"  --duration 20 --bytes 65536
  cell direct "sp-256k-r$r" --duration 20 --bytes 262144
  cell direct "sp-1m-r$r"   --duration 20 --bytes 1048576
done
echo "LEV MATRIX DONE"
