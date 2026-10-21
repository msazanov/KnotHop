#!/usr/bin/env bash
# Основная матрица: интерфейс x MTU-режим x хопы x потери. Повторы - внешний цикл
# (чтобы дрейф нагрузки хоста не смещал отдельную ячейку).
#
#   REPS=3 ./run_matrix.sh main      # потерь нет
#   REPS=3 ./run_matrix.sh loss      # потери 1% (TCP default, UDP; 1 хоп)
set -u
HERE=$(cd "$(dirname "$0")" && pwd)
REPS=${REPS:-3}
SET=${1:-main}
export IDLE=${IDLE:-10} ECHO_N=${ECHO_N:-200}
MIB=1048576

run() { # iface mtu hops loss mib rep
  local tag="m-$SET-$1-$2-h$3-l$4-r$6"
  [ -s "$HERE/results/raw/$tag.json" ] && { echo "skip $tag"; return; }
  "$HERE/run_cell.sh" "$3" "$1" "$2" "$4" "$(($5 * MIB))" "$tag" 2>&1 | grep -E "RESULT|TIMEOUT|fail"
}

for rep in $(seq 1 "$REPS"); do
  if [ "$SET" = main ]; then
    for h in 0 1 2; do
      run tcp      default $h 0 128 $rep
      run backbone default $h 0 128 $rep
      run tcp      aligned $h 0 8   $rep
      run backbone aligned $h 0 8   $rep
      run udp      default $h 0 8   $rep
    done
  elif [ "$SET" = lev ]; then
    export NODE_IMPL=lnsd
    for h in 1 2; do
      run tcp      default $h 0 128 $rep
      run backbone default $h 0 128 $rep
      run tcp      aligned $h 0 8   $rep
      run udp      default $h 0 8   $rep
    done
  elif [ "$SET" = loss ]; then
    for l in 1; do
      run tcp default 1 $l 32 $rep
      run udp default 1 $l 4  $rep
    done
  fi
done
echo "MATRIX $SET DONE"
