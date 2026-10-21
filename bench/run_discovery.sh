#!/usr/bin/env bash
# Время появления пути до сервера: режим интерфейса транспортных узлов (full|gateway) x число транспортов.
# Период анонса сервера 20 с: без пересылки path request путь появится только по анонсу.
set -u
HERE=$(cd "$(dirname "$0")" && pwd)
export IDLE=1 ECHO_N=5 ANNOUNCE_EVERY=20
for rep in 1 2 3; do
  for h in 1 2; do
    for mode in gateway full; do
      [ "$mode" = full ] && [ "$rep" -gt 2 ] && continue
      tag="m-disc-$mode-h$h-r$rep"
      [ -s "$HERE/results/raw/$tag.json" ] && continue
      IFACE_MODE=$([ "$mode" = gateway ] && echo gateway || echo "") "$HERE/run_cell.sh" "$h" tcp default 0 1048576 "$tag" 2>&1 | grep -E "RESULT|TIMEOUT"
    done
  done
done
echo "DISC DONE"
