#!/usr/bin/env bash
# Сравнение формы записей: наш туннель (mimic вкл/выкл) на стенде nginx (rr-cover на 127.0.0.1:18443, см. lab/up.sh или ручной запуск)
# против эталона Chromium (tools/recsniff.py, results/chrome-*.tsv). Всё на loopback, ключ во временном каталоге. N сессий на вариант.
set -euo pipefail
HERE=$(cd "$(dirname "$0")" && pwd); R=$(dirname $HERE)
B=${B:-$HOME/.cache/knothop-target/reality/release/reality-bridge}
T=${T:-$HOME/.cache/knothop-target/reality/tmp/cmp}; N=${N:-6}
rm -rf $T; mkdir -p $T; cd $T
PUB=$($B keygen --out $T/key)
for mode in on off; do
  FL=""; [ $mode = off ] && FL="--no-h2"
  python3 $HERE/mock_quic.py srv 5201 & P1=$!
  $B server --listen 127.0.0.1:8444 --key-file $T/key --short-ids 0123456789abcdef --dest 127.0.0.1:18443 --sni cover.lab --target 127.0.0.1:5201 $FL 2>$T/srv-$mode.log & P2=$!
  LINGER=2 DELAY_MS=${DELAY_MS:-0} python3 $HERE/recsniff.py 19444 127.0.0.1 8444 $T/ours-$mode.tsv $N & P3=$!
  $B client --listen 127.0.0.1:9000 --connect 127.0.0.1:19444 --pubkey $PUB --short-id 0123456789abcdef --sni cover.lab $FL 2>$T/cli-$mode.log & P4=$!
  sleep 3
  for i in $(seq $N); do timeout 10 python3 $HERE/mock_quic.py cli 9000; done | tee $T/mock-$mode.txt; sleep 1
  LINGER=2; kill $P3 $P1 $P2 $P4 2>/dev/null || true; wait 2>/dev/null || true
done
