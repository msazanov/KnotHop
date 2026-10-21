#!/bin/sh
# Проверка обнаружения «чёрной дыры» TCP без сети и root: пользовательское и сетевое пространство имён, на loopback режутся сегменты с данными
# (рукопожатие и чистые ACK проходят). Ожидается: tcpc::connect возвращает Dial::Blackhole.
# Запуск из bench/rns-iroh-node: sh ../android/blackhole_test.sh
set -eu
export RUSTFLAGS='-C link-arg=-fuse-ld=bfd'
C='patch."https://codeberg.org/Lew_Palm/Leviculum".leviculum-std.path="$HOME/dev/leviculum/leviculum-std"'
BIN=$(cargo test --offline --lib --no-run --config "$C" 2>&1 | sed -n 's/.*Executable unittests src\/lib.rs (\(.*\))/\1/p')
[ -x "$BIN" ] || { echo "не нашёл тестовый бинарник" >&2; exit 2; }
exec unshare -Urn sh -c '
set -e
ip link set lo up
nft add table inet bh
nft add chain inet bh in "{ type filter hook input priority 0; }"
# пакет с 4 байтами данных и TCP-опциями длиннее 54 байт; SYN, чистый ACK и FIN короче или помечены флагами
nft add rule inet bh in tcp flags \& \(syn\|fin\|rst\) == 0 meta length gt 54 counter drop
"$0" --ignored connect_reports_blackhole_when_payload_is_dropped --test-threads=1
nft list ruleset | grep counter
' "$BIN"
