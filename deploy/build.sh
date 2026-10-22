#!/usr/bin/env bash
# Сборка rawgd для узлов и выкладка в deploy/dist/ вместе с SHA256SUMS.
#   rawgd         - хост сборки (glibc новее; Arch/Debian 12+/Ubuntu 24.04)
#   rawgd-u2204   - в контейнере ubuntu:22.04 (glibc 2.35; de). Образ rawg-build:u2204 строится из deploy/Dockerfile.u2204.
# Исходники одни и те же (рабочее дерево). Токены и ключи сюда не попадают.
set -euo pipefail
HERE="$(cd "$(dirname "$0")" && pwd)"
ROOT="$(dirname "$HERE")"
FORK="${LEVICULUM_FORK:-$HOME/dev/leviculum}"
DIST="$HERE/dist"
mkdir -p "$DIST"

# воспроизводимый штамп leviculum-core/build.rs: время сборки берём из HEAD форка,
# иначе каждое изменение коммита меняет байты бинарника. Эталон - 9dfdaaa2 (W69/wave v3).
if [ -z "${SOURCE_DATE_EPOCH:-}" ] ; then
  SOURCE_DATE_EPOCH="$(git -C "$FORK" log -1 --format=%ct HEAD 2>/dev/null || echo 0)"
  export SOURCE_DATE_EPOCH
fi
echo "SOURCE_DATE_EPOCH=$SOURCE_DATE_EPOCH (штамп build.rs)"
bash "$ROOT/bench/build_fork.sh" --bin rawgd 2>&1 | grep -E "^error|Finished" | tee /tmp/rawg-host-build.log
grep -q Finished /tmp/rawg-host-build.log || { echo "сборка хоста не удалась" >&2; exit 1; }
install -m 0755 "${CARGO_TARGET_DIR:-$HOME/.cache/rawg-target/fork}/release/rawgd" "$DIST/rawgd"

echo "== rawgd-u2204 (ubuntu:22.04)"
docker image inspect rawg-build:u2204 >/dev/null 2>&1 || docker build -q -t rawg-build:u2204 -f "$HERE/Dockerfile.u2204" "$HERE"
mkdir -p "$HOME/.cache/rawg-target/u2204"
docker run --rm --user "$(id -u):$(id -g)" \
  -v "$HOME/.cache/rawg-cargo-u2204:/cargo" -v "$HOME/.cache/rawg-target/u2204:/target" \
  -v "$ROOT:$ROOT" -v "$FORK:$FORK" \
  -e HOME=/tmp -e CARGO_HOME=/cargo -e RUSTUP_HOME=/cargo/rustup -e CARGO_TARGET_DIR=/target -e PATH=/cargo/bin:/usr/bin:/bin \
  -e SOURCE_DATE_EPOCH=${SOURCE_DATE_EPOCH} \
  -w "$ROOT/bench/rns-iroh-node" rawg-build:u2204 \
  cargo build --release --bin rawgd --config "patch.\"https://codeberg.org/Lew_Palm/Leviculum\".leviculum-std.path=\"$FORK/leviculum-std\"" 2>&1 \
  | grep -E "^error|Finished" | tee /tmp/rawg-u2204-build.log
grep -q Finished /tmp/rawg-u2204-build.log || { echo "сборка u2204 не удалась" >&2; exit 1; }
install -m 0755 "$HOME/.cache/rawg-target/u2204/release/rawgd" "$DIST/rawgd-u2204"

# проверка совместимости с glibc целевых узлов: максимальная требуемая версия символов
for f in rawgd rawgd-u2204; do
  need=$(objdump -T "$DIST/$f" | grep -o 'GLIBC_[0-9.]*' | sort -uV | tail -1)
  echo "   $f требует до $need"
done
if [ "$(objdump -T "$DIST/rawgd-u2204" | grep -o 'GLIBC_[0-9.]*' | sort -uV | tail -1)" \> "GLIBC_2.35" ]; then
  echo "rawgd-u2204 требует glibc новее 2.35: на de не запустится" >&2; exit 1
fi

cp "$HERE/node-install.sh" "$HERE/node-hostfix.sh" "$HERE/push-remote.sh" "$ROOT/deploy-0013/rawgd-pilot.nft" "$DIST/"
# снимок состояния форка: без него по бинарнику не видно, какие правки в него вошли
bash "$HERE/fork-manifest.sh" "$DIST/FORK-MANIFEST.txt"
# push-remote.sh входит в SUMS: push.py не отправит helper, которого нет в эталоне (он выполняется на узле от root)
(cd "$DIST" && sha256sum rawgd rawgd-u2204 node-install.sh node-hostfix.sh push-remote.sh rawgd-pilot.nft > SHA256SUMS && cat SHA256SUMS)
