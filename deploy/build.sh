#!/usr/bin/env bash
# Сборка knothopd для узлов и выкладка в deploy/dist/ вместе с SHA256SUMS.
#   knothopd         - хост сборки (glibc новее; Arch/Debian 12+/Ubuntu 24.04)
#   knothopd-u2204   - в контейнере ubuntu:22.04 (glibc 2.35; de). Образ knothop-build:u2204 строится из deploy/Dockerfile.u2204.
# Исходники одни и те же (рабочее дерево). Токены и ключи сюда не попадают.
set -euo pipefail
HERE="$(cd "$(dirname "$0")" && pwd)"
ROOT="$(dirname "$HERE")"
FORK="${LEVICULUM_FORK:-$HOME/dev/leviculum}"
DIST="$HERE/dist"
mkdir -p "$DIST"
# общий патч форка (leviculum-std + leviculum-lxmf из одного checkout), тот же, что в bench/build_fork.sh
# shellcheck source=bench/fork-patch.sh
source "$ROOT/bench/fork-patch.sh"
fork_patch_init "$FORK"

# воспроизводимый штамп leviculum-core/build.rs: время сборки берём из HEAD форка,
# иначе каждое изменение коммита меняет байты бинарника. Эталон - 9dfdaaa2 (W69/wave v3).
if [ -z "${SOURCE_DATE_EPOCH:-}" ] ; then
  SOURCE_DATE_EPOCH="$(git -C "$FORK" log -1 --format=%ct HEAD 2>/dev/null || echo 0)"
  export SOURCE_DATE_EPOCH
fi
echo "SOURCE_DATE_EPOCH=$SOURCE_DATE_EPOCH (штамп build.rs)"
bash "$ROOT/bench/build_fork.sh" --bin knothopd 2>&1 | grep -E "^error|Finished" | tee /tmp/knothop-host-build.log
grep -q Finished /tmp/knothop-host-build.log || { echo "сборка хоста не удалась" >&2; exit 1; }
install -m 0755 "${CARGO_TARGET_DIR:-$HOME/.cache/knothop-target/fork}/release/knothopd" "$DIST/knothopd"

echo "== knothopd-u2204 (ubuntu:22.04)"
docker image inspect knothop-build:u2204 >/dev/null 2>&1 || docker build -q -t knothop-build:u2204 -f "$HERE/Dockerfile.u2204" "$HERE"
mkdir -p "$HOME/.cache/knothop-target/u2204"
docker run --rm --user "$(id -u):$(id -g)" \
  -v "$HOME/.cache/knothop-cargo-u2204:/cargo" -v "$HOME/.cache/knothop-target/u2204:/target" \
  -v "$ROOT:$ROOT" -v "$FORK:$FORK" \
  -e HOME=/tmp -e CARGO_HOME=/cargo -e RUSTUP_HOME=/cargo/rustup -e CARGO_TARGET_DIR=/target -e PATH=/cargo/bin:/usr/bin:/bin \
  -e SOURCE_DATE_EPOCH=${SOURCE_DATE_EPOCH} \
  -w "$ROOT/bench/rns-iroh-node" knothop-build:u2204 \
  cargo build --release --bin knothopd "${FORK_PATCH_ARGS[@]}" 2>&1 \
  | grep -E "^error|Finished" | tee /tmp/knothop-u2204-build.log
grep -q Finished /tmp/knothop-u2204-build.log || { echo "сборка u2204 не удалась" >&2; exit 1; }
install -m 0755 "$HOME/.cache/knothop-target/u2204/release/knothopd" "$DIST/knothopd-u2204"

# проверка совместимости с glibc целевых узлов: максимальная требуемая версия символов
for f in knothopd knothopd-u2204; do
  need=$(objdump -T "$DIST/$f" | grep -o 'GLIBC_[0-9.]*' | sort -uV | tail -1)
  echo "   $f требует до $need"
done
if [ "$(objdump -T "$DIST/knothopd-u2204" | grep -o 'GLIBC_[0-9.]*' | sort -uV | tail -1)" \> "GLIBC_2.35" ]; then
  echo "knothopd-u2204 требует glibc новее 2.35: на de не запустится" >&2; exit 1
fi

cp "$HERE/node-install.sh" "$HERE/node-migrate.sh" "$HERE/node-hostfix.sh" "$HERE/node-hostpolicy.sh" "$HERE/push-remote.sh" "$ROOT/deploy-0013/knothop.nft" "$ROOT/deploy-0013/knothopd.service" "$DIST/"
# снимок состояния форка: без него по бинарнику не видно, какие правки в него вошли
bash "$HERE/fork-manifest.sh" "$DIST/FORK-MANIFEST.txt"
# push-remote.sh входит в SUMS: push.py не отправит helper, которого нет в эталоне (он выполняется на узле от root)
(cd "$DIST" && sha256sum knothopd knothopd-u2204 node-install.sh node-migrate.sh node-hostfix.sh node-hostpolicy.sh push-remote.sh knothop.nft knothopd.service > SHA256SUMS && cat SHA256SUMS)
