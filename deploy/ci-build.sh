#!/usr/bin/env bash
# Сборка knothopd для CI (.github/workflows/ci.yml). Флаги и исходники как в deploy/build.sh:
# SOURCE_DATE_EPOCH из HEAD форка, патч форка на его путь, bfd на хосте, контейнер ubuntu:22.04 для u2204.
# Отличаются только каталоги сборки (каталог раннера вместо домашнего кэша) и отсутствие пилотных файлов.
# Использование: ci-build.sh host|u2204 КАТАЛОГ_ВЫВОДА
#   host   - knothopd на хосте раннера (glibc Ubuntu 24.04); также пишет FORK-MANIFEST.txt
#   u2204  - knothopd-u2204 в контейнере ubuntu:22.04 (glibc 2.35), образ из deploy/Dockerfile.u2204
# Окружение: LEVICULUM_FORK - checkout форка на коммите из deploy/leviculum.ref (обязательно);
#            CI_TARGET - каталог сборок (по умолчанию $RUNNER_TEMP/knothop-target).
# Токены и ключи сюда не попадают.
set -euo pipefail
HERE="$(cd "$(dirname "$0")" && pwd)"
ROOT="$(dirname "$HERE")"
MODE="${1:?нужен режим: host или u2204}"
OUT="${2:?нужен каталог вывода}"
FORK="${LEVICULUM_FORK:?нужен LEVICULUM_FORK: checkout форка}"
TARGET="${CI_TARGET:-${RUNNER_TEMP:-/tmp}/knothop-target}"
mkdir -p "$OUT" "$TARGET"

# собираем только тот коммит форка, который закреплён в репозитории
PIN="$(tr -d '[:space:]' < "$ROOT/deploy/leviculum.ref")"
if [ "$(git -C "$FORK" rev-parse HEAD)" != "$PIN" ]; then
  echo "HEAD форка не совпадает с deploy/leviculum.ref" >&2; exit 1
fi
# штамп leviculum-core/build.rs: время коммита форка, иначе байты зависят от момента сборки
SOURCE_DATE_EPOCH="$(git -C "$FORK" log -1 --format=%ct HEAD)"
export SOURCE_DATE_EPOCH
# leviculum-std и leviculum-lxmf подставляются из этого checkout (один leviculum-core), см. bench/fork-patch.sh
# shellcheck source=bench/fork-patch.sh
source "$ROOT/bench/fork-patch.sh"
fork_patch_init "$FORK"

case "$MODE" in
host)
  echo "== knothopd (хост: $(uname -sr))"
  LEVICULUM_FORK="$FORK" CARGO_TARGET_DIR="$TARGET/host" bash "$ROOT/bench/build_fork.sh" --bin knothopd
  install -m 0755 "$TARGET/host/release/knothopd" "$OUT/knothopd"
  BIN="$OUT/knothopd"
  LEVICULUM_FORK="$FORK" bash "$HERE/fork-manifest.sh" "$OUT/FORK-MANIFEST.txt"
  ;;
u2204)
  echo "== knothopd-u2204 (ubuntu:22.04)"
  CARGO_VOL="$TARGET/u2204-cargo"
  mkdir -p "$CARGO_VOL" "$TARGET/u2204"
  docker build -q -t knothop-build:u2204 -f "$HERE/Dockerfile.u2204" "$HERE" >/dev/null
  # toolchain ставит rustup-init внутри контейнера в том CARGO_VOL; сам rustup-init берём с хоста по SHA-256
  if [ ! -x "$CARGO_VOL/bin/cargo" ]; then
    RUSTUP_URL="https://static.rust-lang.org/rustup/dist/x86_64-unknown-linux-gnu/rustup-init"
    curl --proto '=https' --tlsv1.2 --fail --silent --show-error --location -o "$TARGET/rustup-init" "$RUSTUP_URL"
    curl --proto '=https' --tlsv1.2 --fail --silent --show-error --location -o "$TARGET/rustup-init.sha256" "$RUSTUP_URL.sha256"
    (cd "$TARGET" && echo "$(cut -d' ' -f1 rustup-init.sha256)  rustup-init" | sha256sum -c -)
    chmod 0755 "$TARGET/rustup-init"
    docker run --rm --user "$(id -u):$(id -g)" -e HOME=/tmp -e CARGO_HOME=/cargo -e RUSTUP_HOME=/cargo/rustup \
      -v "$CARGO_VOL:/cargo" -v "$TARGET/rustup-init:/rustup-init:ro" knothop-build:u2204 \
      /rustup-init -y --profile minimal --default-toolchain stable --no-modify-path
  fi
  # те же исходники, что и на хосте: рабочее дерево и форк монтируются по тем же путям
  docker run --rm --user "$(id -u):$(id -g)" \
    -v "$CARGO_VOL:/cargo" -v "$TARGET/u2204:/target" -v "$ROOT:$ROOT" -v "$FORK:$FORK" \
    -e HOME=/tmp -e CARGO_HOME=/cargo -e RUSTUP_HOME=/cargo/rustup -e CARGO_TARGET_DIR=/target \
    -e PATH=/cargo/bin:/usr/bin:/bin -e SOURCE_DATE_EPOCH="$SOURCE_DATE_EPOCH" \
    -w "$ROOT/bench/rns-iroh-node" knothop-build:u2204 \
    cargo build --release --bin knothopd "${FORK_PATCH_ARGS[@]}"
  install -m 0755 "$TARGET/u2204/release/knothopd" "$OUT/knothopd-u2204"
  BIN="$OUT/knothopd-u2204"
  ;;
*)
  echo "режим: host или u2204" >&2; exit 1
  ;;
esac

# максимальная версия glibc, которую требует бинарник; knothopd-u2204 должен укладываться в 2.35
need="$(objdump -T "$BIN" | grep -o 'GLIBC_[0-9.]*' | sort -uV | tail -1)"
echo "   $(basename "$BIN") требует до ${need:-никакой версии GLIBC}"
if [ "$MODE" = u2204 ] && [ "$(printf '%s\n' GLIBC_2.35 "$need" | sort -V | tail -1)" != GLIBC_2.35 ]; then
  echo "knothopd-u2204 требует glibc новее 2.35: на узлах de не запустится" >&2; exit 1
fi
