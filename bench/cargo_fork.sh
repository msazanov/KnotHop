#!/usr/bin/env bash
# Штатный запуск cargo для настоящих крейтов KnotHop с патчем локального форка (check/test/metadata/tree).
# Использование: bench/cargo_fork.sh КРЕЙТ [аргументы cargo...]
#   КРЕЙТ - rns-iroh-node | android-native
# Пример: bench/cargo_fork.sh rns-iroh-node check --offline --tests
#         bench/cargo_fork.sh rns-iroh-node test --offline --lib --no-run
# Окружение: LEVICULUM_FORK (по умолчанию ~/dev/leviculum), CARGO_TARGET_DIR (по умолчанию отдельный
# каталог в ~/.cache/knothop-target/check-КРЕЙТ, не deploy/dist), SOURCE_DATE_EPOCH (из HEAD форка).
# Для android-native собирается хостовый check; APK собирает bench/android/build.sh.
set -euo pipefail
HERE="$(cd "$(dirname "$0")" && pwd)"
export PATH="$HOME/.cargo/bin:$PATH"
CRATE="${1:?нужен крейт: rns-iroh-node | android-native}"
shift
case "$CRATE" in
  rns-iroh-node) DIR="$HERE/rns-iroh-node" ;;
  android-native) DIR="$HERE/android/native" ;;
  *) echo "крейт: rns-iroh-node | android-native" >&2; exit 1 ;;
esac
FORK="${LEVICULUM_FORK:-$HOME/dev/leviculum}"
# shellcheck source=bench/fork-patch.sh
source "$HERE/fork-patch.sh"
fork_patch_init "$FORK"
if [ -z "${SOURCE_DATE_EPOCH:-}" ]; then
  SOURCE_DATE_EPOCH="$(git -C "$FORK" log -1 --format=%ct HEAD 2>/dev/null || echo 0)"
  export SOURCE_DATE_EPOCH
fi
export RUSTFLAGS="${RUSTFLAGS:--C link-arg=-fuse-ld=bfd}"
export CARGO_TARGET_DIR="${CARGO_TARGET_DIR:-$HOME/.cache/knothop-target/check-$CRATE}"
cd "$DIR"
exec cargo "${FORK_PATCH_ARGS[@]}" "$@"
