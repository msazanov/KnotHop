#!/usr/bin/env bash
# Сборка rns-iroh-node против локального форка leviculum ($HOME/dev/leviculum, ветка knothop/tuning).
# Результат: $CARGO_TARGET_DIR/release/rns-iroh-node (по умолчанию ~/.cache/knothop-target/fork;
# в /tmp на этой машине не хватает места под таргеты)
set -eu
export PATH="$HOME/.cargo/bin:$PATH"
# target-cpu=native дал +11% на стенде (интерполированные пары), но бинарник после этого
# не переносим на другие CPU: включать только если сборка и запуск на одном хосте.
target="${CARGO_BUILD_TARGET:-}"
want_target=0
for arg in "$@"; do
  if [ "$want_target" = "1" ]; then target="$arg"; want_target=0; fi
  case "$arg" in
    --target) want_target=1 ;;
    --target=*) target="${arg#--target=}" ;;
  esac
done
if [ "$target" = "aarch64-linux-android" ]; then
  # Dependency .cargo/config is not loaded from this benchmark crate, and
  # RUSTFLAGS overrides target-specific config. Supply both ARM backends here.
  export RUSTFLAGS="${RUSTFLAGS:-} --cfg aes_armv8 --cfg polyval_armv8"
else
  export RUSTFLAGS="${RUSTFLAGS:--C link-arg=-fuse-ld=bfd}"
fi
if [ "${KNOTHOP_NATIVE:-0}" = "1" ]; then
  export RUSTFLAGS="$RUSTFLAGS -C target-cpu=native"
fi
FORK=${LEVICULUM_FORK:-$HOME/dev/leviculum}
HERE="$(cd "$(dirname "$0")" && pwd)"
# shellcheck source=bench/fork-patch.sh
source "$HERE/fork-patch.sh"
fork_patch_init "$FORK"
cd "$HERE/rns-iroh-node"
CARGO_TARGET_DIR="${CARGO_TARGET_DIR:-$HOME/.cache/knothop-target/fork}" cargo build --release \
  "${FORK_PATCH_ARGS[@]}" "$@"
