#!/usr/bin/env bash
# Общий патч локального форка Leviculum для всех сборок KnotHop (подключается через source).
#
# Манифесты rns-iroh-node берут leviculum-std и leviculum-lxmf с публичного Codeberg на ОДНОЙ ревизии
# (merge-base форка с upstream, она там есть). Коммита форка на Codeberg нет и не должно быть, поэтому
# фактические исходники подставляет Cargo [patch]: оба пакета берутся из одного checkout форка.
# leviculum-core тогда приходит из этого же checkout по path-зависимостям std и lxmf: один пакет,
# один набор типов. Патчить core отдельно не нужно (патч не используется и попал бы в Cargo.lock
# как patch.unused).
#
# Использование:
#   source bench/fork-patch.sh
#   fork_patch_init "$FORK"          # проверяет checkout, заполняет массив FORK_PATCH_ARGS
#   cargo build "${FORK_PATCH_ARGS[@]}" ...
#
# Всё ниже - только --config командной строки: ни ~/.cargo/config.toml, ни кэш пакетов, ни
# временные манифесты не меняются.

# URL должен совпадать с git-зависимостью в Cargo.toml буква в букву: по нему Cargo сопоставляет патч.
FORK_PATCH_SOURCE="https://codeberg.org/Lew_Palm/Leviculum"
# Ожидаемые пакеты рабочего пространства форка. Другие пакеты не патчатся.
FORK_PATCH_PACKAGES=(leviculum-std leviculum-lxmf)

fork_patch_init() {
  local fork="${1:?нужен путь checkout форка}" pkg
  case "$fork" in
    /*) ;;
    *) echo "fork-patch: путь форка должен быть абсолютным: $fork" >&2; return 1 ;;
  esac
  # путь попадает в строку TOML внутри --config: кавычки, обратная косая и перевод строки недопустимы
  case "$fork" in
    *\"* | *\\* | *$'\n'*) echo "fork-patch: недопустимые символы в пути форка" >&2; return 1 ;;
  esac
  FORK_PATCH_ARGS=()
  for pkg in "${FORK_PATCH_PACKAGES[@]}"; do
    if ! grep -q "^name = \"$pkg\"" "$fork/$pkg/Cargo.toml" 2>/dev/null; then
      echo "fork-patch: в $fork нет пакета $pkg" >&2; return 1
    fi
    FORK_PATCH_ARGS+=(--config "patch.\"$FORK_PATCH_SOURCE\".$pkg.path=\"$fork/$pkg\"")
  done
}
