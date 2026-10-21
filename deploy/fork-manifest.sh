#!/usr/bin/env bash
# Манифест состояния форка Leviculum, из которого собран бинарник.
# Форк правится в рабочем дереве (правка шифра Link по ADR 0016, кэш срока путей),
# поэтому в поставку кладём снимок: ревизия, список изменённых файлов и хеш diff.
# Без этого по готовому бинарнику нельзя сказать, что именно в него вошло (см. O3/F5 ревью).
set -euo pipefail
FORK="${LEVICULUM_FORK:-$HOME/dev/leviculum}"
OUT="${1:?нужен путь файла манифеста}"
{
  echo "fork=$FORK"
  echo "generated=$(date -u +%FT%TZ)"
  echo "head=$(git -C "$FORK" rev-parse HEAD 2>/dev/null || echo unknown)"
  echo "branch=$(git -C "$FORK" rev-parse --abbrev-ref HEAD 2>/dev/null || echo unknown)"
  echo "diff_sha256=$(git -C "$FORK" diff | sha256sum | cut -d' ' -f1)"
  # неотслеживаемые файлы git diff не видит: хешируем их содержимое отдельно
  echo "untracked_sha256=$(git -C "$FORK" ls-files --others --exclude-standard -z | (cd "$FORK" && xargs -0 -r sha256sum) | sha256sum | cut -d' ' -f1)"
  echo "changed_files:"
  git -C "$FORK" status --porcelain 2>/dev/null | sed 's/^/  /' || echo "  (недоступно)"
} > "$OUT"
echo "манифест форка: $OUT"
