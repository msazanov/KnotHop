#!/usr/bin/env bash
# Слияние апстрима Leviculum в наш форк. Вызывается из .github/workflows/leviculum-sync.yml; локально годится для сухого прогона
# на временном клоне (скрипт сам создаёт ветку и коммит слияния ТОЛЬКО в переданном каталоге, ничего не пушит).
#   leviculum-sync.sh prepare ФОРК_КАТАЛОГ   клон форка, HEAD = закреплённый коммит (deploy/leviculum.ref), история полная
#   leviculum-sync.sh body ФОРК_КАТАЛОГ      текст PR: что пришло из апстрима и какие чувствительные пути затронуты
# prepare печатает в stdout строки KEY=VALUE (их же дописывает в $GITHUB_OUTPUT):
#   state=uptodate|conflict|merged  upstream=<sha>  pin=<sha>  candidate=<sha, только merged>  branch=<имя, только merged>
#   conflicts=<файлы через запятую, только conflict>
# Апстрим - чужой код: слияние попадает в main только PR после ревью человеком. Автослияния нет: релиз раскатывается на узлы сам.
set -euo pipefail

UPSTREAM_URL="${UPSTREAM_URL:-https://codeberg.org/Lew_Palm/Leviculum}"
UPSTREAM_REF="${UPSTREAM_REF:-master}"
HERE="$(cd "$(dirname "$0")" && pwd)"
SENSITIVE='crypto|aes|gcm|token|hkdf|ratchet|identity|signature|ed25519|x25519|link_management|packet\.rs'

emit() { printf '%s\n' "$1"; [ -z "${GITHUB_OUTPUT:-}" ] || printf '%s\n' "$1" >> "$GITHUB_OUTPUT"; }

prepare() {
  local dir=$1 pin up merge_msg branch
  pin="$(tr -d '[:space:]' < "$HERE/leviculum.ref")"
  [[ $pin =~ ^[0-9a-f]{40}$ ]] || { echo "deploy/leviculum.ref: нужен полный SHA-1" >&2; return 1; }
  cd "$dir"
  [ "$(git rev-parse HEAD)" = "$pin" ] || { echo "HEAD форка не равен закреплённому $pin" >&2; return 1; }
  [ -z "$(git status --porcelain)" ] || { echo "рабочее дерево форка не чистое" >&2; return 1; }
  git remote get-url upstream >/dev/null 2>&1 || git remote add upstream "$UPSTREAM_URL"
  git fetch --quiet --no-tags upstream "$UPSTREAM_REF"
  up="$(git rev-parse FETCH_HEAD)"
  emit "pin=$pin"; emit "upstream=$up"
  if git merge-base --is-ancestor "$up" "$pin"; then emit "state=uptodate"; return 0; fi
  branch="knothop/upstream-$(date -u +%Y%m%d)-${up:0:8}"
  git switch --quiet -c "$branch"
  merge_msg="Слияние апстрима Leviculum ${up:0:12} в knothop"
  if git -c user.name="knothop-sync" -c user.email="knothop-sync@users.noreply.github.com" merge --no-ff --no-edit -m "$merge_msg" "$up" >/dev/null 2>&1; then
    emit "state=merged"; emit "candidate=$(git rev-parse HEAD)"; emit "branch=$branch"
  else
    local files; files="$(git diff --name-only --diff-filter=U | paste -sd, -)"
    git merge --abort 2>/dev/null || true
    emit "state=conflict"; emit "conflicts=${files}"
  fi
}

body() {
  local dir=$1 pin up
  pin="$(tr -d '[:space:]' < "$HERE/leviculum.ref")"
  cd "$dir"
  up="$(git rev-parse FETCH_HEAD)"   # тот же каталог, что и после prepare: FETCH_HEAD = целевой коммит апстрима
  echo "Закреплённый форк: \`${pin:0:12}\`; апстрим: \`${up:0:12}\`."
  echo
  echo "Коммитов апстрима, которых нет в форке: $(git rev-list --count "$pin..$up")."
  echo "Изменения апстрима относительно форка: $(git diff --shortstat "$pin" "$up" 2>/dev/null)"
  echo
  echo "Затронутые чувствительные пути (крипто, Link, пакеты, идентичность): прочитать диф глазами до слияния."
  echo '```'
  git diff --name-only "$pin" "$up" | grep -Ei "$SENSITIVE" | head -40 || true
  echo '```'
  echo
  echo "Это слияние чужого кода. После попадания в main и ручного запуска CI релиз раскатывается на узлы сам, откат - удалить релиз."
}

case "${1:-}" in
  prepare) prepare "${2:?каталог форка}" ;;
  body) body "${2:?каталог форка}" ;;
  *) sed -n 2,10p "$0"; exit 64 ;;
esac
