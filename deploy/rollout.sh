#!/usr/bin/env bash
# Раскатка knothopd на узлы с контроллера (там, где есть ssh к узлам). Узлы по одному, на первой ошибке остановка.
#   rollout.sh status [метки]               read-only: хеш установленного бинарника, active, рестарты, glibc, есть ли старый rawgd-pilot
#   rollout.sh hostfix check [метки]        read-only: скрипт идёт через stdin, на узел ничего не пишется
#   rollout.sh stage [метки]                разложить knothopd.new, скрипты, юнит и nft в /root/knothop-stage/ (0700), сверить хеш; узлы не перезапускает
#   rollout.sh migrate [--dry-run] МЕТКА... одноразовая миграция rawgd -> knothop (node-migrate.sh): снять старое, поставить knothopd + persist, запустить; с откатом
#   rollout.sh install [--dry-run] МЕТКА... заменить бинарник с откатом (node-install.sh); метки обязательны, «все сразу» не бывает
#   rollout.sh hostfix apply|persist|revert МЕТКА...   (нужен stage: скрипт и nft берутся с узла)
# Список узлов - deploy/hosts.tsv, колонки через TAB:
#   метка | ssh-цель | вариант бинарника (knothopd | knothopd-u2204) | [опции ssh/scp, через пробел, напр. operator@host -o UserKnownHostsFile=/путь/known_hosts]
# Пользователь, не равный root (user@host), получает sudo -n для всего, что пишет в /root или меняет систему; загрузка идёт в ~/.knothopd-up/ и
# переносится под sudo. Опции из 4-й колонки ставятся ПЕРЕД умолчаниями (у ssh побеждает первое значение). Умолчания: BatchMode=yes,
# StrictHostKeyChecking=yes (без TOFU: ключ узла должен быть в known_hosts заранее).
# Ограничения: вариант только knothopd | knothopd-u2204; в 4-й колонке нельзя переопределять StrictHostKeyChecking и подменять known_hosts на /dev/null (закреплённый файл UserKnownHostsFile допустим)
# (файл known_hosts задаётся в ~/.ssh/config для Host узла). Действия: status|stage|install|hostfix check|apply|persist|revert|hostpolicy show|add-root.
# Артефакты - deploy/dist/ (deploy/build.sh); хеши сверяются с dist/SHA256SUMS. Приглашения и ключи скрипт не касается.
set -euo pipefail
HERE="$(cd "$(dirname "$0")" && pwd)"
DIST="$HERE/dist"
HOSTS="${HOSTS_FILE:-$HERE/hosts.tsv}"
RD="${RD_DIR:-/root/knothop-stage}"

[ -f "$HOSTS" ] || { echo "нет $HOSTS: скопируйте deploy/hosts.tsv.example и заполните"; exit 1; }
[ -f "$DIST/SHA256SUMS" ] || { echo "нет dist/SHA256SUMS: выполните deploy/build.sh"; exit 1; }

sum_of() { awk -v f="$1" '$2==f{print $1}' "$DIST/SHA256SUMS"; }
rows() { grep -vE '^\s*(#|$)' "$HOSTS"; }
pick() { # метки -> строки в порядке hosts.tsv
  if [ $# -eq 0 ]; then rows; else
    for l in "$@"; do rows | awk -F'\t' -v l="$l" '$1==l' | grep . || { echo "нет метки $l в $HOSTS" >&2; return 1; }; done
  fi
}

# Окружение текущего узла: OPTS (ssh/scp), SUDO, T (цель)
SSHB=(-o BatchMode=yes -o StrictHostKeyChecking=yes -o ConnectTimeout=15 -o ServerAliveInterval=10)
rsh() { ssh "${OPTS[@]}" "${SSHB[@]}" "$T" "$@" < /dev/null; }       # stdin закрыт: ssh не должен съедать список узлов
rsh_in() { ssh "${OPTS[@]}" "${SSHB[@]}" "$T" "$@"; }                 # stdin отдан вызывающему (скрипт через stdin)

each() { # fn метки...
  local fn=$1; shift
  while IFS=$'\t' read -r -u3 label target variant opts; do
    [ -n "$target" ] || { echo "== $label: пустая ssh-цель в $HOSTS"; exit 1; }
    case "$variant" in
      knothopd|knothopd-u2204) ;;
      *) echo "== $label: неизвестный вариант бинарника '$variant' (допустимо: knothopd | knothopd-u2204)"; exit 1 ;;
    esac
    # закреплённый файл ключей (UserKnownHostsFile=<файл>) допустим; отключать проверку ключа или подменять файл на /dev/null - нет
    if printf '%s\n' "${opts:-}" | grep -qiE 'StrictHostKeyChecking|UserKnownHostsFile=? *(/dev/null|none)\b|GlobalKnownHostsFile'; then
      echo "== $label: в колонке опций нельзя переопределять StrictHostKeyChecking или отключать known_hosts"; exit 1
    fi
    T=$target; V=$variant
    read -r -a OPTS <<< "${opts:-}"
    SUDO=""; case "$target" in root@*) ;; *@*) SUDO="sudo -n" ;; esac
    echo "== $label ($variant${SUDO:+, $SUDO})"   # адрес цели в вывод не пишем (правило: IP не печатать)
    "$fn" "$label" || { echo "!! $label: ошибка, раскатка остановлена"; exit 1; }
  done 3< <(pick "$@")
}

do_status() {
  local want; want=$(sum_of "$V")
  rsh 'h=$(sha256sum /opt/knothop/knothopd 2>/dev/null | cut -d" " -f1); echo "hash=$h active=$(systemctl is-active knothopd) restarts=$(systemctl show knothopd -p NRestarts --value) glibc=$(ldd --version | head -1 | grep -o "[0-9.]*$") legacy_rawgd=$(systemctl cat rawgd-pilot >/dev/null 2>&1 && echo present || echo absent)"' \
    | { read -r line; echo "   $line"; case "$line" in *"hash=$want"*) echo "   = актуальный ($V)";; *) echo "   != dist/$V (${want:0:8})";; esac; }
}

# MISS в отчёте - не сбой раскатки: обходим все узлы и только сообщаем (ошибкой считается недоступность узла, код 255 ssh)
do_check() { local rc=0; rsh_in "$SUDO bash -s -- check" < "$DIST/node-hostfix.sh" || rc=$?; [ "$rc" -ne 255 ] || return 255; [ "$rc" -eq 0 ] || echo "   (есть MISS: сверьте вручную, apply без разрешения владельца не выполнять)"; }

do_stage() {
  local want; want=$(sum_of "$V")
  # доставка одним потоком tar|ssh (без scp/sftp: на части узлов подсистемы sftp нет, а через -J scp обрывался), бинарник переименовывается в knothopd.new
  tar -C "$DIST" --transform "s/^$V\$/knothopd.new/" --transform 's#^public-rns-whitelist.txt$#public_rns.txt#' -czf - "$V" node-install.sh node-migrate.sh node-hostfix.sh knothop.nft knothopd.service SHA256SUMS \
    -C "$HERE/../deploy-0013" node.json \
    -C "$HERE" public-rns-whitelist.txt \
    | rsh_in "install -d -m 0700 ~/.knothopd-up && tar -xzf - -C ~/.knothopd-up"
  rsh "$SUDO install -d -m 0700 $RD && $SUDO cp ~/.knothopd-up/* $RD/ && $SUDO chmod 0755 $RD/node-install.sh $RD/node-migrate.sh $RD/node-hostfix.sh $RD/knothopd.new && rm -rf ~/.knothopd-up \
    && [ \"\$($SUDO sha256sum $RD/knothopd.new | cut -d' ' -f1)\" = $want ] && echo '   стаж готов, хеш совпал ${want:0:8}'"
}

DRY=""
do_install() {
  local want; want=$(sum_of "$V")
  do_stage "$@"
  rsh "$SUDO bash $RD/node-install.sh $want $DRY"
}

do_migrate() {
  local want; want=$(sum_of "$V")
  do_stage "$@"
  rsh "$SUDO bash $RD/node-migrate.sh $want $DRY"
}

CMD="${1:-}"; shift || true
case "$CMD" in
  status) each do_status "$@" ;;
  stage) each do_stage "$@" ;;
  install)
    [ "${1:-}" = "--dry-run" ] && { DRY="--dry-run"; shift; }
    [ $# -gt 0 ] || { echo "install: назовите узлы (метки) явно"; exit 64; }
    each do_install "$@" ;;
  migrate)
    [ "${1:-}" = "--dry-run" ] && { DRY="--dry-run"; shift; }
    [ $# -gt 0 ] || { echo "migrate: назовите узлы (метки) явно"; exit 64; }
    each do_migrate "$@" ;;
  hostfix)
    ACT="${1:?check|apply|persist|revert}"; shift
    case "$ACT" in
      check|apply|persist|revert) ;;
      *) echo "hostfix: неизвестное действие '$ACT' (допустимо: check | apply | persist | revert)"; exit 64 ;;
    esac
    if [ "$ACT" = check ]; then each do_check "$@"; else
      [ $# -gt 0 ] || { echo "hostfix $ACT: назовите узлы явно"; exit 64; }
      hf() { rsh "$SUDO bash $RD/node-hostfix.sh $ACT"; }
      each hf "$@"
    fi ;;
  hostpolicy)
    ACT="${1:?show|add-root}"; shift
    case "$ACT" in
      show) HP_ARGS="show" ;;
      add-root)
        # корень - публичный 32-hex хеш якоря; max_holders обязателен, чтобы не спутать его с меткой узла
        [[ "${1:-}" =~ ^[0-9A-Fa-f]{32}$ && "${2:-}" =~ ^[0-9]{1,3}$ ]] && (( 10#$2 >= 1 && 10#$2 <= 512 )) \
          || { echo "hostpolicy add-root: <32hex> <max_holders 1..512> узлы..."; exit 64; }
        HP_ARGS="add-root $1 $2"; shift 2
        [ $# -gt 0 ] || { echo "hostpolicy add-root: назовите узлы явно"; exit 64; } ;;
      *) echo "hostpolicy: неизвестное действие '$ACT' (допустимо: show | add-root)"; exit 64 ;;
    esac
    # Скрипт идёт по stdin из dist и сверяется с SHA256SUMS; служба не перезапускается (host-policy.json читается при старте).
    want=$(sum_of node-hostpolicy.sh); got=$(sha256sum "$DIST/node-hostpolicy.sh" 2>/dev/null | cut -d' ' -f1 || true)
    [ -n "$want" ] && [ "$want" = "$got" ] || { echo "dist/node-hostpolicy.sh отсутствует или не совпадает с SHA256SUMS: выполните deploy/build.sh"; exit 1; }
    hp() { rsh_in "$SUDO bash -s -- $HP_ARGS" < "$DIST/node-hostpolicy.sh"; }
    each hp "$@" ;;
  *) sed -n 2,16p "$0"; exit 64 ;;
esac
