#!/usr/bin/env bash
# Автообновление knothopd на узле пилота из последнего релиза GitHub (решение владельца 27.10: только бинарник, без копий,
# проверка только по SHA256SUMS релиза, узлы обновляются сразу после публикации с небольшим джиттером).
# Запускается от root. Копия лежит в /opt/knothop/knothop-autoupdate.sh, таймер вызывает `run`.
#   run               один проход: сверить SHA256SUMS с установленным бинарником, при отличии скачать, проверить, заменить, перезапустить knothopd
#   install ВАРИАНТ   поставить юнит и таймер (ВАРИАНТ: knothopd | knothopd-u2204); службу knothopd не трогает
#   remove            снять таймер и юнит; бинарник и службу не трогает
#   status            read-only: таймер, хеши, доступность GitHub
# Остановить: touch /opt/knothop/autoupdate.disabled; или пометить релиз prerelease/draft (`releases/latest` его не отдаёт).
# Откат плохого релиза: удалить его на GitHub; latest укажет на прошлый, узлы вернутся сами. Копий бинарника на узле нет.
set -uo pipefail

REPO=msazanov/KnotHop
BASE="https://github.com/$REPO/releases/latest/download"
DIR=/opt/knothop BIN=/opt/knothop/knothopd UNIT=knothopd
SELF=/opt/knothop/knothop-autoupdate.sh
TMP="$DIR/.knothopd.autoupdate.new" LOCK="$DIR/.knothop-autoupdate.lock" OFF="$DIR/autoupdate.disabled"
SVC=/etc/systemd/system/knothop-autoupdate.service TMR=/etc/systemd/system/knothop-autoupdate.timer
MAX_BIN=125829120   # 120 МиБ: потолок скачивания (бинарники ≈41–43 МиБ)

log() { printf 'knothop-autoupdate: %s\n' "$*"; }
sha() { sha256sum "$1" 2>/dev/null | awk '{print $1}'; }
fetch() { # URL ФАЙЛ МАКС_БАЙТ МАКС_СЕК; только https, проверка сертификата, ограниченные редиректы
  curl --fail --silent --show-error --location --proto '=https' --proto-redir '=https' --tlsv1.2 \
    --max-redirs 5 --connect-timeout 15 --max-time "$4" --max-filesize "$3" -o "$2" "$1"
}
want_from_sums() { # SUMS ВАРИАНТ: ровно одна строка с нужным именем и корректный sha256
  local w; w=$(awk -v f="$2" '$2==f{print $1}' "$1")
  [[ $w =~ ^[0-9a-f]{64}$ && $(awk -v f="$2" '$2==f' "$1" | wc -l) -eq 1 ]] || return 1
  printf '%s' "$w"
}

variant_ok() { [[ ${1:-} == knothopd || ${1:-} == knothopd-u2204 ]]; }

# SA-20: защита от отката. Версия бинарника в нём не зашита (`--version` нет), поэтому берём тег релиза из редиректа
# `releases/latest` (vX.Y.Z) и помним последний установленный тег в $VERFILE; тег старее запомненного — отказ.
VERFILE="$DIR/autoupdate.version"
latest_tag() { # печатает vX.Y.Z или ничего
  local u; u=$(curl --silent --proto '=https' --tlsv1.2 --connect-timeout 15 --max-time 30 -o /dev/null -w '%{redirect_url}' "https://github.com/$REPO/releases/latest") || return 1
  [[ $u =~ /releases/tag/(v[0-9]+\.[0-9]+\.[0-9]+)$ ]] && printf '%s' "${BASH_REMATCH[1]}"
}
ver_older() { # A B: истина, если A строго старее B (sort -V)
  [[ $1 != "$2" && $(printf '%s\n%s\n' "$1" "$2" | sort -V | head -n1) == "$1" ]]
}
tag_exists() { # vX.Y.Z: 0 — релиз есть, 1 — удалён (404), 2 — неизвестно (сеть)
  local c; c=$(curl --silent --proto '=https' --tlsv1.2 --connect-timeout 15 --max-time 30 -o /dev/null -w '%{http_code}' "https://github.com/$REPO/releases/tag/$1") || return 2
  case $c in 200) return 0 ;; 404) return 1 ;; *) return 2 ;; esac
}

cmd_run() {
  [[ $EUID -eq 0 ]] || { log "нужен root"; return 1; }
  variant_ok "${KH_VARIANT:-}" || { log "KH_VARIANT не задан или неверен"; return 1; }
  [[ -e $OFF ]] && { log "отключено ($OFF)"; return 0; }
  exec 9>"$LOCK"; flock -n 9 || { log "другой проход уже идёт"; return 0; }
  local sums want have got restarts0 tag prev
  sums=$(mktemp -p "$DIR" .autoupdate-sums.XXXXXX) || return 1
  SUMS_FILE=$sums   # trap EXIT срабатывает уже после выхода из функции: локальная переменная к тому времени недоступна
  trap 'rm -f "${SUMS_FILE:-}" "$TMP"' EXIT
  fetch "$BASE/SHA256SUMS" "$sums" 4096 30 || { log "SHA256SUMS недоступен, повтор позже"; return 1; }
  want=$(want_from_sums "$sums" "$KH_VARIANT") || { log "в SHA256SUMS нет единственной строки для $KH_VARIANT"; return 1; }
  have=$(sha "$BIN")
  if [[ $want == "$have" ]]; then
    # ручной запуск печатает одну строку; запуск таймером/юнитом (systemd задаёт INVOCATION_ID) молчит
    [[ -n ${INVOCATION_ID:-} ]] || log "актуально: ${want:0:12}"
    [[ -s $VERFILE ]] || { tag=$(latest_tag) && printf '%s\n' "$tag" >"$VERFILE"; } || true   # SA-20: первая отметка версии на актуальном узле
    return 0
  fi
  # SA-20: только вперёд. Тег не определился — отказ (fail-closed); тег старее последнего установленного — отказ с записью в журнал.
  tag=$(latest_tag) || tag=
  [[ -n $tag ]] || { log "не удалось определить тег latest, обновление отложено (защита от отката)"; return 1; }
  prev=$(head -c 64 "$VERFILE" 2>/dev/null | tr -d '[:space:]')
  if [[ $prev =~ ^v[0-9]+\.[0-9]+\.[0-9]+$ ]] && ver_older "$tag" "$prev"; then
    # штатный откат владельца — удалить плохой релиз на GitHub (AGENTS.md): тогда установленный тег исчез и откат разрешён;
    # если релиз $prev на месте, «latest» старее него — подмена или ошибка, не ставим
    tag_exists "$prev"; case $? in
      1) log "релиз $prev удалён: откат на $tag разрешён" ;;
      0) log "ОТКАЗ: latest=$tag старее установленного $prev, а релиз $prev существует — откат не ставлю (SA-20)"; return 1 ;;
      *) log "не удалось проверить релиз $prev, обновление отложено"; return 1 ;;
    esac
  fi
  BASE="https://github.com/$REPO/releases/download/$tag"   # тег фиксируем: SHA256SUMS и бинарник из одного релиза
  fetch "$BASE/SHA256SUMS" "$sums" 4096 30 || { log "SHA256SUMS $tag недоступен, повтор позже"; return 1; }
  want=$(want_from_sums "$sums" "$KH_VARIANT") || { log "в SHA256SUMS $tag нет единственной строки для $KH_VARIANT"; return 1; }
  [[ $want == "$have" ]] && { printf '%s\n' "$tag" >"$VERFILE"; return 0; }
  log "установлен ${have:0:12} (последний тег ${prev:-неизвестен}), в релизе $tag ${want:0:12}: обновляю $KH_VARIANT"
  rm -f "$TMP"
  fetch "$BASE/$KH_VARIANT" "$TMP" "$MAX_BIN" 900 || { log "скачивание не удалось"; return 1; }
  got=$(sha "$TMP")
  [[ $got == "$want" ]] || { log "хеш скачанного ${got:0:12} != $want (релиз мог смениться в процессе), повтор позже"; return 1; }
  chmod 0755 "$TMP"; chown --reference="$BIN" "$TMP" 2>/dev/null || chown root:root "$TMP"
  # Дымовая проверка: бинарник должен хотя бы запускаться (повреждение, не тот glibc). Это не копия и не откат.
  timeout 20 "$TMP" --help >/dev/null 2>&1 || { log "новый бинарник не запускается (--help), замена отменена"; return 1; }
  sync -f "$TMP" 2>/dev/null || sync
  restarts0=$(systemctl show "$UNIT" -p NRestarts --value 2>/dev/null || echo 0)
  mv -f "$TMP" "$BIN" || { log "mv не удался"; return 1; }
  systemctl restart "$UNIT" || log "ВНИМАНИЕ: systemctl restart вернул ошибку"
  for _ in $(seq 1 18); do
    sleep 5
    if [[ $(systemctl is-active "$UNIT") == active && $(sha "/proc/$(systemctl show "$UNIT" -p MainPID --value)/exe") == "$want" ]]; then
      printf '%s\n' "$tag" >"$VERFILE"   # SA-20: запомнить установленный тег
      log "готово: $tag ${want:0:12}, служба active (рестартов с замены: $(( $(systemctl show "$UNIT" -p NRestarts --value) - restarts0 )))"
      return 0
    fi
  done
  log "ОШИБКА: после замены на ${want:0:12} служба не active за 90 с. Копий нет: удалите релиз на GitHub (latest вернётся к прошлому) или поставьте бинарник вручную"
  return 1
}

cmd_install() {
  [[ $EUID -eq 0 ]] || { echo "нужен root"; return 1; }
  variant_ok "${1:-}" || { echo "install: вариант knothopd | knothopd-u2204"; return 1; }
  [[ -x $SELF && -d $DIR ]] || { echo "install: нет $SELF или $DIR (сначала положите скрипт)"; return 1; }
  for t in curl sha256sum flock systemctl timeout; do command -v "$t" >/dev/null || { echo "install: нет $t"; return 1; }; done
  cat >"$SVC.new" <<EOF
[Unit]
Description=KnotHop pilot: обновление knothopd из релиза GitHub
Wants=network-online.target
After=network-online.target

[Service]
Type=oneshot
Environment=KH_VARIANT=$1
ExecStart=$SELF run
TimeoutStartSec=20min
Nice=10
CPUWeight=20
ProtectSystem=strict
ReadWritePaths=$DIR
ProtectHome=yes
PrivateTmp=yes
NoNewPrivileges=yes
EOF
  cat >"$TMR.new" <<'EOF'
[Unit]
Description=KnotHop pilot: проверка новой версии knothopd

[Timer]
OnBootSec=5min
OnUnitInactiveSec=10min
RandomizedDelaySec=90
AccuracySec=10s

[Install]
WantedBy=timers.target
EOF
  mv -f "$SVC.new" "$SVC" && mv -f "$TMR.new" "$TMR" || return 1
  systemctl daemon-reload && systemctl enable --now knothop-autoupdate.timer
  echo "автообновление установлено ($1)"
}

cmd_remove() {
  [[ $EUID -eq 0 ]] || { echo "нужен root"; return 1; }
  systemctl disable --now knothop-autoupdate.timer 2>/dev/null
  rm -f "$SVC" "$TMR" "$SELF"; systemctl daemon-reload; echo "автообновление снято"
}

cmd_status() {
  local v sums want have
  v=$(systemctl show knothop-autoupdate.service -p Environment --value 2>/dev/null | sed -n 's/.*KH_VARIANT=\([A-Za-z0-9_-]*\).*/\1/p')
  echo "таймер: $(systemctl is-enabled knothop-autoupdate.timer 2>&1) / $(systemctl is-active knothop-autoupdate.timer 2>&1); вариант: ${v:-нет}; стоп-файл: $([[ -e $OFF ]] && echo есть || echo нет)"
  echo "knothopd: $(systemctl is-active $UNIT), рестартов $(systemctl show $UNIT -p NRestarts --value)"
  sums=$(mktemp) || return 1
  if fetch "$BASE/SHA256SUMS" "$sums" 4096 30; then
    want=$(want_from_sums "$sums" "${v:-knothopd}") || want=
    have=$(sha "$BIN")
    echo "github: доступен; релиз ${want:0:12}, установлен ${have:0:12} $([[ -n $want && $want == "$have" ]] && echo '(совпадает)' || echo '(отличается)')"
  else
    echo "github: SHA256SUMS НЕДОСТУПЕН с этого узла"
  fi
  rm -f "$sums"
  journalctl -u knothop-autoupdate.service --no-pager -n 3 -o cat 2>/dev/null | sed 's/^/  журнал: /'
}

case "${1:-}" in
  run) cmd_run ;;
  install) shift; cmd_install "$@" ;;
  remove) cmd_remove ;;
  status) cmd_status ;;
  *) sed -n 2,10p "$0"; exit 64 ;;
esac
