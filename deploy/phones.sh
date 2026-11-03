#!/usr/bin/env bash
# Телефоны KnotHop по adb (state=device): раскатка APK, включение VPN, проверка.
#   deploy/phones.sh install [APK|--latest]   APK из аргумента или последний релиз GitHub (knothop.apk + SHA256SUMS, только https)
#   deploy/phones.sh status                   versionCode и режим VPN (UI «VPN включён» + tun); HTTP-проба с телефона — не доказательство egress
#   deploy/phones.sh vpn-on [SERIAL...]       включить VPN свайпом по SeekBar режима (по умолчанию все телефоны), ждать до 30 с
# Успех vpn-on = режим «VPN включён» в UI И интерфейс tunN; текст «выход: …» (соединение с выходом) успехом не считается.
# Телефон не в state=device (offline/unauthorized) — ошибка install/status/vpn-on, а не тихий пропуск.
# adb install -r рвёт туннель; после установки VPN включается вручную или vpn-on. Лабораторные интенты (KNOTHOP_LAB) не используются.
# Сквозная проверка (ping, netprobe, узлы): deploy/live-check.sh.
set -euo pipefail

PKG=com.knothop.vpn
REPO=msazanov/KnotHop
BASE="https://github.com/$REPO/releases/latest/download"
ASSET=knothop.apk
IP_HOST=ifconfig.me
UI_FILE=/sdcard/knothop_ui.xml
APK_MAX=$((120 * 1024 * 1024))
SUMS_MAX=$((64 * 1024))
# Ожидание UI после свайпа; PHONES_UI_SETTLE/PHONES_UI_POLL_TRIES переопределяют только mock-тесты.
SETTLE=${PHONES_UI_SETTLE:-3}
TRIES=${PHONES_UI_POLL_TRIES:-10}

TMPDIR_KH=""
APK_PATH=""
DEVICES=()
SKIPPED=0
VPN_OK=0
VPN_TEXT=""
cleanup() { if [ -n "$TMPDIR_KH" ]; then rm -rf -- "$TMPDIR_KH"; fi; }
trap cleanup EXIT

die() { echo "phones: $*" >&2; exit 1; }

note() { echo "phones: $*" >&2; }

need() { command -v "$1" >/dev/null 2>&1 || die "нет программы: $1"; }

usage() {
  sed -n '2,9p' "$0" | sed 's/^# \{0,1\}//'
}

# adb shell с закрытым stdin: без этого shell в цикле съедает остаток списка.
ad() { local s=$1; shift; adb -s "$s" shell "$@" </dev/null; }

sha_of() { sha256sum "$1" | awk '{print $1}'; }

# Список телефонов в state=device (DEVICES) и число пропущенных (SKIPPED: offline/unauthorized и т.п.).
# Работает в текущем shell (не в подстановке), поэтому SKIPPED виден вызывающему; stdin не читает.
refresh_devices() {
  DEVICES=()
  SKIPPED=0
  local out line serial state
  out=$(adb devices 2>&1) || die "adb devices завершился ошибкой"
  while IFS= read -r line; do
    line=${line%$'\r'}
    [ -n "$line" ] || continue
    case "$line" in
      "List of devices attached"*|"adb server"*|"*"*) continue ;;
    esac
    read -r serial state _ <<<"$line"
    [ -n "${serial:-}" ] || continue
    if [ "${state:-}" = device ]; then
      DEVICES+=("$serial")
    else
      note "пропущен $serial (state=${state:-?}): разблокируйте телефон/разрешите отладку и повторите"
      SKIPPED=$((SKIPPED + 1))
    fi
  done <<<"$out"
}

# Скачивание только по https, в том числе редиректы; потолок размера и времени.
curl_get() { # URL ФАЙЛ МАКС_БАЙТ МАКС_СЕК
  curl -fsSL --proto '=https' --proto-redir '=https' --tlsv1.2 --max-redirs 5 \
    --connect-timeout 15 --max-time "$4" --max-filesize "$3" -o "$2" "$1"
}

# Скачивает knothop.apk и SHA256SUMS последнего релиза в TMPDIR_KH и сверяет sha256.
# Результат — глобальная APK_PATH. Скачанный файл не исполняется: им занимается только adb install.
fetch_latest() {
  need curl
  need sha256sum
  TMPDIR_KH=$(mktemp -d)
  curl_get "$BASE/SHA256SUMS" "$TMPDIR_KH/SHA256SUMS" "$SUMS_MAX" 60 \
    || die "SHA256SUMS недоступен: $BASE/SHA256SUMS"
  curl_get "$BASE/$ASSET" "$TMPDIR_KH/$ASSET" "$APK_MAX" 300 \
    || die "$ASSET недоступен: $BASE/$ASSET"
  local want got count
  want=$(awk -v f="$ASSET" '$2 == f || $2 == "*" f {print $1}' "$TMPDIR_KH/SHA256SUMS")
  count=$(printf '%s\n' "$want" | grep -c . || true)
  [ "$count" = 1 ] || die "в SHA256SUMS нет единственной строки для $ASSET"
  got=$(sha_of "$TMPDIR_KH/$ASSET")
  [ "$want" = "$got" ] || die "sha256 $ASSET не совпал с SHA256SUMS (ожидали $want, получили $got)"
  echo "релиз: sha256 $ASSET совпал с SHA256SUMS ($got)"
  APK_PATH="$TMPDIR_KH/$ASSET"
}

# versionCode / versionName установленного пакета; пусто, если пакета нет или adb не ответил.
pkg_field() {
  local s=$1 key=$2 v
  v=$(adb -s "$s" shell dumpsys package "$PKG" 2>/dev/null </dev/null | tr -d '\r' \
      | sed -n "s/.*${key}=\([^ ]*\).*/\1/p" | head -n1) || true
  printf '%s' "$v"
}

# Число интерфейсов tunN в `ip -o link`; пусто, если adb не ответил (не путать с «0 tun»).
tun_count() {
  local out
  out=$(ad "$1" 'ip -o link 2>/dev/null') || return 1
  grep -cE '^[0-9]+: tun[0-9]+[:@]' <<<"$out" || true
}

# Свежий дамп текущего окна. Файл на телефоне удаляется до дампа, а cat читается только после
# успешного dump: старый /sdcard/knothop_ui.xml не может выдать себя за текущий экран.
ui_dump() {
  local i xml
  for i in 1 2; do
    ad "$1" rm -f "$UI_FILE" >/dev/null 2>&1 || true
    if ad "$1" uiautomator dump "$UI_FILE" >/dev/null 2>&1; then
      xml=$(ad "$1" cat "$UI_FILE" 2>/dev/null | tr -d '\r') || true
      if [ -n "$xml" ]; then printf '%s' "$xml"; return 0; fi
    fi
    sleep 1
  done
  return 1
}

# Пакет верхнего окна, если нашего приложения в дампе нет (блокирующий диалог/чужое окно).
# Возвращает 1, когда в дампе есть наше приложение.
foreign_pkg() {
  if grep -q "package=\"$PKG\"" <<<"$1"; then return 1; fi
  grep -oE 'package="[^"]+"' <<<"$1" | sed -e 's/^package="//' -e 's/"$//' | head -n1
}

# Режим по панели режима: off | network | vpn | blocked | unknown. «выход: …» — соединение, не режим VPN.
ui_mode() {
  if grep -qF 'text="VPN не работает, трафик заблокирован' <<<"$1"; then echo blocked
  elif grep -qF 'text="VPN включён' <<<"$1"; then echo vpn
  elif grep -qF 'text="В сети нод, без VPN' <<<"$1"; then echo network
  elif grep -qF 'text="Отключено' <<<"$1"; then echo off
  else echo unknown; fi
}

# Строки экрана со статусом соединения (для терминала; IPv4 маскируется).
ui_info() {
  grep -oE 'text="[^"]{2,200}"' <<<"$1" | sed -e 's/^text="//' -e 's/"$//' \
    | grep -E 'выход|носитель|VPN' | head -n4 \
    | sed -E 's/([0-9]{1,3}\.){3}[0-9]{1,3}/<ip>/g' | sed 's/^/    /' || true
}

# Границы первого узла UI, в котором есть шаблон (grep -F): печатает «x1 y1 x2 y2».
# Возвращает 1 для отсутствующего узла и для bounds, из которых нельзя получить корректный прямоугольник.
bounds_of() {
  local node raw x1 y1 x2 y2
  node=$(grep -oE '<node [^>]*>' <<<"$1" | grep -F -- "$2" | head -n1) || true
  [ -n "$node" ] || return 1
  raw=$(grep -oE 'bounds="\[[0-9]+,[0-9]+\]\[[0-9]+,[0-9]+\]"' <<<"$node" | head -n1 \
        | grep -oE '[0-9]+' | tr '\n' ' ') || true
  [ -n "$raw" ] || return 1
  read -r x1 y1 x2 y2 <<<"$raw"
  [[ ${x1:-} =~ ^[0-9]+$ && ${y1:-} =~ ^[0-9]+$ && ${x2:-} =~ ^[0-9]+$ && ${y2:-} =~ ^[0-9]+$ ]] || return 1
  [ "$x2" -gt "$x1" ] && [ "$y2" -gt "$y1" ] || return 1
  printf '%s %s %s %s' "$x1" "$y1" "$x2" "$y2"
}

# Системный диалог разрешения уведомлений (permissioncontroller, кнопка «Разрешить»): закрыть тапом по bounds.
# Другие системные диалоги (VPN consent, приглашения) не трогаем: о них сообщает vpn_on_one.
dismiss_notif() {
  local s=$1 xml b x1 y1 x2 y2
  xml=$(ui_dump "$s") || return 0
  grep -q 'package="com.google.android.permissioncontroller"' <<<"$xml" || return 0
  b=$(bounds_of "$xml" 'text="Разрешить"') || return 0
  read -r x1 y1 x2 y2 <<<"$b"
  ad "$s" input tap $(( (x1 + x2) / 2 )) $(( (y1 + y2) / 2 )) || true
  echo "  закрыт системный диалог разрешения уведомлений"
  sleep 2
}

# Состояние для status: tun + режим из UI. Глобальные VPN_OK (1 — режим VPN и tun>0) и VPN_TEXT.
vpn_state() {
  local s=$1 tun xml mode
  VPN_OK=0
  if ! tun=$(tun_count "$s"); then VPN_TEXT='adb не ответил (offline/unauthorized?)'; return; fi
  if [ "$tun" = 0 ]; then VPN_TEXT='выключен (нет tun)'; return; fi
  if ! xml=$(ui_dump "$s"); then VPN_TEXT="tun=$tun, UI недоступен"; return; fi
  mode=$(ui_mode "$xml")
  case "$mode" in
    vpn) VPN_OK=1; VPN_TEXT="включён (режим VPN, tun=$tun)" ;;
    network) VPN_TEXT="tun=$tun, режим «Сеть» — не VPN" ;;
    blocked) VPN_TEXT="VPN не работает, трафик заблокирован (tun=$tun)" ;;
    off) VPN_TEXT="tun=$tun, приложение показывает «Отключено»" ;;
    *) VPN_TEXT="tun=$tun, режим по UI не определён" ;;
  esac
}

# Доступен ли toybox nc на телефоне (иначе HTTP-проба бессмысленна).
has_nc() { ad "$1" toybox 2>/dev/null | tr -d '\r' | tr ' ' '\n' | grep -qx nc; }

# HTTP-проба с телефона: адрес выхода скрыт, возвращается только «получен/нет ответа/…».
# Это проверка доступности HTTP, не доказательство того, что трафик ушёл через выход KnotHop.
external_ip() {
  local cmd out ip
  if ! has_nc "$1"; then printf 'nc недоступен'; return; fi
  cmd="(printf 'GET / HTTP/1.0\\r\\nHost: $IP_HOST\\r\\nConnection: close\\r\\n\\r\\n'; sleep 2) | toybox nc -w 5 $IP_HOST 80"
  out=$(timeout 20 adb -s "$1" shell "$cmd" 2>/dev/null </dev/null | tr -d '\r') || true
  ip=$(grep -oE '^[[:space:]]*([0-9]{1,3}\.){3}[0-9]{1,3}[[:space:]]*$' <<<"$out" | tail -n1 | tr -d ' \t') || true
  if [ -n "$ip" ]; then printf 'получен'; else printf 'нет ответа'; fi
}

cmd_install() {
  need adb
  local src=${1:---latest} apk
  if [ "$src" = "--latest" ]; then
    fetch_latest
    apk=$APK_PATH
  else
    [ -f "$src" ] || die "нет файла: $src"
    apk=$src
    echo "APK: $apk sha256=$(sha_of "$apk")"
  fi

  refresh_devices
  [ "${#DEVICES[@]}" -gt 0 ] || die "нет телефонов в состоянии device (проверьте adb devices)"
  echo "телефонов: ${#DEVICES[@]}"
  [ "$SKIPPED" = 0 ] || note "пропущено телефонов: $SKIPPED"

  local s before after out fail=0
  for s in "${DEVICES[@]}"; do
    before=$(pkg_field "$s" versionCode)
    out=$(timeout 300 adb -s "$s" install -r "$apk" 2>&1 </dev/null) || true
    if ! grep -q '^Success' <<<"$out"; then
      echo "$s: установка НЕ выполнена: $(tail -n3 <<<"$out" | tr -d '\r')"
      fail=1
      continue
    fi
    after=$(pkg_field "$s" versionCode)
    if [ -z "$after" ]; then
      echo "$s: Success, но $PKG не найден после установки"
      fail=1
      continue
    fi
    echo "$s: установлено; versionCode ${before:-нет} -> $after, versionName $(pkg_field "$s" versionName)"
  done

  echo "ВНИМАНИЕ: туннель после установки оборван. Включите VPN: deploy/phones.sh vpn-on (или кнопкой в приложении),"
  echo "затем проверьте: deploy/phones.sh status"
  if [ "$SKIPPED" != 0 ]; then fail=1; fi
  [ "$fail" = 0 ] || { echo "phones: есть телефоны с ошибкой установки или пропущенные" >&2; exit 1; }
}

# Включение VPN одного телефона. Успех — только режим «VPN включён» в UI и tun>0.
vpn_on_one() {
  local s=$1 xml mode tun b x1 y1 x2 y2 cy w i pkg
  echo "== $s"
  if ! tun=$(tun_count "$s"); then
    echo "  adb не ответил (offline/unauthorized?): проверьте adb devices"; return 1
  fi
  ad "$s" input keyevent KEYCODE_WAKEUP || true
  ad "$s" am start -W -n "$PKG/.MainActivity" >/dev/null 2>&1 || true
  sleep "$SETTLE"
  dismiss_notif "$s"
  if ! xml=$(ui_dump "$s"); then
    echo "  не удалось получить свежий UI (экран заблокирован или uiautomator не отвечает)"; return 1
  fi
  if pkg=$(foreign_pkg "$xml"); then
    echo "  блокирующее окно (${pkg:-неизвестный пакет}): подтвердите вручную и повторите"; return 1
  fi
  mode=$(ui_mode "$xml")
  if [ "$mode" = blocked ]; then
    echo "  приложение сообщает «VPN не работает, трафик заблокирован»: сдвиньте ползунок влево вручную и повторите"
    return 1
  fi
  if [ "$mode" = vpn ] && [ "$tun" -gt 0 ]; then
    echo "  VPN уже включён: режим «VPN включён», tun=$tun"
    ui_info "$xml"
    return 0
  fi
  if [ "$mode" = vpn ]; then
    echo "  режим «VPN включён», но tun не появился: жду"
  else
    if ! b=$(bounds_of "$xml" 'class="android.widget.SeekBar"'); then
      echo "  SeekBar режима не найден или bounds некорректны (откройте KnotHop вручную)"; return 1
    fi
    read -r x1 y1 x2 y2 <<<"$b"
    w=$(( x2 - x1 ))
    if [ "$w" -lt 120 ]; then
      echo "  SeekBar слишком узкий ($w px): включите VPN вручную"; return 1
    fi
    cy=$(( (y1 + y2) / 2 ))
    # свайп от левой части SeekBar к правой: край экрана не трогаем (MIUI принимает его за «назад/домой»)
    ad "$s" input swipe $(( x1 + w / 4 )) "$cy" $(( x1 + w * 9 / 10 )) "$cy" 500 || true
  fi
  i=0
  while [ "$i" -lt "$TRIES" ]; do
    i=$((i + 1))
    sleep "$SETTLE"
    if ! tun=$(tun_count "$s"); then
      echo "  adb перестал отвечать (offline?)"; return 1
    fi
    if ! xml=$(ui_dump "$s"); then continue; fi
    if pkg=$(foreign_pkg "$xml"); then
      echo "  блокирующее окно (${pkg:-неизвестный пакет}): подтвердите вручную и повторите"; return 1
    fi
    mode=$(ui_mode "$xml")
    if [ "$mode" = blocked ]; then
      echo "  приложение сообщает «VPN не работает, трафик заблокирован»: сдвиньте ползунок влево вручную"
      return 1
    fi
    if [ "$mode" = vpn ] && [ "$tun" -gt 0 ]; then break; fi
  done
  echo "  режим: $mode, tun=$tun"
  ui_info "$xml"
  if [ "$mode" = vpn ] && [ "$tun" -gt 0 ]; then
    echo "  VPN подтверждён: режим «VPN включён» и tun=$tun"
    return 0
  fi
  echo "  VPN НЕ подтверждён за $((TRIES * SETTLE)) с (нужны режим «VPN включён» и tun>0)"
  return 1
}

cmd_vpn_on() {
  need adb
  refresh_devices
  local -a want=()
  local s fail=0
  if [ $# -gt 0 ]; then
    # явный список кодом не портят пропуски посторонних телефонов: отвечает только выбранный
    for s in "$@"; do
      if printf '%s\n' "${DEVICES[@]}" | grep -qxF -- "$s"; then
        want+=("$s")
      else
        note "нет $s в состоянии device (offline/unauthorized?)"
        fail=1
      fi
    done
  else
    want=("${DEVICES[@]}")
    [ "$SKIPPED" = 0 ] || fail=1
  fi
  [ "${#want[@]}" -gt 0 ] || die "нет телефонов в состоянии device (проверьте adb devices)"
  for s in "${want[@]}"; do
    vpn_on_one "$s" || fail=1
  done
  [ "$fail" = 0 ] || { echo "phones: VPN не подтверждён на части телефонов (или телефон пропущен)" >&2; exit 1; }
}

cmd_status() {
  need adb
  refresh_devices
  [ "${#DEVICES[@]}" -gt 0 ] || die "нет телефонов в состоянии device (проверьте adb devices)"
  local s model vc vn ipnote fail=0
  for s in "${DEVICES[@]}"; do
    model=$(timeout 15 adb -s "$s" shell getprop ro.product.model 2>/dev/null </dev/null | tr -d '\r') || true
    vc=$(pkg_field "$s" versionCode)
    if [ -z "$model" ] && [ -z "$vc" ]; then
      echo "$s: нет ответа adb (offline/unauthorized?)"
      fail=1
      continue
    fi
    if [ -z "$vc" ]; then
      echo "$s ${model:-?}: $PKG не установлен"
      continue
    fi
    vn=$(pkg_field "$s" versionName)
    vpn_state "$s"
    ipnote=""
    if [ "$VPN_OK" = 1 ]; then
      ipnote=" HTTP80(с телефона, не доказательство egress)=$(external_ip "$s")"
    fi
    echo "$s ${model:-?}: versionCode=$vc versionName=$vn VPN=$VPN_TEXT$ipnote"
  done
  [ "$SKIPPED" = 0 ] || { note "пропущено телефонов: $SKIPPED"; fail=1; }
  [ "$fail" = 0 ] || exit 1
}

case "${1:-}" in
  install) shift; cmd_install "${1:---latest}" ;;
  status) cmd_status ;;
  vpn-on) shift; cmd_vpn_on "$@" ;;
  -h|--help|help|"") usage ;;
  *) usage >&2; exit 2 ;;
esac
