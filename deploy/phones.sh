#!/usr/bin/env bash
# Раскатка APK KnotHop на все телефоны, подключённые по adb (state=device), и проверка после неё.
#   deploy/phones.sh install [APK|--latest]  APK из аргумента или последний релиз GitHub (knothop.apk + SHA256SUMS)
#   deploy/phones.sh status                  versionCode, признак VPN, внешний IP через туннель
# Установка: adb install -r (данные, профиль и зачисления сохраняются; понижение версии adb отвергнет, -d не используется).
# adb install -r рвёт работающий туннель: после установки VPN включается кнопкой в приложении.
# Лабораторные интенты (KNOTHOP_LAB), profileable и подробные логи здесь не используются.
# Серийные номера печатаются в терминал; в файлы репозитория ничего не пишется.
# Временный каталог скачивания создаётся через mktemp и удаляется при выходе.
set -euo pipefail

PKG=com.knothop.vpn
REPO=msazanov/KnotHop
BASE="https://github.com/$REPO/releases/latest/download"
ASSET=knothop.apk
IP_HOST=ifconfig.me

TMPDIR_KH=""
APK_PATH=""
cleanup() { if [ -n "$TMPDIR_KH" ]; then rm -rf -- "$TMPDIR_KH"; fi; }
trap cleanup EXIT

die() { echo "phones: $*" >&2; exit 1; }

need() { command -v "$1" >/dev/null 2>&1 || die "нет программы: $1"; }

usage() {
  sed -n '2,8p' "$0" | sed 's/^# \{0,1\}//'
}

# Серийные номера телефонов в состоянии device; остальные состояния печатаются предупреждением.
devices() {
  adb devices | tr -d '\r' | awk 'NR>1 && NF>=2 {
    if ($2 == "device") print $1;
    else printf "phones: пропущен %s (state=%s)\n", $1, $2 > "/dev/stderr"
  }'
}

sha_of() { sha256sum "$1" | awk '{print $1}'; }

# Скачивает knothop.apk и SHA256SUMS последнего релиза в TMPDIR_KH и сверяет sha256.
# Результат — глобальная APK_PATH. Скачанный файл не исполняется: им занимается только adb install.
fetch_latest() {
  need curl
  need sha256sum
  TMPDIR_KH=$(mktemp -d)
  curl -fsSL --max-time 60 -o "$TMPDIR_KH/SHA256SUMS" "$BASE/SHA256SUMS" || die "SHA256SUMS недоступен: $BASE/SHA256SUMS"
  curl -fsSL --max-time 300 -o "$TMPDIR_KH/$ASSET" "$BASE/$ASSET" || die "$ASSET недоступен: $BASE/$ASSET"
  local want got count
  want=$(awk -v f="$ASSET" '$2 == f || $2 == "*" f {print $1}' "$TMPDIR_KH/SHA256SUMS")
  count=$(printf '%s\n' "$want" | grep -c . || true)
  [ "$count" = 1 ] || die "в SHA256SUMS нет единственной строки для $ASSET"
  got=$(sha_of "$TMPDIR_KH/$ASSET")
  [ "$want" = "$got" ] || die "sha256 $ASSET не совпал с SHA256SUMS (ожидали $want, получили $got)"
  echo "релиз: sha256 $ASSET совпал с SHA256SUMS ($got)"
  APK_PATH="$TMPDIR_KH/$ASSET"
}

# versionCode / versionName установленного пакета; пусто, если пакета нет.
pkg_field() {
  local key=$2 v
  v=$(adb -s "$1" shell dumpsys package "$PKG" 2>/dev/null | tr -d '\r' \
      | sed -n "s/.*${key}=\([^ ]*\).*/\1/p" | head -n1) || true
  printf '%s' "$v"
}

# Признак VPN: dumpsys connectivity с «Established by <пакет>» и наличие tun-интерфейса в /proc/net/dev.
vpn_state() {
  local out tun
  out=$(timeout 30 adb -s "$1" shell dumpsys connectivity 2>/dev/null | tr -d '\r') || true
  tun=$(timeout 15 adb -s "$1" shell cat /proc/net/dev 2>/dev/null | tr -d '\r' | grep -c 'tun[0-9]' || true)
  if grep -qF "Established by $PKG" <<<"$out"; then
    printf 'up(tun=%s)' "${tun:-0}"
  else
    printf 'не подтверждён(tun=%s)' "${tun:-0}"
  fi
}

# Внешний IPv4 с телефона: тот же запрос, что в bench/android/mesh_bench.py (toybox nc, shell идёт в туннель).
external_ip() {
  local cmd out ip
  cmd="(printf 'GET / HTTP/1.0\\r\\nHost: $IP_HOST\\r\\nConnection: close\\r\\n\\r\\n'; sleep 2) | toybox nc -w 5 $IP_HOST 80"
  out=$(timeout 20 adb -s "$1" shell "$cmd" 2>/dev/null | tr -d '\r') || true
  ip=$(grep -oE '^[[:space:]]*([0-9]{1,3}\.){3}[0-9]{1,3}[[:space:]]*$' <<<"$out" | tail -n1 | tr -d ' \t') || true
  printf '%s' "${ip:-нет ответа}"
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

  local -a serials=()
  mapfile -t serials < <(devices)
  [ "${#serials[@]}" -gt 0 ] || die "нет телефонов в состоянии device (проверьте adb devices)"
  echo "телефонов: ${#serials[@]}"

  local s before after out fail=0
  for s in "${serials[@]}"; do
    before=$(pkg_field "$s" versionCode)
    out=$(timeout 300 adb -s "$s" install -r "$apk" 2>&1) || true
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

  echo "ВНИМАНИЕ: туннель после установки оборван. Включите VPN кнопкой в приложении на каждом телефоне,"
  echo "затем проверьте: deploy/phones.sh status"
  [ "$fail" = 0 ] || { echo "phones: есть телефоны с ошибкой установки" >&2; exit 1; }
}

cmd_status() {
  need adb
  local -a serials=()
  mapfile -t serials < <(devices)
  [ "${#serials[@]}" -gt 0 ] || die "нет телефонов в состоянии device (проверьте adb devices)"
  local s model vc vn
  for s in "${serials[@]}"; do
    model=$(timeout 15 adb -s "$s" shell getprop ro.product.model 2>/dev/null | tr -d '\r') || true
    vc=$(pkg_field "$s" versionCode)
    if [ -z "$vc" ]; then
      echo "$s ${model:-?}: $PKG не установлен"
      continue
    fi
    vn=$(pkg_field "$s" versionName)
    echo "$s ${model:-?}: versionCode=$vc versionName=$vn VPN=$(vpn_state "$s") внешний IP=$(external_ip "$s")"
  done
}

case "${1:-}" in
  install) shift; cmd_install "${1:---latest}" ;;
  status) cmd_status ;;
  -h|--help|help|"") usage ;;
  *) usage >&2; exit 2 ;;
esac
