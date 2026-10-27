#!/usr/bin/env bash
# Выполняется НА УЗЛЕ от root. Заменяет бинарник knothopd пилота с откатом; state и identity не трогает.
#   node-install.sh <sha256-нового-бинарника> [--dry-run]
# Ожидает свежий файл в /root/knothop-stage/knothopd.new (его кладёт deploy/rollout.sh stage).
# Порядок: проверка хеша -> запуск нового бинарника вхолостую (ловит несовместимую glibc ДО остановки) -> stop -> замена ->
# проверка хеша установленного -> start -> 20 с наблюдения (active, рестартов 0, knothopd list) -> при сбое откат на сохранённый knothopd.prev.
# Приглашений не читает и в журнал не пишет.
set -u
WANT="${1:?нужен sha256 нового бинарника}"
DRY=0; [ "${2:-}" = "--dry-run" ] && DRY=1
UNIT=knothopd
DIR=/opt/knothop
BIN=$DIR/knothopd
STAGE=/root/knothop-stage/knothopd.new
STATE=$DIR/state
ok() { echo "OK   $*"; }
bad() { echo "FAIL $*"; }
# Та же блокировка, что у push-remote.sh (fd 9 там, fd 8 здесь): две замены бинарника одновременно недопустимы.
exec 8>>"$DIR/.knothop-push.lock" || { bad "не открыть блокировку $DIR/.knothop-push.lock"; exit 5; }
flock -n 8 || { bad "другая раскатка держит $DIR/.knothop-push.lock"; exit 75; }

[ -f "$STAGE" ] || { bad "нет $STAGE (сначала stage)"; exit 2; }
got=$(sha256sum "$STAGE" | cut -d' ' -f1)
[ "$got" = "$WANT" ] || { bad "хеш стагированного $got != $WANT"; exit 2; }
ok "стагированный хеш совпал"
chmod 0755 "$STAGE"
"$STAGE" --version >/dev/null 2>&1 || "$STAGE" --help >/dev/null 2>&1 || { bad "новый бинарник не запускается (glibc? архитектура?)"; "$STAGE" --help 2>&1 | head -3; exit 3; }
ok "новый бинарник запускается"

cur=$(sha256sum "$BIN" 2>/dev/null | cut -d' ' -f1)
echo "     установлен: ${cur:-нет}"
if [ "$cur" = "$WANT" ]; then
  ok "уже установлен нужный бинарник, замена не нужна"
  systemctl is-active "$UNIT" >/dev/null && ok "юнит active" || bad "юнит не active"
  exit 0
fi
# --- nft-ready-begin (тот же блок, что в push-remote.sh; тест test_push сверяет идентичность)
# knothopd с HOST_ACCESS-nft очищает наборы inet knothop при старте: без нового шаблона старт падает, узел уходит в рестарты и откат.
# Поэтому ДО backup и остановки службы требуем: загруженная таблица с правилом TCP и обоими наборами с timeout 3s, активный
# knothop-hostfix, persist-копия и шаблон reload/boot с новой меткой. Порядок на узле: rollout.sh stage -> hostfix apply -> hostfix persist
# -> systemctl start knothop-hostfix -> только потом бинарник (docs/development.md). NFT_READY_ERR - причина отказа без адресов.
HOSTFIX_BIN=/usr/local/sbin/knothop-hostfix
NFT_STAGE_TEMPLATE=/root/knothop-stage/knothop.nft
NFT_HOST_MARK='client->host-access-tcp'
NFT_READY_ERR=
nft_host_ready() {
  local t s
  NFT_READY_ERR=
  t=$(nft list table inet knothop 2>/dev/null) || { NFT_READY_ERR='таблица inet knothop не загружена'; return 1; }
  grep -qF "$NFT_HOST_MARK" <<<"$t" || { NFT_READY_ERR='в таблице нет правила client->host-access-tcp (старый шаблон)'; return 1; }
  for s in host_access_v4 host_access_dest_v4; do
    # вывод в переменную: `| grep -q` при pipefail даёт ложный отказ, когда grep закрывает pipe раньше, чем nft допишет
    t=$(nft list set inet knothop "$s" 2>/dev/null) && grep -qF 'timeout 3s' <<<"$t" || { NFT_READY_ERR="нет набора $s с timeout 3s"; return 1; }
  done
  systemctl is-active --quiet knothop-hostfix.service 2>/dev/null || { NFT_READY_ERR='knothop-hostfix.service не active'; return 1; }
  grep -qF "$NFT_HOST_MARK" "$HOSTFIX_BIN" 2>/dev/null || { NFT_READY_ERR="$HOSTFIX_BIN не знает новой метки (нужен hostfix persist)"; return 1; }
  grep -qF "$NFT_HOST_MARK" "$NFT_STAGE_TEMPLATE" 2>/dev/null || { NFT_READY_ERR="$NFT_STAGE_TEMPLATE без нового правила (нужен stage)"; return 1; }
}
# --- nft-ready-end
if nft_host_ready; then ok "nft-шаблон и hostfix готовы к HOST_ACCESS"; else
  bad "nft-шаблон/hostfix не готов к HOST_ACCESS: $NFT_READY_ERR; сначала rollout.sh stage, hostfix apply/persist, start knothop-hostfix (бинарник не заменён)"; exit 2
fi
[ "$DRY" = 1 ] && { ok "dry-run: заменил бы $cur -> $WANT"; exit 0; }

cp -a "$BIN" "$BIN.prev" || { bad "не удалось сохранить knothopd.prev"; exit 4; }
ok "старый сохранён: knothopd.prev ($cur)"

rollback() {
  bad "$1: откат на knothopd.prev"
  systemctl stop "$UNIT" 2>/dev/null
  cp -a "$BIN.prev" "$BIN"
  systemctl start "$UNIT"
  sleep 3
  systemctl is-active "$UNIT" >/dev/null && ok "после отката юнит active ($(sha256sum "$BIN" | cut -c1-8))" || bad "после отката юнит НЕ active"
  exit 1
}

systemctl stop "$UNIT" || rollback "stop не прошёл"
cp "$STAGE" "$BIN.new" && chown --reference="$BIN.prev" "$BIN.new" && chmod --reference="$BIN.prev" "$BIN.new" && mv -f "$BIN.new" "$BIN" || rollback "не удалось заменить файл"
now=$(sha256sum "$BIN" | cut -d' ' -f1)
[ "$now" = "$WANT" ] || rollback "хеш установленного $now != $WANT"
ok "установленный хеш совпал"
since=$(date '+%Y-%m-%d %H:%M:%S')
systemctl start "$UNIT" || rollback "start не прошёл"

for i in $(seq 1 20); do sleep 1; systemctl is-active "$UNIT" >/dev/null || rollback "юнит упал на ${i}-й секунде"; done
nr=$(systemctl show "$UNIT" -p NRestarts --value 2>/dev/null)
[ "${nr:-0}" = "0" ] || rollback "рестартов: $nr"
ok "юнит active 20 с, рестартов 0"

run_as() { if command -v runuser >/dev/null; then runuser -u knothopd -- "$@"; else sudo -u knothopd "$@"; fi; }
lst=$(run_as "$BIN" list --state "$STATE" 2>&1) || rollback "knothopd list не отработал: $(echo "$lst" | head -2)"
echo "$lst" | grep -E "^(нода|якорь)|права" | head -8 | sed 's/^/     /'
n=$(journalctl -u "$UNIT" --since "$since" --no-pager 2>/dev/null | grep -c 'kh-')
[ "$n" = "0" ] && ok "в журнале kh-: 0" || bad "в журнале есть kh- ($n строк): проверить вручную"
ss -lun 2>/dev/null | grep -q ':47001 ' && ok "UDP 47001 слушается" || bad "UDP 47001 не слушается"
ss -ltn 2>/dev/null | grep -q ':47001 ' && ok "TCP 47001 слушается" || echo "     TCP 47001 не слушается (если носитель только QUIC - норма)"
echo "     лимиты: CPUQuota=$(systemctl show "$UNIT" -p CPUQuotaPerSecUSec --value) MemoryMax=$(systemctl show "$UNIT" -p MemoryMax --value)"
echo "DONE $(hostname) $(sha256sum "$BIN" | cut -c1-16)"
