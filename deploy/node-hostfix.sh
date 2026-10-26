#!/usr/bin/env bash
# Выполняется НА УЗЛЕ от root. Хостфиксы файрвола и forwarding, без которых узел зачисляется, но трафик через него не идёт.
#   node-hostfix.sh check     только отчёт (ничего не меняет); код 0 - всё в порядке, 1 - нужны правки
#   node-hostfix.sh apply     идемпотентно; сначала nft-таблицы (fail-closed), потом iptables ACCEPT; откат: revert
#   node-hostfix.sh persist   поставить systemd-юнит knothop-hostfix, который применяет apply при загрузке и после
#                             restart/reload nftables.service (его `flush ruleset` стирает наши таблицы)
#   node-hostfix.sh revert    отключить persist-юнит, убрать iptables-правила и nft-таблицы (сам knothopd не трогает)
# Что чинится (все пункты из живой переустановки 18.10.2026):
#   1. INPUT policy DROP -> нужны ACCEPT на 47001/udp и 47001/tcp (иначе клиенты и соседи не дозваниваются);
#   2. FORWARD policy DROP (Docker) -> нужны ACCEPT для khd0 (accept в чужой nft-таблице решение policy drop не отменяет);
#   3. таблицы nft knothop / knothop_nat (защита от доступа клиентов к службам узла, NAT 198.18.0.0/15, защита от петли носителя);
#   4. net.ipv4.ip_forward=1.
# Порядок apply (fail-closed): nft-таблицы загружаются и проверяются первыми. Если это не удалось, ни одно iptables-правило
# не добавляется и скрипт возвращает ошибку: открывать порт и пересылку без изоляции клиентов нельзя.
# Правки по iptables нужны только при policy DROP на цепочке; при ACCEPT скрипт ничего не добавляет (флаг --all добавляет всегда).
# IPv6: клиентский TUN IPv6 не несёт; запрет IPv6 из khd0 в forward - в nft (метка client-ipv6). sysctl IPv6 только в отчёте.
set -u
CMD="${1:-check}"; ALL=0; [ "${2:-}" = "--all" ] && ALL=1
NFT=/root/knothop-stage/knothop.nft
OWN_ENDPOINTS=${KNOTHOP_OWN_ENDPOINTS:-/root/knothop-stage/own-endpoints.conf}
UNIT_FILE=/etc/systemd/system/knothop-hostfix.service
DROPIN_DIR=/etc/systemd/system/knothop-hostfix.service.d
DROPIN_FILE=$DROPIN_DIR/10-reapply.conf
WATCH_SVC=/etc/systemd/system/knothop-hostfix-watch.service   # снятый сторож (W68): persist и revert его убирают
WATCH_TIMER=/etc/systemd/system/knothop-hostfix-watch.timer
BIN_FILE=/usr/local/sbin/knothop-hostfix
PORT=47001
TUN=khd0
rc=0
say() { printf '%-6s %s\n' "$1" "$2"; }
has_ipt() { command -v iptables >/dev/null; }
policy() { iptables -S "$1" 2>/dev/null | sed -n '1s/^-P [A-Z]* //p'; }

need_input() { has_ipt && { [ "$(policy INPUT)" = DROP ] || [ "$ALL" = 1 ]; }; }
need_forward() { has_ipt && { [ "$(policy FORWARD)" = DROP ] || [ "$ALL" = 1 ]; }; }

rules_input()   { printf '%s\n' "INPUT -p udp --dport $PORT -j ACCEPT" "INPUT -p tcp --dport $PORT -j ACCEPT"; }
rules_forward() { printf '%s\n' "FORWARD -i $TUN -j ACCEPT" "FORWARD -o $TUN -m conntrack --ctstate RELATED,ESTABLISHED -j ACCEPT"; }

present() { iptables -C $1 >/dev/null 2>&1; }

# Метки - комментарии правил в nft: по ним проверяется, что загружен наш файл, а не чужая таблица с тем же именем.
NFT_MARKS=("client->node" "client->internal" "client-ipv6" "client->own-endpoint" "carrier-loop-guard" "knothop-user-no-tunnel")
nft_loaded() { nft list table inet knothop >/dev/null 2>&1 && nft list table ip knothop_nat >/dev/null 2>&1; }
nft_verified() {
  local t mark
  t=$(nft list table inet knothop 2>/dev/null) || return 1
  for mark in "${NFT_MARKS[@]}"; do printf '%s\n' "$t" | grep -qF "$mark" || return 1; done
  nft list table ip knothop_nat 2>/dev/null | grep -q masquerade \
    && nft list set inet knothop own_public_v4 >/dev/null 2>&1 \
    && nft list set inet knothop own_public_v6 >/dev/null 2>&1
}

nft_swap() { # add+delete объявляют таблицу и тут же удаляют её, если её нет: один файл = одна транзакция nft, проверка -c до загрузки
  local tmp elements r; tmp=$(mktemp /root/.knothopd-nft.XXXXXX) || return 1
  elements=$(mktemp /root/.knothopd-endpoints.XXXXXX) || { rm -f "$tmp"; return 1; }
  if ! endpoint_elements > "$elements"; then rm -f "$tmp" "$elements"; return 1; fi
  { printf 'add table inet knothop\ndelete table inet knothop\nadd table ip knothop_nat\ndelete table ip knothop_nat\n'; cat "$NFT"; cat "$elements"; } > "$tmp"
  nft -c -f "$tmp" && nft -f "$tmp"; r=$?
  rm -f "$tmp" "$elements"; return $r
}

# Operator-provisioned trusted endpoint inventory: one literal global IPv4/IPv6 address per line;
# no DNS, URLs, peer hints, or address discovery. Never echo the contents (public infrastructure data).
endpoint_elements() {
  [ -f "$OWN_ENDPOINTS" ] && [ ! -L "$OWN_ENDPOINTS" ] || return 1
  [ "$(stat -c '%u:%a' "$OWN_ENDPOINTS" 2>/dev/null)" = "0:600" ] || return 1
  python3 - "$OWN_ENDPOINTS" <<'PY'
import ipaddress, sys
v4, v6 = set(), set()
try:
    with open(sys.argv[1], encoding="ascii") as f:
        for raw in f:
            line = raw.split("#", 1)[0].strip()
            if not line:
                continue
            ip = ipaddress.ip_address(line)
            if not ip.is_global or ip.is_multicast or ip.is_unspecified:
                raise ValueError
            (v4 if ip.version == 4 else v6).add(str(ip))
            if len(v4) + len(v6) > 64:
                raise ValueError
    if not (v4 or v6):
        raise ValueError
except (OSError, UnicodeError, ValueError):
    sys.exit(1)
if v4:
    print("add element inet knothop own_public_v4 { " + ", ".join(sorted(v4, key=ipaddress.ip_address)) + " }")
if v6:
    print("add element inet knothop own_public_v6 { " + ", ".join(sorted(v6, key=ipaddress.ip_address)) + " }")
PY
}

nft_sync_endpoints() {
  local tmp r; tmp=$(mktemp /root/.knothopd-endpoint-sync.XXXXXX) || return 1
  { printf 'flush set inet knothop own_public_v4\nflush set inet knothop own_public_v6\n'; endpoint_elements; } > "$tmp" || { rm -f "$tmp"; return 1; }
  nft -c -f "$tmp" && nft -f "$tmp"; r=$?
  rm -f "$tmp"; return $r
}

check_group() { # name needfn rulesfn
  local name=$1 need=$2 rules=$3
  if ! $need; then say OK "$name: policy $(policy "${name}")  (правила не требуются)"; return; fi
  local miss=0
  while read -r r; do present "$r" || { say MISS "$name: нет правила: $r"; miss=1; }; done < <($rules)
  [ $miss = 0 ] && say OK "$name: правила на месте" || rc=1
}

do_check() {
  has_ipt || say SKIP "iptables не установлен: проверьте файрвол вручную (nft/ufw)"
  has_ipt && { check_group INPUT need_input rules_input; check_group FORWARD need_forward rules_forward; }
  # MISS может быть ложным: эквивалентные правила, привязанные к интерфейсу/адресу, скрипт не распознаёт. Для ручной сверки:
  if has_ipt; then
    say INFO "правила про khd0/$PORT в iptables (для ручной сверки):"
    iptables -S 2>/dev/null | grep -E "khd0|$PORT" | sed 's/^/       /'
  fi
  for t in "inet knothop" "ip knothop_nat"; do
    nft list table $t >/dev/null 2>&1 && say OK "nft таблица $t загружена" || { say MISS "nft таблица $t не загружена"; rc=1; }
  done
  if nft_loaded; then
    nft_verified && say OK "nft: изоляция клиентов, loop-guard и NAT на месте" \
      || { say MISS "nft: таблицы загружены, но без ожидаемых правил (${NFT_MARKS[*]}, masquerade)"; rc=1; }
  fi
  endpoint_elements >/dev/null && say OK "trusted own-endpoint inventory: валидна" \
    || { say MISS "trusted own-endpoint inventory отсутствует/невалидна (содержимое скрыто)"; rc=1; }
  if nft list table inet knothop 2>/dev/null | grep -qF "client-ipv6"; then
    say OK "IPv6 из khd0 в forward: drop (nft client-ipv6)"
  else
    say MISS "IPv6 из khd0 в forward не запрещён (нет правила client-ipv6)"; rc=1
  fi
  say INFO "net.ipv6.conf.all.forwarding=$(sysctl -n net.ipv6.conf.all.forwarding 2>/dev/null || echo ?) (только отчёт, не меняется)"
  [ "$(sysctl -n net.ipv4.ip_forward 2>/dev/null)" = 1 ] && say OK "ip_forward=1" || { say MISS "ip_forward=0"; rc=1; }
  ss -lun 2>/dev/null | grep -q ":$PORT " && say OK "UDP $PORT слушается" || say WARN "UDP $PORT не слушается (юнит остановлен?)"
  return $rc
}

ins() { # правило, вставка в начало цепочки; ошибка iptables прерывает apply
  present "$1" && return 0
  iptables -I $1 && say ADD "iptables -I $1" || { say FAIL "iptables -I $1"; return 1; }
}

do_apply() {
  # 1. nft первыми: без проверенной изоляции iptables ничего не открывает
  endpoint_elements >/dev/null || { say FAIL "trusted own-endpoint inventory отсутствует/невалидна (содержимое скрыто); firewall не меняю"; return 1; }
  if ! nft_verified; then
    # нет таблиц, часть таблиц или старая версия: заменяем одной транзакцией (окна без изоляции клиентов нет)
    [ -f "$NFT" ] || { say FAIL "нет $NFT: iptables не трогаю"; return 1; }
    nft_swap && say ADD "nft: таблицы knothopd заменены атомарно из $NFT" || { say FAIL "nft не принял $NFT: iptables не трогаю"; return 1; }
  fi
  nft_verified || { say FAIL "nft-таблицы загружены, но без ожидаемых правил: iptables не трогаю"; return 1; }
  nft_sync_endpoints || { say FAIL "не удалось атомарно обновить own-endpoint sets: iptables не трогаю"; return 1; }
  # 2. iptables ACCEPT - только после проверенного nft
  if need_input; then
    while read -r r; do ins "$r" || return 1; done < <(rules_input)
  fi
  if need_forward; then
    n=1
    while read -r r; do
      if ! present "$r"; then
        c=${r%% *}; rest=${r#* }
        iptables -I "$c" $n $rest && say ADD "iptables -I $c $n $rest" || { say FAIL "iptables -I $c $n $rest"; return 1; }
      fi
      n=$((n+1))
    done < <(rules_forward)
  fi
  # 3. forwarding
  [ "$(sysctl -n net.ipv4.ip_forward 2>/dev/null)" = 1 ] || { sysctl -qw net.ipv4.ip_forward=1 && say ADD "ip_forward=1"; }
  do_check
}

do_revert() {
  # сначала снимаем persist: иначе перезагрузка вернёт правила, которые мы сейчас убираем
  if [ -f "$UNIT_FILE" ] || systemctl is-enabled knothop-hostfix.service >/dev/null 2>&1; then
    if systemctl disable knothop-hostfix.service >/dev/null 2>&1; then
      systemctl disable --now knothop-hostfix-watch.timer >/dev/null 2>&1
      rm -f "$WATCH_SVC" "$WATCH_TIMER" "$UNIT_FILE" "$DROPIN_FILE" "$BIN_FILE" && rmdir "$DROPIN_DIR" 2>/dev/null; systemctl daemon-reload && say DEL "knothop-hostfix.service отключён, юнит и $BIN_FILE удалены"
    else
      say FAIL "systemctl disable knothop-hostfix.service не прошёл: персист не снят"; rc=1
    fi
  fi
  if has_ipt; then
    while read -r r; do present "$r" && iptables -D $r && say DEL "iptables -D $r"; done < <(rules_input; rules_forward)
  fi
  nft delete table inet knothop 2>/dev/null && say DEL "nft inet knothop"
  nft delete table ip knothop_nat 2>/dev/null && say DEL "nft ip knothop_nat"
  say NOTE "ip_forward не откатывается (мог быть включён до нас)"
  return $rc
}

do_persist() {
  # без nft-файла юнит поднимет узел без изоляции клиентов, поэтому persist отказывается
  [ -f "$NFT" ] || { say FAIL "нет $NFT: сначала stage; persist не ставлю"; return 1; }
  install -m 0755 "$0" "$BIN_FILE" || { say FAIL "не удалось установить $BIN_FILE"; return 1; }
  install -d -m 0755 /root/knothop-stage
  cat > "$UNIT_FILE" <<'EOF'
[Unit]
Description=knothopd host firewall fixes (INPUT/FORWARD/nft/ip_forward)
After=network-online.target docker.service nftables.service
Wants=network-online.target
Before=knothopd.service

[Service]
Type=oneshot
RemainAfterExit=yes
ExecStart=/usr/local/sbin/knothop-hostfix apply

[Install]
WantedBy=multi-user.target
EOF
  # перезагрузка nftables (`nft -f` с `flush ruleset` в /etc/nftables.conf) стирает чужие таблицы, в том числе наши:
  # restart nftables перезапускает юнит (PartOf, порядок After=nftables), reload - вызывает ExecReload
  install -d -m 0755 "$DROPIN_DIR"
  cat > "$DROPIN_FILE" <<'EOF'
[Unit]
PartOf=nftables.service
ReloadPropagatedFrom=nftables.service

[Service]
ExecReload=/usr/local/sbin/knothop-hostfix apply
EOF
  # сторож W68 (таймер раз в 30 с) владелец отменил как лишнее: снимаем, если остался от прежнего persist
  if [ -f "$WATCH_TIMER" ] || [ -f "$WATCH_SVC" ]; then
    systemctl disable --now knothop-hostfix-watch.timer >/dev/null 2>&1
    rm -f "$WATCH_TIMER" "$WATCH_SVC" && say DEL "сторож knothop-hostfix-watch снят"
  fi
  systemctl daemon-reload && systemctl enable knothop-hostfix.service >/dev/null 2>&1 \
    && say ADD "knothop-hostfix.service включён (при загрузке и после reload/restart nftables)" \
    || { say FAIL "knothop-hostfix.service не включился"; return 1; }
}

case "$CMD" in
  check) do_check ;;
  apply) do_apply || rc=1 ;;
  persist) do_persist || rc=1 ;;
  revert) do_revert || rc=1 ;;
  *) echo "check|apply|persist|revert [--all]"; exit 64 ;;
esac
exit "$rc"
