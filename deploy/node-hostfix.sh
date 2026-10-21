#!/usr/bin/env bash
# Выполняется НА УЗЛЕ от root. Хостфиксы файрвола и forwarding, без которых узел зачисляется, но трафик через него не идёт.
#   node-hostfix.sh check     только отчёт (ничего не меняет); код 0 - всё в порядке, 1 - нужны правки
#   node-hostfix.sh apply     идемпотентно; сначала nft-таблицы (fail-closed), потом iptables ACCEPT; откат: revert
#   node-hostfix.sh persist   поставить systemd-юнит rawgd-hostfix, который применяет apply при загрузке и после
#                             restart/reload nftables.service (его `flush ruleset` стирает наши таблицы)
#   node-hostfix.sh revert    отключить persist-юнит, убрать iptables-правила и nft-таблицы (сам rawgd не трогает)
# Что чинится (все пункты из живой переустановки 18.10.2026):
#   1. INPUT policy DROP -> нужны ACCEPT на 47001/udp и 47001/tcp (иначе клиенты и соседи не дозваниваются);
#   2. FORWARD policy DROP (Docker) -> нужны ACCEPT для rgd0 (accept в чужой nft-таблице решение policy drop не отменяет);
#   3. таблицы nft rawgd_pilot / rawgd_pilot_nat (защита от доступа клиентов к службам узла, NAT 198.18.0.0/15, защита от петли носителя);
#   4. net.ipv4.ip_forward=1.
# Порядок apply (fail-closed): nft-таблицы загружаются и проверяются первыми. Если это не удалось, ни одно iptables-правило
# не добавляется и скрипт возвращает ошибку: открывать порт и пересылку без изоляции клиентов нельзя.
# Правки по iptables нужны только при policy DROP на цепочке; при ACCEPT скрипт ничего не добавляет (флаг --all добавляет всегда).
# IPv6: клиентский TUN IPv6 не несёт; запрет IPv6 из rgd0 в forward - в nft (метка client-ipv6). sysctl IPv6 только в отчёте.
set -u
CMD="${1:-check}"; ALL=0; [ "${2:-}" = "--all" ] && ALL=1
NFT=/root/rawgd-0013/rawgd-pilot.nft
UNIT_FILE=/etc/systemd/system/rawgd-hostfix.service
DROPIN_DIR=/etc/systemd/system/rawgd-hostfix.service.d
DROPIN_FILE=$DROPIN_DIR/10-reapply.conf
WATCH_SVC=/etc/systemd/system/rawgd-hostfix-watch.service   # снятый сторож (W68): persist и revert его убирают
WATCH_TIMER=/etc/systemd/system/rawgd-hostfix-watch.timer
BIN_FILE=/usr/local/sbin/rawgd-hostfix
PORT=47001
TUN=rgd0
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
NFT_MARKS=("client->node" "client->internal" "client-ipv6" "carrier-loop-guard" "rawgd-user-no-tunnel")
nft_loaded() { nft list table inet rawgd_pilot >/dev/null 2>&1 && nft list table ip rawgd_pilot_nat >/dev/null 2>&1; }
nft_verified() {
  local t mark
  t=$(nft list table inet rawgd_pilot 2>/dev/null) || return 1
  for mark in "${NFT_MARKS[@]}"; do printf '%s\n' "$t" | grep -qF "$mark" || return 1; done
  nft list table ip rawgd_pilot_nat 2>/dev/null | grep -q masquerade
}

nft_swap() { # add+delete объявляют таблицу и тут же удаляют её, если её нет: один файл = одна транзакция nft, проверка -c до загрузки
  local tmp r; tmp=$(mktemp /root/.rawgd-nft.XXXXXX) || return 1
  { printf 'add table inet rawgd_pilot\ndelete table inet rawgd_pilot\nadd table ip rawgd_pilot_nat\ndelete table ip rawgd_pilot_nat\n'; cat "$NFT"; } > "$tmp"
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
    say INFO "правила про rgd0/$PORT в iptables (для ручной сверки):"
    iptables -S 2>/dev/null | grep -E "rgd0|$PORT" | sed 's/^/       /'
  fi
  for t in "inet rawgd_pilot" "ip rawgd_pilot_nat"; do
    nft list table $t >/dev/null 2>&1 && say OK "nft таблица $t загружена" || { say MISS "nft таблица $t не загружена"; rc=1; }
  done
  if nft_loaded; then
    nft_verified && say OK "nft: изоляция клиентов, loop-guard и NAT на месте" \
      || { say MISS "nft: таблицы загружены, но без ожидаемых правил (${NFT_MARKS[*]}, masquerade)"; rc=1; }
  fi
  if nft list table inet rawgd_pilot 2>/dev/null | grep -qF "client-ipv6"; then
    say OK "IPv6 из rgd0 в forward: drop (nft client-ipv6)"
  else
    say MISS "IPv6 из rgd0 в forward не запрещён (нет правила client-ipv6)"; rc=1
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
  if ! nft_verified; then
    # нет таблиц, часть таблиц или старая версия: заменяем одной транзакцией (окна без изоляции клиентов нет)
    [ -f "$NFT" ] || { say FAIL "нет $NFT: iptables не трогаю"; return 1; }
    nft_swap && say ADD "nft: таблицы rawgd заменены атомарно из $NFT" || { say FAIL "nft не принял $NFT: iptables не трогаю"; return 1; }
  fi
  nft_verified || { say FAIL "nft-таблицы загружены, но без ожидаемых правил: iptables не трогаю"; return 1; }
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
  if [ -f "$UNIT_FILE" ] || systemctl is-enabled rawgd-hostfix.service >/dev/null 2>&1; then
    if systemctl disable rawgd-hostfix.service >/dev/null 2>&1; then
      systemctl disable --now rawgd-hostfix-watch.timer >/dev/null 2>&1
      rm -f "$WATCH_SVC" "$WATCH_TIMER" "$UNIT_FILE" "$DROPIN_FILE" "$BIN_FILE" && rmdir "$DROPIN_DIR" 2>/dev/null; systemctl daemon-reload && say DEL "rawgd-hostfix.service отключён, юнит и $BIN_FILE удалены"
    else
      say FAIL "systemctl disable rawgd-hostfix.service не прошёл: персист не снят"; rc=1
    fi
  fi
  if has_ipt; then
    while read -r r; do present "$r" && iptables -D $r && say DEL "iptables -D $r"; done < <(rules_input; rules_forward)
  fi
  nft delete table inet rawgd_pilot 2>/dev/null && say DEL "nft inet rawgd_pilot"
  nft delete table ip rawgd_pilot_nat 2>/dev/null && say DEL "nft ip rawgd_pilot_nat"
  say NOTE "ip_forward не откатывается (мог быть включён до нас)"
  return $rc
}

do_persist() {
  # без nft-файла юнит поднимет узел без изоляции клиентов, поэтому persist отказывается
  [ -f "$NFT" ] || { say FAIL "нет $NFT: сначала stage; persist не ставлю"; return 1; }
  install -m 0755 "$0" "$BIN_FILE" || { say FAIL "не удалось установить $BIN_FILE"; return 1; }
  install -d -m 0755 /root/rawgd-0013
  cat > "$UNIT_FILE" <<'EOF'
[Unit]
Description=rawgd host firewall fixes (INPUT/FORWARD/nft/ip_forward)
After=network-online.target docker.service nftables.service
Wants=network-online.target
Before=rawgd-pilot.service

[Service]
Type=oneshot
RemainAfterExit=yes
ExecStart=/usr/local/sbin/rawgd-hostfix apply

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
ExecReload=/usr/local/sbin/rawgd-hostfix apply
EOF
  # сторож W68 (таймер раз в 30 с) владелец отменил как лишнее: снимаем, если остался от прежнего persist
  if [ -f "$WATCH_TIMER" ] || [ -f "$WATCH_SVC" ]; then
    systemctl disable --now rawgd-hostfix-watch.timer >/dev/null 2>&1
    rm -f "$WATCH_TIMER" "$WATCH_SVC" && say DEL "сторож rawgd-hostfix-watch снят"
  fi
  systemctl daemon-reload && systemctl enable rawgd-hostfix.service >/dev/null 2>&1 \
    && say ADD "rawgd-hostfix.service включён (при загрузке и после reload/restart nftables)" \
    || { say FAIL "rawgd-hostfix.service не включился"; return 1; }
}

case "$CMD" in
  check) do_check ;;
  apply) do_apply || rc=1 ;;
  persist) do_persist || rc=1 ;;
  revert) do_revert || rc=1 ;;
  *) echo "check|apply|persist|revert [--all]"; exit 64 ;;
esac
exit "$rc"
