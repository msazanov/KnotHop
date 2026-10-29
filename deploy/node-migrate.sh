#!/usr/bin/env bash
# Выполняется НА УЗЛЕ от root. Одноразовая миграция пилота со старых имён rawgd на knothop (решение владельца 22.10).
#   node-migrate.sh <sha256-knothopd.new> [--dry-run]
# Ожидает в /root/knothop-stage/: knothopd.new, knothopd.service, knothop.nft, node-hostfix.sh (кладёт rollout.sh migrate|stage).
# Порядок:
#   1. предусловия: есть старый rawgd-pilot, нового state нет, хеш бинарника верный, предел памяти читается из старого юнита;
#   2. резерв /root/knothop-migrate-bak-<UTC>/ (юниты, drop-in, rawgd-hostfix, nft rawgd_pilot*, iptables, node.json, env);
#   3. stop+disable rawgd-pilot и rawgd-hostfix; nft delete rawgd_pilot/rawgd_pilot_nat; iptables -D только точные правила rgd0 пилота;
#      юниты и /usr/local/sbin/rawgd-hostfix убираются (копии в резерве);
#   4. пользователь knothopd (без логина), /opt/knothop (state пустой, 0700), бинарник, public_rns.txt, node.json (rgd0->khd0,
#      пути), env (RAWGD_*/RAWG_* -> KNOTHOP_*);
#   5. knothopd.service: CPUWeight=100, Nice=0, без CPUQuota, MemoryMax как был на узле; node-hostfix.sh persist; start knothop-hostfix;
#   6. enable+start knothopd; 20 с наблюдения: active, NRestarts 0, процесс от knothopd, khd0, nft knothop/knothop_nat с метками.
# Сбой после первого изменения: откат - revert hostfix нового, новые юниты и каталог /opt/knothop уходят в резерв (не удаляются),
# старые юниты, nft и iptables восстанавливаются, rawgd-pilot запускается снова. Состояние и identity старого узла не трогаются:
# /opt/rawgd-pilot остаётся выключенным резервом. Правила KnotHop (правила с чужими префиксами комментариев) не трогаются, даже если ссылаются на rgd0.
# Приглашение старой сети (invite.txt) не переносится: в новой сети зачисление - отдельный этап. Секреты в журнал не пишутся.
set -u
WANT="${1:?нужен sha256 knothopd.new}"
DRY=0; [ "${2:-}" = "--dry-run" ] && DRY=1
STAGE=/root/knothop-stage
DIR=/opt/knothop
OLD=/opt/rawgd-pilot
UNITS=/etc/systemd/system
OLD_UNIT=rawgd-pilot
OLD_HF=rawgd-hostfix
NEW_UNIT=knothopd
TS=$(date -u +%Y%m%dT%H%M%SZ)
BAK=/root/knothop-migrate-bak-$TS
CHANGED=0
ok() { echo "OK   $*"; }
bad() { echo "FAIL $*"; }
step() { echo "--- $*"; }

rollback() {
  bad "$1: откат на старые юниты"
  systemctl stop "$NEW_UNIT" >/dev/null 2>&1; systemctl disable "$NEW_UNIT" >/dev/null 2>&1
  if [ -f "$UNITS/knothop-hostfix.service" ]; then
    systemctl stop knothop-hostfix >/dev/null 2>&1   # oneshot с RemainAfterExit: без stop остался бы active после удаления юнита
    bash "$STAGE/node-hostfix.sh" revert || bad "revert knothop-hostfix не прошёл"
  fi
  [ -f "$UNITS/$NEW_UNIT.service" ] && mv -f "$UNITS/$NEW_UNIT.service" "$BAK/knothopd.service.failed"
  if [ -d "$DIR" ]; then mv "$DIR" "$BAK/knothop-failed" && echo "     новый каталог $DIR -> $BAK/knothop-failed (не удалён)"; fi
  cp -a "$BAK/$OLD_UNIT.service" "$BAK/$OLD_HF.service" "$UNITS/"
  [ -d "$BAK/$OLD_UNIT.service.d" ] && cp -a "$BAK/$OLD_UNIT.service.d" "$UNITS/"
  [ -d "$BAK/$OLD_HF.service.d" ] && cp -a "$BAK/$OLD_HF.service.d" "$UNITS/"
  [ -f "$BAK/rawgd-hostfix" ] && cp -a "$BAK/rawgd-hostfix" /usr/local/sbin/rawgd-hostfix
  systemctl daemon-reload
  systemctl enable "$OLD_HF" "$OLD_UNIT" >/dev/null 2>&1
  # старый hostfix сам загрузит старые nft-таблицы из /root/rawgd-0013 и добавит свои iptables-правила rgd0
  systemctl start "$OLD_HF" || bad "старый $OLD_HF не запустился"
  systemctl start "$OLD_UNIT"
  sleep 3
  echo "ROLLBACK: $OLD_UNIT=$(systemctl is-active "$OLD_UNIT") $OLD_HF=$(systemctl is-active "$OLD_HF") rawgd_pilot_tables=$(nft list tables 2>/dev/null | grep -c rawgd_pilot)"
  echo "ROLLBACK: резерв $BAK"
  exit 1
}
fail() { bad "$*"; [ "$CHANGED" = 1 ] && rollback "$*"; exit 1; }

# --- 1. предусловия (ничего не меняют)
exec 9>/root/.knothop-migrate.lock || { bad "не открыть /root/.knothop-migrate.lock"; exit 5; }
flock -n 9 || { bad "миграция уже идёт (блокировка)"; exit 75; }
[ "$(id -u)" = 0 ] || { bad "нужен root"; exit 1; }
for f in knothopd.new knothopd.service knothop.nft node-hostfix.sh; do
  [ -f "$STAGE/$f" ] || { bad "нет $STAGE/$f (сначала stage)"; exit 2; }
done
got=$(sha256sum "$STAGE/knothopd.new" | cut -d' ' -f1)
[ "$got" = "$WANT" ] || { bad "хеш knothopd.new $got != $WANT"; exit 2; }
ok "стаж: хеш knothopd.new совпал"
chmod 0755 "$STAGE/knothopd.new"
"$STAGE/knothopd.new" --help >/dev/null 2>&1 || "$STAGE/knothopd.new" --version >/dev/null 2>&1 || { bad "knothopd.new не запускается (glibc? архитектура?)"; exit 3; }
ok "knothopd.new запускается"
[ -f "$UNITS/$OLD_UNIT.service" ] || { bad "нет $UNITS/$OLD_UNIT.service: узел уже не на старых именах (обновление бинарника - node-install.sh)"; exit 4; }
[ -f "$OLD/node.json" ] && [ -f "$OLD/public_rns.txt" ] || { bad "нет $OLD/node.json или public_rns.txt"; exit 4; }
[ -e "$DIR" ] && { bad "$DIR уже есть: миграция не повторяется поверх (см. резерв knothop-failed, если это откат)"; exit 4; }
mem=$(systemctl show "$OLD_UNIT" -p MemoryMax --value 2>/dev/null)
case "$mem" in ''|*[!0-9]*) bad "MemoryMax старого юнита не читается: '$mem'"; exit 4 ;; esac
if [ $((mem % 1048576)) != 0 ] || [ "$mem" -lt 67108864 ] || [ "$mem" -gt 1073741824 ]; then
  bad "MemoryMax=$mem: не целое число МБ в диапазоне 64M..1G"; exit 4
fi
MEM="$((mem / 1048576))M"
ok "предел памяти старого юнита: $MEM (переносится)"
echo "     старый юнит: CPUQuotaPerSecUSec=$(systemctl show "$OLD_UNIT" -p CPUQuotaPerSecUSec --value) CPUWeight=$(systemctl show "$OLD_UNIT" -p CPUWeight --value) Nice=$(systemctl show "$OLD_UNIT" -p Nice --value)"
echo "     новый юнит: CPUWeight=100 Nice=0, квоты CPU нет (решение владельца 28.10)"
if [ -d "$DIR/state" ] && [ -n "$(ls -A "$DIR/state" 2>/dev/null)" ]; then bad "$DIR/state непуст"; exit 4; fi
ok "предусловия выполнены"
[ "$DRY" = 1 ] && { echo "dry-run: изменений не сделано"; exit 0; }

# --- 2. резерв
step "резерв: $BAK"
install -d -m 0700 "$BAK"
cp -a "$UNITS/$OLD_UNIT.service" "$UNITS/$OLD_HF.service" "$BAK/"
[ -d "$UNITS/$OLD_UNIT.service.d" ] && cp -a "$UNITS/$OLD_UNIT.service.d" "$BAK/"
[ -d "$UNITS/$OLD_HF.service.d" ] && cp -a "$UNITS/$OLD_HF.service.d" "$BAK/"
[ -f /usr/local/sbin/rawgd-hostfix ] && cp -a /usr/local/sbin/rawgd-hostfix "$BAK/"
cp -a "$OLD/node.json" "$OLD/public_rns.txt" "$BAK/"
[ -f "$OLD/rawgd.env" ] && cp -a "$OLD/rawgd.env" "$BAK/"
{ nft list table inet rawgd_pilot; nft list table ip rawgd_pilot_nat; } > "$BAK/rawgd_pilot.nft" 2>/dev/null
iptables-save > "$BAK/iptables-before.txt" 2>/dev/null
ok "резерв сохранён"

# --- 3. снятие старого (первое изменение: дальше при сбое откат)
step "снятие старых юнитов, nft и правил rgd0"
CHANGED=1
systemctl stop "$OLD_UNIT" || { CHANGED=0; bad "stop $OLD_UNIT не прошёл: старое работает, ничего не изменено"; exit 6; }
systemctl disable "$OLD_UNIT" "$OLD_HF" >/dev/null 2>&1
systemctl stop "$OLD_HF" >/dev/null 2>&1
nft delete table inet rawgd_pilot 2>/dev/null && ok "nft inet rawgd_pilot удалена"
nft delete table ip rawgd_pilot_nat 2>/dev/null && ok "nft ip rawgd_pilot_nat удалена"
: > "$BAK/removed-iptables.txt"
for r in "FORWARD -i rgd0 -j ACCEPT" "FORWARD -o rgd0 -m conntrack --ctstate RELATED,ESTABLISHED -j ACCEPT"; do
  read -r -a spec <<< "$r"
  while iptables -C "${spec[@]}" 2>/dev/null; do
    iptables -D "${spec[@]}" || fail "iptables -D $r"
    echo "$r" >> "$BAK/removed-iptables.txt"
    ok "iptables -D $r"
  done
done
rm -f "$UNITS/$OLD_UNIT.service" "$UNITS/$OLD_HF.service" /usr/local/sbin/rawgd-hostfix
rm -rf "$UNITS/$OLD_UNIT.service.d" "$UNITS/$OLD_HF.service.d"
systemctl daemon-reload
systemctl reset-failed "$OLD_UNIT" "$OLD_HF" >/dev/null 2>&1
ok "старые юниты и rawgd-hostfix сняты (копии в резерве)"

# --- 4. установка нового
step "установка knothop"
id -u knothopd >/dev/null 2>&1 || useradd --system --no-create-home --home-dir /nonexistent --shell /usr/sbin/nologin knothopd || fail "useradd knothopd"
ok "пользователь knothopd: uid $(id -u knothopd)"
install -d -m 0755 -o root -g root "$DIR" || fail "каталог $DIR"
install -d -m 0700 -o knothopd -g knothopd "$DIR/state" || fail "state"
install -m 0755 -o root -g root "$STAGE/knothopd.new" "$DIR/knothopd" || fail "бинарник"
[ "$(sha256sum "$DIR/knothopd" | cut -d' ' -f1)" = "$WANT" ] || fail "хеш установленного бинарника"
install -m 0644 -o root -g root "$OLD/public_rns.txt" "$DIR/public_rns.txt" || fail "public_rns.txt"
python3 -I - "$OLD/node.json" "$DIR/.node.json.new" <<'PY' || fail "node.json не переписан"
import json, sys
src, dst = sys.argv[1], sys.argv[2]
with open(src, encoding="utf-8") as f:
    d = json.load(f)
for k, v in d.items():
    if isinstance(v, str):
        v = v.replace("/opt/rawgd-pilot/", "/opt/knothop/")
        if v == "rgd0":
            v = "khd0"
        d[k] = v
text = json.dumps(d, indent=2, ensure_ascii=False) + "\n"
if "rawg" in text.lower() or "rgd0" in text:
    raise SystemExit("старое имя осталось в node.json")
with open(dst, "w", encoding="utf-8") as f:
    f.write(text)
PY
chown root:knothopd "$DIR/.node.json.new" && chmod 0640 "$DIR/.node.json.new" && mv -f "$DIR/.node.json.new" "$DIR/node.json" || fail "node.json"
ok "node.json перенесён (ключи: $(python3 -I -c 'import json,sys;print(" ".join(sorted(json.load(open(sys.argv[1])))))' "$DIR/node.json"))"
if [ -f "$OLD/rawgd.env" ]; then
  sed -E 's/RAWGD_/KNOTHOP_/g; s/RAWG_/KNOTHOP_/g' "$OLD/rawgd.env" > "$DIR/.knothopd.env.new" || fail "env"
  grep -q 'RAWG' "$DIR/.knothopd.env.new" && fail "в env остались RAWG-имена"
  chown root:knothopd "$DIR/.knothopd.env.new" && chmod 0640 "$DIR/.knothopd.env.new" && mv -f "$DIR/.knothopd.env.new" "$DIR/knothopd.env" || fail "env"
  ok "env перенесён, переменные: $(grep -oE '^[A-Z_]+=' "$DIR/knothopd.env" | tr '\n' ' ')"
fi
sed -E "s/^MemoryMax=.*/MemoryMax=$MEM/" "$STAGE/knothopd.service" > "$UNITS/.knothopd.service.new" && mv -f "$UNITS/.knothopd.service.new" "$UNITS/$NEW_UNIT.service" || fail "юнит"
grep -qx "MemoryMax=$MEM" "$UNITS/$NEW_UNIT.service" || fail "MemoryMax не подставлен"
systemctl daemon-reload || fail "daemon-reload"
ok "knothopd.service установлен (MemoryMax=$MEM)"

# --- 5. hostfix: persist и загрузка nft/iptables (fail-closed внутри скрипта)
step "knothop-hostfix persist"
bash "$STAGE/node-hostfix.sh" persist || fail "persist"
systemctl start knothop-hostfix || fail "knothop-hostfix (apply) не прошёл"
ok "knothop-hostfix: $(systemctl is-active knothop-hostfix)"

# --- 6. запуск и наблюдение
step "запуск knothopd"
systemctl enable "$NEW_UNIT" >/dev/null 2>&1 || fail "enable knothopd"
systemctl start "$NEW_UNIT" || fail "start knothopd"
for i in $(seq 1 20); do sleep 1; systemctl is-active --quiet "$NEW_UNIT" || fail "юнит упал на ${i}-й секунде"; done
nr=$(systemctl show "$NEW_UNIT" -p NRestarts --value 2>/dev/null)
[ "${nr:-x}" = 0 ] || fail "рестартов: $nr"
pid=$(systemctl show "$NEW_UNIT" -p MainPID --value 2>/dev/null)
case "$pid" in ''|*[!0-9]*|0) fail "нет MainPID" ;; esac
[ "$(ps -o user= -p "$pid" | tr -d ' ')" = knothopd ] || fail "процесс не от knothopd"
ok "knothopd active 20 с, NRestarts=0, процесс от knothopd"
ip link show khd0 >/dev/null 2>&1 || fail "khd0 не создан"
ok "TUN khd0 есть"
t=$(nft list table inet knothop 2>/dev/null) || fail "нет таблицы inet knothop"
for mark in "client->node" "client->internal" "client-ipv6" "carrier-loop-guard" "knothop-user-no-tunnel"; do
  printf '%s\n' "$t" | grep -qF "$mark" || fail "в knothop нет метки $mark"
done
nft list table ip knothop_nat 2>/dev/null | grep -q masquerade || fail "нет NAT knothop_nat"
ok "nft knothop/knothop_nat загружены с метками"
nft list tables 2>/dev/null | grep -q rawgd && fail "остались таблицы rawgd"
ok "таблиц rawgd нет"
ss -lun 2>/dev/null | grep -q ':47001 ' || fail "UDP 47001 не слушается"
ok "UDP 47001 слушается"
[ -f "$DIR/state/identity.key" ] && ok "state создан процессом (identity.key: $(stat -c %U:%G "$DIR/state/identity.key"))"
echo "     журнал kh- строк: $(journalctl -u "$NEW_UNIT" --since "-2 min" --no-pager 2>/dev/null | grep -c 'kh-')"
echo "     список: $(runuser -u knothopd -- "$DIR/knothopd" list --state "$DIR/state" 2>&1 | grep -E '^(нода|якорь)' | head -2 | tr '\n' ' ')"
echo "DONE $(hostname) $(sha256sum "$DIR/knothopd" | cut -c1-16) резерв=$BAK"
