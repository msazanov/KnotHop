#!/usr/bin/env bash
# Runs as root on an allowlisted KnotHop pilot node. Caller streams this helper and knothopd.new.
set -uo pipefail
STAGE=$1 WANT=$2 DIR=/opt/knothop BIN=/opt/knothop/knothopd UNIT=knothopd
PREV="$DIR/knothopd.prev" TMP="$DIR/.knothopd.push.new" LOCK="$DIR/.knothop-push.lock"
BASE_HASH=null BASE_RESTARTS=null BASE_MESH=null BASE_TS=null
POSTSTART_RESTARTS=null HOST_ACL=null HOST_ACL_ERR=
INSTALLED_HASH=null EXE_HASH=null PID=null RESTARTS=null MESH=null TS=null
ROLLBACK=not-needed DETAIL=initializing SUCCESS=0 REPLACEMENT_STARTED=0 ROLLBACK_DONE=0 RESULT_EMITTED=0

sha() { sha256sum "$1" 2>/dev/null | awk '{print $1}'; }

emit_result() {
  local status=$1 rollback=$2 detail=$3
  INSTALLED_HASH=$(sha "$BIN" || printf null)
  if [[ ${PID:-0} =~ ^[0-9]+$ && $PID -gt 0 && -e /proc/$PID/exe ]]; then EXE_HASH=$(sha "/proc/$PID/exe" || printf null); else EXE_HASH=null; fi
  python3 - "$status" "$rollback" "$detail" "$INSTALLED_HASH" "$EXE_HASH" "$BASE_HASH" "$PID" "$RESTARTS" "$MESH" "$TS" "$BASE_RESTARTS" "$BASE_MESH" "$BASE_TS" "$POSTSTART_RESTARTS" "$HOST_ACL" <<'PY'
import json, sys
def number(value):
    try: return int(value)
    except (TypeError, ValueError): return None
print("PUSH_RESULT " + json.dumps({
    "status": sys.argv[1], "rollback": sys.argv[2], "detail": sys.argv[3],
    "installed_sha256": None if sys.argv[4] == "null" else sys.argv[4],
    "executable_sha256": None if sys.argv[5] == "null" else sys.argv[5],
    "previous_sha256": None if sys.argv[6] == "null" else sys.argv[6],
    "pid": number(sys.argv[7]), "restarts": number(sys.argv[8]), "mesh": number(sys.argv[9]),
    "ts": number(sys.argv[10]), "baseline_restarts": number(sys.argv[11]),
    "baseline_mesh": number(sys.argv[12]), "baseline_ts": number(sys.argv[13]),
    "poststart_restarts": number(sys.argv[14]),
    "host_acl": None if sys.argv[15] == "null" else sys.argv[15],
}, separators=(",", ":")))
PY
  RESULT_EMITTED=1
}

# neighbors.json is read-only. A valid peer is external, up, and has an actual carrier.
read_mesh_sample() {
  python3 - <<'PY'
import json, time
try:
    with open('/opt/knothop/state/neighbors.json', encoding='utf-8') as f:
        d = json.load(f)
    ts = d.get('ts')
    if isinstance(ts, bool) or not isinstance(ts, int): raise ValueError('invalid ts')
    now = int(time.time() * 1000)
    age = now - ts
    mesh = sum(1 for n in d.get('exits', []) if isinstance(n, dict)
               and n.get('s') == 'up' and n.get('self') is not True
               and n.get('c') in ('quic', 'tcp'))
    fresh = 1 if 0 <= age <= 10000 else 0
    print(f'{ts} {mesh} {fresh}')
except Exception:
    print('0 0 0')
PY
}

# --- host-acl-begin (тесты загружают этот блок отдельно)
# knothopd с fail-closed host ACL не допускает клиентов без <state>/host-acl.json. Файл обеспечивается ДО замены бинарника:
# отсутствует - создаётся атомарно (temp в том же каталоге, fsync, ln без перезаписи, rm temp), существующий не меняется.
# Владелец - пользователь службы (User= юнита): host_acl.rs принимает владельца root или euid службы, а процесс knothopd
# не прочитает файл root:root 0600. Откат бинарника файл не удаляет: старый knothopd его не читает.
HOST_ACL_DEFAULT='{"version":1,"aliases":[],"allow":[]}'
HOST_ACL_NAME='^[A-Za-z_][A-Za-z0-9_.-]*$'
host_acl_fail() { HOST_ACL=refused; HOST_ACL_ERR=$1; return 1; }

host_acl_state_dir() { # --state из ExecStart юнита, иначе /opt/knothop/state; только буквальный абсолютный путь без ..
  local exec dir=/opt/knothop/state re='--state[= ]([^ ]+)'
  exec=$(systemctl show "$UNIT" -p ExecStart --value 2>/dev/null || :)
  if [[ $exec =~ $re ]]; then dir=${BASH_REMATCH[1]}; fi
  [[ $dir =~ ^/[A-Za-z0-9._/-]+$ && $dir != *..* ]] || return 1
  printf '%s' "$dir"
}

host_acl_owner() { # user:group службы; без User= служба работает от root
  local u g
  u=$(systemctl show "$UNIT" -p User --value 2>/dev/null || :)
  g=$(systemctl show "$UNIT" -p Group --value 2>/dev/null || :)
  [[ -n $u ]] || u=root
  [[ $u =~ $HOST_ACL_NAME ]] || return 1
  [[ -n $g ]] || g=$(id -gn "$u" 2>/dev/null) || return 1
  [[ $g =~ $HOST_ACL_NAME ]] || return 1
  printf '%s:%s' "$u" "$g"
}

ensure_host_acl() { # $1 state-каталог, $2 user:group; HOST_ACL=created|present, иначе refused и код 1
  local state=$1 owner=$2 acl uid mode size svc_uid tmp
  acl=$state/host-acl.json
  [[ -d $state && ! -L $state ]] || { host_acl_fail 'state directory is missing or a symlink'; return 1; }
  [[ ! -L $acl ]] || { host_acl_fail 'host-acl.json is a symlink'; return 1; }
  svc_uid=$(id -u "${owner%%:*}" 2>/dev/null) || { host_acl_fail 'service user is unknown'; return 1; }
  if [[ -e $acl ]]; then
    [[ -f $acl ]] || { host_acl_fail 'host-acl.json is not a regular file'; return 1; }
    read -r uid mode size < <(stat -c '%u %a %s' -- "$acl") || { host_acl_fail 'cannot stat host-acl.json'; return 1; }
    # Существующий файл не правим, но заведомо непригодный (его отвергнет knothopd) не оставляем до замены бинарника.
    (( 8#$mode & 077 )) && { host_acl_fail 'existing host-acl.json is accessible to group/other'; return 1; }
    [[ $uid == 0 || $uid == "$svc_uid" ]] || { host_acl_fail 'existing host-acl.json has an unexpected owner'; return 1; }
    (( size <= 16384 )) || { host_acl_fail 'existing host-acl.json exceeds 16KiB'; return 1; }
    HOST_ACL=present
    return 0
  fi
  tmp=$(mktemp "$state/.host-acl.json.XXXXXX") || { host_acl_fail 'cannot create temporary file'; return 1; }
  if printf '%s\n' "$HOST_ACL_DEFAULT" > "$tmp" && chown "$owner" "$tmp" && chmod 0600 "$tmp" \
      && { sync "$tmp" 2>/dev/null || sync; } && ln -- "$tmp" "$acl"; then
    rm -f -- "$tmp"
    HOST_ACL=created
    return 0
  fi
  rm -f -- "$tmp"
  host_acl_fail 'cannot publish host-acl.json'
}
# --- host-acl-end

# --- nft-ready-begin (тесты загружают этот блок отдельно; тот же блок в node-install.sh)
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

rollback_previous() {
  ROLLBACK=attempted
  trap - EXIT HUP INT TERM
  systemctl stop "$UNIT" >/dev/null 2>&1 || true
  if [[ -f $PREV ]] && install -o root -g root -m 0755 "$PREV" "$TMP" && mv -fT "$TMP" "$BIN"; then
    systemctl start "$UNIT" >/dev/null 2>&1 || true
    sleep 3
    PID=$(systemctl show "$UNIT" -p MainPID --value 2>/dev/null || printf 0)
    RESTARTS=$(systemctl show "$UNIT" -p NRestarts --value 2>/dev/null || printf unknown)
    EXE_HASH=null
    if [[ $PID =~ ^[0-9]+$ && $PID -gt 0 && -e /proc/$PID/exe ]]; then EXE_HASH=$(sha "/proc/$PID/exe" || printf null); fi
    if [[ $(sha "$BIN" || :) == "$BASE_HASH" && $EXE_HASH == "$BASE_HASH" ]] && systemctl is-active --quiet "$UNIT"; then
      ROLLBACK=verified
    else
      ROLLBACK=failed
    fi
  else
    ROLLBACK=failed
  fi
  ROLLBACK_DONE=1
}

on_exit() {
  local rc=$?
  trap - EXIT HUP INT TERM
  if (( REPLACEMENT_STARTED && ! SUCCESS && ! ROLLBACK_DONE )); then rollback_previous; fi
  if (( ! SUCCESS && ! RESULT_EMITTED )); then
    [[ $DETAIL == initializing ]] && DETAIL="remote helper exited rc=$rc"
    emit_result failed "$ROLLBACK" "$DETAIL"
  fi
  exit "$rc"
}
die() { DETAIL=$1; printf 'knothop push: %s\n' "$DETAIL" >&2; exit 1; }
early_die() { ROLLBACK=$1; DETAIL=$2; emit_result failed "$ROLLBACK" "$DETAIL"; exit 1; }

[[ $EUID == 0 && -d $DIR && -f $STAGE ]] || early_die unavailable 'root/paths check failed'
# The lock is acquired before traps or any backup/replacement work. A loser must not
# touch knothopd.prev/knothopd.new or run a rollback belonging to the lock holder.
exec 9>>"$LOCK" || early_die unavailable 'cannot open knothop rollout lock'
if ! flock -n 9; then
  emit_result failed lock-busy 'another knothopd rollout holds the lock'
  exit 75
fi
trap on_exit EXIT
# HUP приходит при обрыве ssh-сессии: откат должен идти так же, как при INT/TERM.
trap 'DETAIL=received-SIGHUP; exit 129' HUP
trap 'DETAIL=received-SIGINT; exit 130' INT
trap 'DETAIL=received-SIGTERM; exit 143' TERM

[[ $(sha "$STAGE") == "$WANT" ]] || { ROLLBACK=unavailable; die 'staged binary hash mismatch'; }
chmod 0755 "$STAGE" || { ROLLBACK=unavailable; die 'cannot chmod staged binary'; }
BASE_HASH=$(sha "$BIN" || :)
[[ -n $BASE_HASH && -f $BIN ]] || { ROLLBACK=unavailable; die 'no previous binary to preserve'; }
[[ $(systemctl is-active "$UNIT" 2>/dev/null || :) == active ]] || { ROLLBACK=unavailable; die 'baseline service is not active'; }
read -r BASE_TS BASE_MESH baseline_fresh < <(read_mesh_sample)
BASE_RESTARTS=$(systemctl show "$UNIT" -p NRestarts --value 2>/dev/null || printf unknown)
if [[ $baseline_fresh != 1 || ! $BASE_MESH =~ ^[0-9]+$ || $BASE_MESH -lt 1 ]]; then
  ROLLBACK=unavailable
  die "baseline mesh is not fresh/healthy; baseline_mesh=$BASE_MESH baseline_ts=$BASE_TS (not PASS)"
fi

# Шаблон nft и hostfix проверяются ДО backup/stop: узел остаётся на старом бинарнике, простоя нет.
nft_host_ready || { ROLLBACK=unavailable; die "nft-шаблон/hostfix не готов к HOST_ACCESS: $NFT_READY_ERR; сначала rollout.sh stage, hostfix apply/persist, start knothop-hostfix (бинарник не заменён)"; }

# host-acl.json обязателен новому knothopd: любой отказ здесь происходит до backup и замены, узел остаётся на старом бинарнике.
if ! acl_state=$(host_acl_state_dir) || ! acl_owner=$(host_acl_owner); then
  HOST_ACL=refused; die 'cannot resolve state directory or service user for host-acl.json'
fi
ensure_host_acl "$acl_state" "$acl_owner" || die "host-acl.json: $HOST_ACL_ERR (binary not replaced)"

cp -p "$BIN" "$PREV" || die 'cannot preserve previous binary'
[[ $(sha "$PREV") == "$BASE_HASH" ]] || die 'backup hash mismatch'
install -o root -g root -m 0755 "$STAGE" "$TMP" || die 'cannot install staged temporary binary'
[[ $(sha "$TMP") == "$WANT" ]] || die 'temporary binary hash mismatch'

REPLACEMENT_STARTED=1
systemctl stop "$UNIT" || die 'systemctl stop failed'
mv -fT "$TMP" "$BIN" || die 'atomic binary replacement failed'
[[ $(sha "$BIN") == "$WANT" ]] || die 'installed binary hash mismatch'
START_MS=$(date +%s%3N)
systemctl start "$UNIT" || die 'systemctl start failed'
POSTSTART_RESTARTS=$(systemctl show "$UNIT" -p NRestarts --value 2>/dev/null || printf unknown)
[[ $POSTSTART_RESTARTS == 0 ]] || die "new service did not start with NRestarts=0 (poststart=$POSTSTART_RESTARTS)"

# Require three consecutive healthy samples five seconds apart; transient/stale snapshots
# reset the streak. A process restart also changes PID and/or post-start NRestarts != 0.
deadline=$((SECONDS + 90)); streak=0; previous_pid=; active=unknown
while (( SECONDS <= deadline )); do
  active=$(systemctl is-active "$UNIT" 2>/dev/null || :)
  RESTARTS=$(systemctl show "$UNIT" -p NRestarts --value 2>/dev/null || printf unknown)
  PID=$(systemctl show "$UNIT" -p MainPID --value 2>/dev/null || printf 0)
  EXE_HASH=null
  if [[ $PID =~ ^[0-9]+$ && $PID -gt 0 && -e /proc/$PID/exe ]]; then EXE_HASH=$(sha "/proc/$PID/exe" || printf null); fi
  read -r TS MESH sample_fresh < <(read_mesh_sample)
  healthy=1
  [[ $active == active && $RESTARTS == "$POSTSTART_RESTARTS" && $PID =~ ^[0-9]+$ && $PID -gt 0 && $EXE_HASH == "$WANT" ]] || healthy=0
  [[ $sample_fresh == 1 && $TS =~ ^[0-9]+$ && $TS -ge $START_MS && $MESH =~ ^[0-9]+$ && $MESH -ge 1 ]] || healthy=0
  if (( healthy )); then
    if [[ -n $previous_pid && $PID == "$previous_pid" ]]; then streak=$((streak + 1)); else streak=1; fi
    previous_pid=$PID
    if (( streak >= 3 )); then break; fi
  else
    streak=0; previous_pid=
  fi
  (( SECONDS >= deadline )) && break
  sleep 5
done
if (( streak < 3 )); then
  die "health gate failed after ${SECONDS}s: active=$active poststart_restarts=$RESTARTS pid=$PID exe=$EXE_HASH mesh=$MESH ts=$TS start_ms=$START_MS healthy_streak=$streak"
fi

SUCCESS=1; ROLLBACK=available; DETAIL='three consecutive healthy samples'
emit_result pass "$ROLLBACK" "$DETAIL"
exit 0
