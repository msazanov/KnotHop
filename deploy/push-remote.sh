#!/usr/bin/env bash
# Runs as root on an allowlisted rawg pilot node. Caller streams this helper and rawgd.new.
set -uo pipefail
STAGE=$1 WANT=$2 DIR=/opt/rawgd-pilot BIN=/opt/rawgd-pilot/rawgd UNIT=rawgd-pilot
PREV="$DIR/rawgd.prev" TMP="$DIR/.rawgd.push.new" LOCK="$DIR/.rawgd-push.lock"
BASE_HASH=null BASE_RESTARTS=null BASE_MESH=null BASE_TS=null
POSTSTART_RESTARTS=null
INSTALLED_HASH=null EXE_HASH=null PID=null RESTARTS=null MESH=null TS=null
ROLLBACK=not-needed DETAIL=initializing SUCCESS=0 REPLACEMENT_STARTED=0 ROLLBACK_DONE=0 RESULT_EMITTED=0

sha() { sha256sum "$1" 2>/dev/null | awk '{print $1}'; }

emit_result() {
  local status=$1 rollback=$2 detail=$3
  INSTALLED_HASH=$(sha "$BIN" || printf null)
  if [[ ${PID:-0} =~ ^[0-9]+$ && $PID -gt 0 && -e /proc/$PID/exe ]]; then EXE_HASH=$(sha "/proc/$PID/exe" || printf null); else EXE_HASH=null; fi
  python3 - "$status" "$rollback" "$detail" "$INSTALLED_HASH" "$EXE_HASH" "$BASE_HASH" "$PID" "$RESTARTS" "$MESH" "$TS" "$BASE_RESTARTS" "$BASE_MESH" "$BASE_TS" "$POSTSTART_RESTARTS" <<'PY'
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
}, separators=(",", ":")))
PY
  RESULT_EMITTED=1
}

# neighbors.json is read-only. A valid peer is external, up, and has an actual carrier.
read_mesh_sample() {
  python3 - <<'PY'
import json, time
try:
    with open('/opt/rawgd-pilot/state/neighbors.json', encoding='utf-8') as f:
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
die() { DETAIL=$1; printf 'rawg push: %s\n' "$DETAIL" >&2; exit 1; }
early_die() { ROLLBACK=$1; DETAIL=$2; emit_result failed "$ROLLBACK" "$DETAIL"; exit 1; }

[[ $EUID == 0 && -d $DIR && -f $STAGE ]] || early_die unavailable 'root/paths check failed'
# The lock is acquired before traps or any backup/replacement work. A loser must not
# touch rawgd.prev/rawgd.new or run a rollback belonging to the lock holder.
exec 9>>"$LOCK" || early_die unavailable 'cannot open rawg rollout lock'
if ! flock -n 9; then
  emit_result failed lock-busy 'another rawgd-pilot rollout holds the lock'
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
