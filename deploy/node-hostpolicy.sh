#!/usr/bin/env bash
# Выполняется НА УЗЛЕ от root, вручную оператором. Редактирует <state>/host-policy.json: каких чужих корней доверия (root hash)
# узел принимает как держателей прав на доступ к хосту. Формат и лимиты - по загрузчику host policy в trust.rs:
#   {"v":1,"roots":[{"root":"<32 hex = 16 байт>","max_holders":N}]}, до 8 корней, max_holders 1..512 (по умолчанию 64).
#   node-hostpolicy.sh show                          только отчёт (ничего не меняет)
#   node-hostpolicy.sh add-root <32hex> [max_holders]   добавить корень или изменить его max_holders (идемпотентно)
# Запуск через тот же SSH-механизм, что node-hostfix (скрипт приходит по stdin): rollout.sh hostpolicy show|add-root ... <узлы>.
# Корень - публичный хеш якоря, не секрет; секреты и identity скрипт не читает и не печатает.
# Запись: temp в том же каталоге (O_EXCL, без symlink), fsync, rename, владелец - пользователь службы, режим 0600. Файл-symlink,
# не-регулярный файл, неверный формат существующего файла - отказ без изменений. Службу скрипт НЕ перезапускает:
# knothopd читает host-policy.json только при старте.
set -uo pipefail
UNIT=knothopd
NAME_RE='^[A-Za-z_][A-Za-z0-9_.-]*$'

usage() { echo 'usage: node-hostpolicy.sh show | add-root <32hex> [max_holders 1..512]' >&2; exit 64; }

state_dir() { # --state из ExecStart юнита, иначе /opt/knothop/state; только буквальный абсолютный путь без ..
  local exec dir=/opt/knothop/state re='--state[= ]([^ ]+)'
  exec=$(systemctl show "$UNIT" -p ExecStart --value 2>/dev/null || :)
  if [[ $exec =~ $re ]]; then dir=${BASH_REMATCH[1]}; fi
  [[ $dir =~ ^/[A-Za-z0-9._/-]+$ && $dir != *..* ]] || return 1
  printf '%s' "$dir"
}

service_owner() { # user:group службы; без User= служба работает от root
  local u g
  u=$(systemctl show "$UNIT" -p User --value 2>/dev/null || :)
  g=$(systemctl show "$UNIT" -p Group --value 2>/dev/null || :)
  [[ -n $u ]] || u=root
  [[ $u =~ $NAME_RE ]] || return 1
  [[ -n $g ]] || g=$(id -gn "$u" 2>/dev/null) || return 1
  [[ $g =~ $NAME_RE ]] || return 1
  printf '%s:%s' "$u" "$g"
}

ACTION=${1:-}
case "$ACTION" in
  show) [[ $# -eq 1 ]] || usage ;;
  add-root)
    [[ $# -ge 2 && $# -le 3 ]] || usage
    [[ $2 =~ ^[0-9A-Fa-f]{32}$ ]] || { echo 'node-hostpolicy: root must be exactly 32 hex characters (16-byte root hash)' >&2; exit 64; }
    if [[ $# -eq 3 ]]; then
      [[ $3 =~ ^[0-9]{1,4}$ ]] && (( 10#$3 >= 1 && 10#$3 <= 512 )) || { echo 'node-hostpolicy: max_holders must be 1..512' >&2; exit 64; }
    fi ;;
  *) usage ;;
esac

STATE=$(state_dir) || { echo 'node-hostpolicy: cannot resolve a literal state directory from the unit' >&2; exit 1; }
OWNER=$(service_owner) || { echo 'node-hostpolicy: cannot resolve the service user' >&2; exit 1; }

python3 - "$STATE" "$OWNER" "$@" <<'PY'
import fcntl, grp, json, os, pwd, re, stat, sys

MAX_ROOTS, MAX_HOLDERS, DEFAULT_HOLDERS, MAX_BYTES = 8, 512, 64, 4 * 1024 * 1024
NAME = "host-policy.json"
state, owner, action, *args = sys.argv[1:]


def fail(message):
    print(f"node-hostpolicy: {message}", file=sys.stderr)
    sys.exit(1)


def is_int(value):
    return isinstance(value, int) and not isinstance(value, bool)


try:
    dfd = os.open(state, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC)
except OSError as e:
    fail(f"state directory is unusable: {e.strerror}")
fcntl.flock(dfd, fcntl.LOCK_EX)  # два оператора не переписывают файл одновременно


def load():
    """None, если файла нет. Любое отклонение от формата загрузчика - отказ (его бы отверг и knothopd)."""
    try:
        fd = os.open(NAME, os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC, dir_fd=dfd)
    except FileNotFoundError:
        return None, None
    except OSError as e:
        fail(f"cannot open {NAME} without following symlinks: {e.strerror}")
    with os.fdopen(fd, "rb") as f:
        st = os.fstat(f.fileno())
        if not stat.S_ISREG(st.st_mode):
            fail(f"{NAME} is not a regular file")
        if st.st_size > MAX_BYTES:
            fail(f"{NAME} exceeds the size limit")
        data = f.read(MAX_BYTES + 1)
    try:
        doc = json.loads(data)
    except ValueError:
        fail(f"{NAME} does not parse; fix it manually, nothing changed")
    if not isinstance(doc, dict) or not is_int(doc.get("v")) or doc["v"] != 1:
        fail(f"{NAME}: unsupported version; nothing changed")
    items = doc.get("roots")
    if not isinstance(items, list) or len(items) > MAX_ROOTS:
        fail(f"{NAME}: roots missing or too many; nothing changed")
    roots = {}
    for item in items:
        root = item.get("root") if isinstance(item, dict) else None
        if not isinstance(root, str) or not re.fullmatch(r"[0-9a-f]{32}", root):
            fail(f"{NAME}: bad root entry; nothing changed")
        holders = item.get("max_holders", DEFAULT_HOLDERS)
        if not is_int(holders) or not 1 <= holders <= MAX_HOLDERS:
            fail(f"{NAME}: max_holders out of range; nothing changed")
        roots[root] = holders
    return roots, st


def write(roots):
    try:
        uid = pwd.getpwnam(owner.split(":")[0]).pw_uid
        gid = grp.getgrnam(owner.split(":")[1]).gr_gid
    except KeyError:
        fail("service user or group is unknown")
    body = (json.dumps({"v": 1, "roots": [{"root": r, "max_holders": m} for r, m in roots.items()]},
                       separators=(",", ":")) + "\n").encode()
    tmp = f".{NAME}.{os.getpid()}.tmp"
    fd = os.open(tmp, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW | os.O_CLOEXEC, 0o600, dir_fd=dfd)
    try:
        with os.fdopen(fd, "wb", closefd=False) as f:
            f.write(body)
            f.flush()
        os.fchown(fd, uid, gid)
        os.fchmod(fd, 0o600)
        os.fsync(fd)
        os.rename(tmp, NAME, src_dir_fd=dfd, dst_dir_fd=dfd)
    except BaseException:
        try:
            os.unlink(tmp, dir_fd=dfd)
        except OSError:
            pass
        raise
    finally:
        os.close(fd)
    os.fsync(dfd)


roots, st = load()
if action == "show":
    if roots is None:
        print("host-policy: no host-policy.json (no foreign roots are admitted for host access)")
    else:
        print(f"host-policy: {NAME} uid={st.st_uid} mode={stat.S_IMODE(st.st_mode):o} roots={len(roots)}")
        for root, holders in roots.items():
            print(f"  {root}  max_holders={holders}")
    sys.exit(0)

root = args[0].lower()
holders = int(args[1]) if len(args) > 1 else None
roots = {} if roots is None else roots
if root in roots and (holders is None or holders == roots[root]):
    print(f"host-policy: root {root} already present (max_holders={roots[root]}); unchanged")
    sys.exit(0)
if root not in roots and len(roots) >= MAX_ROOTS:
    fail(f"already {MAX_ROOTS} roots (loader limit); nothing changed")
roots[root] = holders if holders is not None else roots.get(root, DEFAULT_HOLDERS)
write(roots)
print(f"host-policy: root {root} set (max_holders={roots[root]}); {len(roots)} root(s) in {NAME}")
print("host-policy: knothopd reads host-policy.json only at start; this script did NOT restart the service")
PY
