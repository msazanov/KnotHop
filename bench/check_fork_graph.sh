#!/usr/bin/env bash
# Проверка графа Leviculum без компиляции: оба Cargo.lock актуальны (--locked), leviculum-core ровно один,
# и каждый leviculum-* пакет приходит из checkout форка, а не из git-источника Codeberg.
# Использование: bench/check_fork_graph.sh   (окружение: LEVICULUM_FORK, по умолчанию ~/dev/leviculum)
set -euo pipefail
HERE="$(cd "$(dirname "$0")" && pwd)"
FORK="${LEVICULUM_FORK:-$HOME/dev/leviculum}"
FORK="$(cd "$FORK" && pwd)"
for crate in rns-iroh-node android-native; do
  echo "== $crate"
  LEVICULUM_FORK="$FORK" bash "$HERE/cargo_fork.sh" "$crate" metadata --format-version 1 --locked \
    | python3 -I -c '
import json, sys
fork = sys.argv[1].rstrip("/") + "/"
packages = [p for p in json.load(sys.stdin)["packages"] if p["name"].startswith("leviculum") or p["name"] == "lnpnd"]
names = [p["name"] for p in packages]
bad = [p["name"] for p in packages if p["source"] is not None or not p["manifest_path"].startswith(fork)]
if names.count("leviculum-core") != 1:
    sys.exit("leviculum-core: %d копий вместо одной" % names.count("leviculum-core"))
for need in ("leviculum-std", "leviculum-lxmf", "lnpnd"):
    if names.count(need) != 1:
        sys.exit("%s: %d копий вместо одной" % (need, names.count(need)))
if bad:
    sys.exit("не из checkout форка: " + ", ".join(bad))
print("ok:", ", ".join(sorted(names)))
' "$FORK"
done
