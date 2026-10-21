#!/usr/bin/env python3
"""Allowlisted, guarded rawgd-pilot binary rollout. Dry-run is the default."""
from __future__ import annotations

import argparse
import concurrent.futures
import hashlib
import io
import os
import json
from pathlib import Path
import re
import subprocess
import sys
import tarfile
import time
import shlex
from datetime import datetime, timezone

HERE = Path(__file__).resolve().parent
DIST = HERE / "dist"
IDENTITY = Path.home() / ".ssh" / "id_ed25519"
KH = Path.home() / ".ssh" / "known_hosts"
INV = Path(os.environ.get("RAWG_INVENTORY", Path.home() / ".config/rawg/inventory"))
# (ssh target, binary variant, known_hosts: "known_hosts" = KH, иначе имя файла в INV, jump через de)
ALLOWLIST = {
    "es": ("<user@node-ip>", "rawgd", "es.known_hosts", None),
    "uae": ("<user@node-ip>", "rawgd", "known_hosts", None),
    "by": ("<user@node-ip>", "rawgd", "known_hosts", None),
    "ru1": ("<user@node-ip>", "rawgd", "known_hosts", None),
    "nl1": ("<user@node-ip>", "rawgd", "known_hosts", "de"),
    "de": ("<user@node-ip>", "rawgd-u2204", "known_hosts", None),
    "fin1": ("<user@node-ip>", "rawgd", "known_hosts", "de"),
    "us": ("<user@node-ip>", "rawgd", "us.known_hosts", None),
}
HEX = re.compile(r"^[0-9a-f]{64}$")
SSH_TIMEOUT_SECONDS = 300
# Всё, что уходит на узел, обязано быть в dist/SHA256SUMS: бинарники и helper, который выполняется от root.
PAYLOAD_NAMES = ("rawgd", "rawgd-u2204", "push-remote.sh")
UNKNOWN_TRANSPORT_DETAIL = (
    "remote outcome UNKNOWN: SSH ended without a complete trustworthy result. The helper's HUP/INT/TERM/EXIT "
    "traps attempt rollback if replacement began, but transport loss may terminate the remote process before "
    "or during those traps; rollback is not guaranteed. Verify the node before retrying."
)


class RolloutError(RuntimeError):
    def __init__(self, message: str, row: dict | None = None):
        super().__init__(message)
        self.row = row


def sha256_bytes(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def load_expected() -> dict[str, str]:
    """Читает dist/SHA256SUMS один раз: эти значения — единственный эталон для всего запуска."""
    sums = DIST / "SHA256SUMS"
    if not sums.is_file():
        raise RolloutError(f"missing {sums}")
    expected: dict[str, str] = {}
    for line in sums.read_text().splitlines():
        fields = line.split()
        if len(fields) != 2 or not HEX.fullmatch(fields[0]):
            raise RolloutError(f"malformed SHA256SUMS line: {line[:80]!r}")
        if fields[1] in expected:
            raise RolloutError(f"duplicate checksum entry: {fields[1]}")
        expected[fields[1]] = fields[0]
    missing = [name for name in PAYLOAD_NAMES if name not in expected]
    if missing:
        raise RolloutError(f"SHA256SUMS lacks: {', '.join(missing)} (run deploy/build.sh)")
    return expected


def load_payloads(expected: dict[str, str]) -> dict[str, bytes]:
    """Читает файлы один раз и сверяет байты с SHA256SUMS; отправляется только то, что проверено."""
    payloads: dict[str, bytes] = {}
    for name in PAYLOAD_NAMES:
        data = (DIST / name).read_bytes()
        if sha256_bytes(data) != expected[name]:
            raise RolloutError(f"missing or invalid artifact/checksum: {name}")
        payloads[name] = data
    return payloads


def ensure_current(name: str, data: bytes, expected: dict[str, str]) -> None:
    """Перед отправкой: байты в памяти и файл на диске всё ещё совпадают с SHA256SUMS."""
    on_disk = sha256_bytes((DIST / name).read_bytes())
    if sha256_bytes(data) != expected[name] or on_disk != expected[name]:
        raise RolloutError(f"{name} no longer matches SHA256SUMS; not sending")


def ssh_args(node: str) -> list[str]:
    default_target, _, kh_name, jump = ALLOWLIST[node]
    target = os.environ.get(f"RAWG_SSH_TARGET_{node.upper()}", default_target)
    if not target or "<" in target or ">" in target:
        raise RolloutError(f"set RAWG_SSH_TARGET_{node.upper()} outside the repository")
    kh = KH if kh_name == "known_hosts" else INV / kh_name
    if not IDENTITY.is_file() or not kh.is_file():
        raise RolloutError(f"required SSH identity/known_hosts path missing for {node}")
    opts = ["ssh", "-F", "/dev/null", "-i", str(IDENTITY), "-o", "IdentitiesOnly=yes", "-o", "BatchMode=yes",
            "-o", "StrictHostKeyChecking=yes", "-o", f"UserKnownHostsFile={kh}", "-o", "ConnectTimeout=15",
            "-o", "ServerAliveInterval=10"]
    if jump:
        jump_env = f"RAWG_SSH_TARGET_{jump.upper()}"
        jump_target = os.environ.get(jump_env, ALLOWLIST[jump][0])
        if not jump_target or "<" in jump_target or ">" in jump_target:
            raise RolloutError(f"set {jump_env} outside the repository")
        proxy = ["ssh", "-F", "/dev/null", "-W", "%h:%p", "-i", str(IDENTITY), "-o", "IdentitiesOnly=yes",
                 "-o", "BatchMode=yes", "-o", "StrictHostKeyChecking=yes", "-o", f"UserKnownHostsFile={KH}",
                 "-o", "ConnectTimeout=15", jump_target]
        opts += ["-o", "ProxyCommand=" + " ".join(proxy)]
    opts.append(target)
    return opts


def bundle(binary: bytes, helper: bytes) -> bytes:
    buf = io.BytesIO()
    with tarfile.open(fileobj=buf, mode="w:gz") as tf:
        for arcname, data, mode in (("rawgd.new", binary, 0o755), ("push-remote.sh", helper, 0o755)):
            info = tarfile.TarInfo(arcname)
            info.size = len(data)
            info.mode = mode
            tf.addfile(info, io.BytesIO(data))
    return buf.getvalue()


def is_int(value) -> bool:
    return isinstance(value, int) and not isinstance(value, bool)


def pass_problems(result: dict, expected: str) -> list[str]:
    """Строгая схема PASS: всё, что не подтверждено явно, считается неуспехом."""
    checks = {
        "installed_sha256": result.get("installed_sha256") == expected,
        "executable_sha256": result.get("executable_sha256") == expected,
        "restarts": is_int(result.get("restarts")) and result["restarts"] == 0,
        "mesh": is_int(result.get("mesh")) and result["mesh"] >= 1,
        "pid": is_int(result.get("pid")) and result["pid"] > 0,
    }
    return [name for name, ok in checks.items() if not ok]


def invoke(node: str, binary_name: str, apply: bool, payloads: dict[str, bytes], expected: dict[str, str],
           runner=subprocess.run) -> dict:
    started = time.monotonic()
    expected_sha = expected[binary_name]
    row = {"node": node, "variant": binary_name, "expected_sha256": expected_sha, "status": "pending",
           "rollback": "not-needed", "duration_seconds": None}
    if not apply:
        row.update(status="dry-run", detail="local checks passed; no SSH performed")
        row["duration_seconds"] = round(time.monotonic() - started, 3)
        return row
    argv = ssh_args(node)
    remote = "set -eu; d=$(mktemp -d /opt/rawgd-pilot/.push.XXXXXX); trap 'rm -rf \"$d\"' EXIT; tar -xzf - -C \"$d\"; bash \"$d/push-remote.sh\" \"$d/rawgd.new\" " + expected_sha
    if node == "ru1":
        remote = "sudo -n bash -c " + shlex.quote(remote)
    cmd = argv + [remote]
    try:
        # Проверка до отправки: ничего не уходит на узел, если файлы разошлись с эталоном.
        for name in (binary_name, "push-remote.sh"):
            try:
                ensure_current(name, payloads[name], expected)
            except RolloutError as e:
                row.update(status="failed", rollback="not-needed", detail=str(e))
                raise RolloutError(str(e), row) from e
        cp = runner(cmd, input=bundle(payloads[binary_name], payloads["push-remote.sh"]), stdout=subprocess.PIPE,
                    stderr=subprocess.PIPE, timeout=SSH_TIMEOUT_SECONDS)
        out = cp.stdout.decode("utf-8", "replace")
        err = cp.stderr.decode("utf-8", "replace")
        row["output"] = out[-12000:]
        row["error"] = err[-4000:] if err else ""
        # The remote helper emits one machine-readable result line, even on rollback.
        result_line = next((line for line in reversed(out.splitlines()) if line.startswith("PUSH_RESULT ")), None)
        if result_line:
            try:
                remote_result = json.loads(result_line[len("PUSH_RESULT "):])
                if not isinstance(remote_result, dict):
                    raise ValueError("result is not an object")
                row.update(remote_result)
            except (json.JSONDecodeError, ValueError) as e:
                row.update(status="unknown", rollback="unknown", detail=f"invalid remote result: {e}")
                raise RolloutError(f"{node}: malformed remote result; outcome unknown", row)
        if cp.returncode:
            if row.get("status") == "failed":
                raise RolloutError(f"{node}: remote rollout failed (exit {cp.returncode})", row)
            row.update(status="unknown", rollback="unknown",
                       detail=f"SSH exited {cp.returncode}; {UNKNOWN_TRANSPORT_DETAIL}")
            raise RolloutError(f"{node}: SSH ended without confirmed remote result; outcome unknown", row)
        if row.get("status") != "pass":
            row.update(status="unknown", rollback="unknown",
                       detail=f"SSH completed without a structured PASS result; {UNKNOWN_TRANSPORT_DETAIL}")
            raise RolloutError(f"{node}: remote did not report PASS; outcome unknown", row)
        problems = pass_problems(row, expected_sha)
        if problems:
            row.update(status="unknown", rollback="unknown",
                       detail=f"remote reported PASS but fields fail the strict check: {', '.join(problems)}; "
                              "verify the node manually before retrying")
            raise RolloutError(f"{node}: PASS rejected ({', '.join(problems)}); outcome unknown", row)
    except subprocess.TimeoutExpired as e:
        row.update(status="unknown", rollback="unknown",
                   detail=f"SSH timed out after {SSH_TIMEOUT_SECONDS}s; {UNKNOWN_TRANSPORT_DETAIL}")
        if isinstance(e.stdout, bytes):
            row["output"] = e.stdout.decode("utf-8", "replace")[-12000:]
        if isinstance(e.stderr, bytes):
            row["error"] = e.stderr.decode("utf-8", "replace")[-4000:]
        row["duration_seconds"] = round(time.monotonic() - started, 3)
        raise RolloutError(f"{node}: SSH timeout; remote outcome unknown", row) from e
    except Exception as e:
        if isinstance(e, RolloutError) and e.row:
            row.update(e.row)
        else:
            row.update(status="unknown", rollback="unknown",
                       detail=f"SSH invocation failed; remote outcome unknown: {e}")
        row["duration_seconds"] = round(time.monotonic() - started, 3)
        raise RolloutError(str(e), row) from e
    row["duration_seconds"] = round(time.monotonic() - started, 3)
    return row


def main(argv=None) -> int:
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument("--dry-run", action="store_true", help="default; local validation only")
    p.add_argument("--apply", action="store_true", help="perform SSH rollout")
    p.add_argument("--nodes", nargs="+", choices=sorted(ALLOWLIST), default=list(ALLOWLIST))
    p.add_argument("--canary", choices=sorted(ALLOWLIST), default="es")
    p.add_argument("--jobs", type=int, default=3)
    p.add_argument("--report", type=Path, default=HERE / "push-report.json")
    args = p.parse_args(argv)
    if args.apply and args.dry_run:
        p.error("choose only one of --apply and --dry-run")
    if not 1 <= args.jobs <= 8:
        p.error("--jobs must be 1..8")
    if len(set(args.nodes)) != len(args.nodes):
        p.error("duplicate node")
    if args.apply and args.canary not in args.nodes:
        p.error("canary must be included in --nodes")
    try:
        expected = load_expected()
        payloads = load_payloads(expected)
        if args.apply:
            for node in args.nodes:
                ssh_args(node)
        canary = args.canary if args.canary in args.nodes else args.nodes[0]
        ordered = [canary] + [n for n in args.nodes if n != canary]
        report = {"started_utc": datetime.now(timezone.utc).isoformat(), "mode": "apply" if args.apply else "dry-run", "results": []}
        binaries = {n: ALLOWLIST[n][1] for n in ordered}
        failed = False
        if not args.apply:
            report["results"] = [invoke(n, binaries[n], False, payloads, expected) for n in ordered]
        else:
            # Canary always runs alone and is a hard gate. Keep DE out of a batch containing its jump clients.
            try:
                report["results"].append(invoke(canary, binaries[canary], True, payloads, expected))
            except Exception as e:
                report["results"].append(getattr(e, "row", None) or {"node": canary, "status": "failed", "detail": str(e), "rollback": "unknown"})
                failed = True
            if not failed:
                remaining = [n for n in ordered if n != canary]
                if "de" in remaining and any(n in remaining for n in ("nl1", "fin1")):
                    # DE is a jump host; update it only after its dependants finish.
                    remaining = [n for n in remaining if n != "de"] + ["de"]
                batches = []
                batch = []
                for n in remaining:
                    if n == "de" and any(x in batch for x in ("nl1", "fin1")):
                        batches.append(batch); batch = []
                    batch.append(n)
                    if len(batch) >= args.jobs:
                        batches.append(batch); batch = []
                if batch: batches.append(batch)
                for group in batches:
                    with concurrent.futures.ThreadPoolExecutor(max_workers=min(args.jobs, len(group))) as pool:
                        futures = {pool.submit(invoke, n, binaries[n], True, payloads, expected): n for n in group}
                        for f in concurrent.futures.as_completed(futures):
                            n = futures[f]
                            try: report["results"].append(f.result())
                            except Exception as e:
                                report["results"].append(getattr(e, "row", None) or {"node": n, "status": "failed", "detail": str(e), "rollback": "unknown"})
                                failed = True
                    if failed:
                        break
        report["finished_utc"] = datetime.now(timezone.utc).isoformat()
        report["status"] = "failed" if failed else ("dry-run" if not args.apply else "pass")
        args.report.parent.mkdir(parents=True, exist_ok=True)
        args.report.write_text(json.dumps(report, indent=2, ensure_ascii=False) + "\n")
        print(json.dumps(report, indent=2, ensure_ascii=False))
        return 1 if failed else 0
    except (RolloutError, OSError) as e:
        print(f"push.py: {e}", file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
