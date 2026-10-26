#!/usr/bin/env python3
"""Run archived E2E fixtures against a matched immutable host/driver snapshot.

Creates only a new internal Docker lab; preserves state/results and removes only
its exact container names. Does not compile, install, or change the shared lab.
"""
import argparse
from datetime import datetime, timezone
import hashlib
import importlib
import ipaddress
import json
import os
from pathlib import Path
import secrets
import subprocess
import sys
from types import SimpleNamespace


def digest(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


def unused_subnet():
    ids = subprocess.check_output(["docker", "network", "ls", "-q"], text=True).split()
    networks = json.loads(subprocess.check_output(["docker", "network", "inspect", *ids], text=True)) if ids else []
    used = [ipaddress.ip_network(item["Subnet"], strict=False) for net in networks
            for item in ((net.get("IPAM") or {}).get("Config") or []) if item.get("Subnet")]
    routes = json.loads(subprocess.check_output(["ip", "-j", "route", "show", "table", "all"], text=True))
    used += [ipaddress.ip_network(r["dst"], strict=False) for r in routes if r.get("dst") not in (None, "default")]
    for octet in range(102, 120):
        candidate = ipaddress.ip_network(f"172.29.{octet}.0/24")
        if not any(candidate.version == n.version and candidate.overlaps(n) for n in used):
            return str(candidate)
    raise RuntimeError("no unused test subnet found; no network changed")


def holder_in_saved_root(lab, role, root_hash, holder_hash):
    trust = lab.jread(role, "/state/trust.json") or {}
    for wire in trust.get("recs", []):
        try:
            record = bytes.fromhex(wire)
        except (TypeError, ValueError):
            continue
        if len(record) == 171 and record[0] == 1 and record[11:27].hex() == root_hash:
            if hashlib.sha256(record[27:91]).hexdigest()[:32] == holder_hash:
                return True
    return False


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("snapshot", type=Path)
    parser.add_argument("--only", default="")
    args = parser.parse_args()
    os.umask(0o077)
    snapshot = args.snapshot.expanduser().resolve()
    manifest_path = snapshot / "manifest.json"
    manifest = json.loads(manifest_path.read_text())
    if (snapshot / "INCOMPLETE").exists():
        raise RuntimeError("incomplete snapshot")
    archive = snapshot / "source-inputs"
    for relative, expected in manifest["inputs"]["files"].items():
        source = (archive / relative).resolve()
        if not source.is_relative_to(archive.resolve()) or digest(source) != expected:
            raise RuntimeError("archived input mismatch")
    for name in ("knothopd", "driver"):
        if digest(snapshot / name) != manifest["artifacts"][name]:
            raise RuntimeError("snapshot binary mismatch")

    run_id = "khfull-" + datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%S") + "-" + secrets.token_hex(3)
    parent = Path.home() / ".cache/knothop-lxe2e-runs"
    parent.mkdir(mode=0o700, exist_ok=True)
    root = parent / run_id
    root.mkdir(mode=0o700, exist_ok=False)
    subnet = unused_subnet()
    os.environ.update(E2E_BIN=str(snapshot / "knothopd"), E2E_DRIVER=str(snapshot / "driver"),
                      E2E_PREFIX=run_id, E2E_ROOT=str(root), E2E_SUBNET=subnet)
    sys.path.insert(0, str(archive / "bench/tests"))
    lab = importlib.import_module("lxmf_host_access_e2e")
    scenarios = importlib.import_module("lxmf_host_access_e2e_scenarios")
    raw_sh = lab.sh

    def private_sh(*command, **kwargs):
        if command[:2] == ("docker", "run"):
            at = command.index(lab.IMAGE)
            options = list(command[:at])
            if "--network" not in options:
                options += ["--network", "none"]
            command = (*options, "-e", "KNOTHOP_REGION=ZZ", *command[at:])
        return raw_sh(*command, **kwargs)

    lab.sh = private_sh
    raw_sh("docker", "image", "inspect", lab.IMAGE)
    raw_sh("docker", "network", "create", "--internal", "--subnet", subnet,
           "--label", f"knothop.e2e.owner={run_id}", lab.NET)
    metadata = {"snapshot": str(snapshot), "manifest_sha256": digest(manifest_path),
                "artifacts": manifest["artifacts"], "network_internal": True, "region": "ZZ",
                "subnet": subnet, "launcher_sha256": digest(Path(__file__)), "only": args.only}
    (root / "run-manifest.json").write_text(json.dumps(metadata, indent=2) + "\n")
    print(f"run_id={run_id} snapshot_manifest={metadata['manifest_sha256']}", flush=True)
    try:
        lab.cmd_up(SimpleNamespace())
        lab.wait(lambda: lab.dx("deleg", "test", "-f", "/state/identity.key").returncode == 0,
                 60, "delegate identity exists")
        root_hash = lab.whoami("admin")["hash"]
        members = [lab.whoami(role)["hash"] for role in ("usr", "deleg")]
        # Read-only readiness, not state insertion: normal enrollment/T_REC must finish.
        lab.wait(lambda: all(holder_in_saved_root(lab, role, root_hash, holder)
                             for role in ("admin", "exit1") for holder in members),
                 120, "normal enrollment saved on admin and target")
        return scenarios.run(lab, SimpleNamespace(only=args.only, bench=False))
    finally:
        roles = ("hub", "site", "admin", "exit1", "exit2", "usr", "usr2", "deleg", "foreign", "bad1", "bad2", "bad3")
        for role in roles:
            raw_sh("docker", "rm", "-f", lab.NAME(role), check=False)
        raw_sh("docker", "network", "rm", lab.NET, check=False)
        for name, expected in manifest["artifacts"].items():
            if digest(snapshot / name) != expected:
                raise RuntimeError("snapshot binary changed during run")
        print(f"state_preserved={root}", flush=True)


if __name__ == "__main__":
    raise SystemExit(main())
