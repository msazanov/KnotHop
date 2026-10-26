#!/usr/bin/env python3
"""Isolated targeted regression: root CLIENT CLI -> live Trust -> T_REC -> target revoke.

Requires freshly built canonical test knothopd AND embedded-client driver via
E2E_BIN/E2E_DRIVER. Never calls common harness up/run/wipe or switches root to node.
Synthetic invites move as files; identity/PIN contents are never opened/printed.
"""
import importlib.util
import json
import os
from pathlib import Path
import time

HERE = Path(__file__).resolve().parent
spec = importlib.util.spec_from_file_location("m1_diagnosis", HERE / "lxmf_actor_revocation_diagnosis.py")
D = importlib.util.module_from_spec(spec)
spec.loader.exec_module(D)


def executable_info(h, name):
    code = '''import pathlib,os,json,hashlib
out=[]
for p in pathlib.Path('/proc').iterdir():
 if not p.name.isdigit(): continue
 try:
  exe=p/'exe'; name=os.path.basename(os.readlink(exe))
  if name not in ('driver','knothopd','lxmf_host_access_e2e_driver'): continue
  digest=hashlib.sha256()
  with exe.open('rb') as f:
   for chunk in iter(lambda:f.read(1<<20),b''):digest.update(chunk)
  out.append({'executable':name,'sha256':digest.hexdigest()})
 except (FileNotFoundError,PermissionError,ProcessLookupError): pass
print(json.dumps(out))
'''
    return json.loads(h.dx(name, "python3", "-c", code, check=True).stdout)


def run(h):
    if h.P == "lxe2e" or h.ROOT.exists():
        raise RuntimeError("requires a NEW isolated prefix/state, never shared lab")
    h.sh("docker", "network", "create", "--internal", "--subnet", h.SUBNET, h.NET)
    names = []
    out = {"root_mode": "client throughout", "negative_authenticated_reply": "NOT RUN"}
    env = ("-e", "KNOTHOP_REGION=ZZ")
    try:
        h.run("hub", h.HUB_IP, "exec knothopd hub --state /state --port 47000 --tcp-port 4242", extra=env)
        names.append("hub")
        for n in ("admin", "exit1", "deleg"):
            (h.sdir(n) / "pub.txt").write_text(f"{h.HUB_IP}:4242\n")
        driver = "exec driver /run/ctl.sock /state -- client --state /state --public-rns-file /state/pub.txt"
        h.run("admin", f"{h.BASE}.12", driver, extra=env)
        names.append("admin")
        h.wait(lambda: h.dx("admin", "test", "-S", "/run/ctl.sock").returncode == 0, 30, "root client socket")
        root = h.whoami("admin")["hash"]
        D.invite_file(h, "exit1", "relay")
        acl = '{"version":1,"aliases":[],"allow":[]}'
        h.run("exit1", h.EXIT1_IP, h.exit_cmd("exit1", h.EXIT1_IP, acl, root), extra=env)
        names.append("exit1")
        h.wait(lambda: h.dx("exit1", "test", "-f", "/state/trust.json").returncode == 0, 90, "target trust")
        D.invite_file(h, "deleg", "admin")
        h.run("deleg", f"{h.BASE}.14", driver + " --invite-file /state/invite.txt", extra=env)
        names.append("deleg")
        h.wait(lambda: h.dx("deleg", "test", "-S", "/run/ctl.sock").returncode == 0, 30, "actor socket")
        deleg = h.whoami("deleg")["hash"]
        target = h.jread("exit1", "/state/server.json")["d"]

        def initial():
            try:
                rows = D.snapshot(h, "exit1", root, deleg)["trust_rows"]
                admin = h.jread("admin", "/state/status.json") or {}
                actor = h.jread("deleg", "/state/status.json") or {}
                return rows and rows[0]["rights"] == 63 and (admin.get("current") or {}).get("d") == target and (actor.get("current") or {}).get("d") == target
            except (RuntimeError, ValueError, KeyError):
                return False
        h.wait(initial, 120, "root and actor authenticated to target with original grant")
        out["runtime_executables"] = {n: executable_info(h, n) for n in ("admin", "exit1", "deleg")}
        out["before"] = {n: D.snapshot(h, n, root, deleg) for n in ("admin", "exit1", "deleg")}
        out["before_reply"] = D.fresh_status(h, "deleg", target, root)
        before = out["before_reply"]
        if not (before["state"] == "applied" and before["durable_ack"] and before["authenticated_envelope_present"] and before["authority_rights"] == 63):
            raise RuntimeError("baseline genuine direct LXMF applied/63 missing")

        # Offline actor intentionally keeps its authentic old snapshot. No manual
        # trust edits, request injection, signature bypass, or root role change.
        h.sh("docker", "stop", "-t", "3", h.NAME("deleg"))
        started = time.monotonic()
        r = h.dx("admin", "knothopd", "grant", "--state", "/state", "--holder", deleg, "--rights", "none")
        out["cli"] = {"returncode": r.returncode,
                      "local_queue_wording": "локальную очередь" in r.stdout,
                      "remote_unconfirmed_wording": "удалённое применение не подтверждено" in r.stdout,
                      "no_one_second_apply_promise": "~1" not in r.stdout}
        if r.returncode:
            raise RuntimeError("grant CLI failed (raw output withheld)")

        def committed():
            a = D.snapshot(h, "admin", root, deleg)
            t = D.snapshot(h, "exit1", root, deleg)
            ar, tr = a["trust_rows"], t["trust_rows"]
            return a if ar and tr and ar[0]["rights"] == tr[0]["rights"] == 0 and ar[0]["seq"] == tr[0]["seq"] and ar[0]["issuer_root"] and tr[0]["issuer_root"] else None
        h.wait(committed, 60, "CLIENT local commit and normal T_REC target commit")
        out["target_commit_after_seconds"] = round(time.monotonic() - started, 3)
        out["after"] = {n: D.snapshot(h, n, root, deleg) for n in ("admin", "exit1")}
        out["root_executable_after_commit"] = executable_info(h, "admin")
        # Counts/log text emitted only by the live consumer, never by offline CLI.
        log = h.dx("admin", "python3", "-c",
            "import pathlib,json; p=pathlib.Path('/state/log.txt'); print(json.dumps([s.split('inbox13 client:',1)[1] for s in p.read_text().splitlines() if 'inbox13 client:' in s]))", check=True)
        out["live_consumer_notes"] = json.loads(log.stdout)
        out["root_client_to_target_revoke"] = True
        D.persist(h, out)
        h.sh("docker", "start", h.NAME("deleg"))
        h.wait(lambda: h.dx("deleg", "test", "-S", "/run/ctl.sock").returncode == 0, 30, "actor restarted")
        time.sleep(2)
        out["next_fresh_request"] = D.fresh_status(h, "deleg", target, root)
        out["actor_after"] = D.snapshot(h, "deleg", root, deleg)
        out["target_after_fresh_request"] = D.snapshot(h, "exit1", root, deleg)
        reply = out["next_fresh_request"]
        out["next_fresh_request_not_applied"] = reply.get("fresh_id_absent_before") is True and reply.get("state") != "applied"
        target_rows = out["target_after_fresh_request"]["trust_rows"]
        out["target_revoke_survives_stale_actor"] = bool(target_rows and target_rows[0]["rights"] == 0 and target_rows[0]["seq"] == out["after"]["exit1"]["trust_rows"][0]["seq"])
        if reply.get("authenticated_envelope_present"):
            out["negative_authenticated_reply"] = "observed" if reply.get("state") == "rejected" else "other authenticated outcome"
        else:
            out["negative_authenticated_reply"] = "NOT RUN: no authenticated app reply; silence is not cryptographic rejection"
        D.persist(h, out)
        if not out["next_fresh_request_not_applied"] or not out["target_revoke_survives_stale_actor"]:
            raise RuntimeError("fresh request applied after target revoke")
        return out
    finally:
        if h.ROOT.exists():
            D.persist(h, out)
        for n in reversed(names):
            h.sh("docker", "rm", "-f", h.NAME(n), check=False)
        h.sh("docker", "network", "rm", h.NET, check=False)


if __name__ == "__main__":
    print(json.dumps(run(D.load_harness()), indent=2))
