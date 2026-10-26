#!/usr/bin/env python3
"""Targeted M1 diagnosis; existing lab observation is strictly read-only.

--observe: aggregate public trust/inbox evidence only, no ctl requests.
--run: NEW isolated Docker lab; uses prebuilt binaries, never common up/run.
No identity/PIN contents are read or printed by this script. CLI-generated
invite files move via docker cp; public identity IDs stay internal.
"""
import argparse
import importlib.util
import json
import os
from pathlib import Path
import time
import uuid

HERE = Path(__file__).resolve().parent


def load_harness():
    spec = importlib.util.spec_from_file_location("m1_harness", HERE / "lxmf_host_access_e2e.py")
    h = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(h)
    return h


def public_ids(h, names):
    # whoami CLI writes whoami.json; do NOT invoke it in read-only observation.
    return {n: h.jread(n, "/state/whoami.json")["hash"] for n in names}


def snapshot(h, name, root, holder):
    # Only public signed Record v1 files. Never enumerate/read identity or pins.
    code = '''import json,pathlib,hashlib,sys
p=pathlib.Path('/state'); root,holder=sys.argv[1:]
def rec(s):
 b=bytes.fromhex(s.strip())
 assert len(b)==171 and b[0]==1
 return {'rights':int.from_bytes(b[1:3],'little'),'seq':int.from_bytes(b[3:11],'little'),'root_match':b[11:27].hex()==root,'holder_match':hashlib.sha256(b[27:91]).digest()[:16].hex()==holder,'issuer_root':b[91:107].hex()==root}
t=json.loads((p/'trust.json').read_text()); rows=[rec(s) for s in t['recs']]
rows=[x for x in rows if x['root_match'] and x['holder_match']]
i=[]
if (p/'inbox13').exists():
 for f in (p/'inbox13').iterdir():
  if f.suffix in ('.rec','.rejected'):
   x=rec(f.read_text())
   if x['root_match'] and x['holder_match']: i.append(dict(x,suffix=f.suffix))
print(json.dumps({'trust_rows':rows,'inbox_rows':i}))
'''
    r = h.dx(name, "python3", "-c", code, root, holder, check=True)
    return json.loads(r.stdout)


def ctl(h, name, line):
    r = h.dx(name, "python3", "/e2e/lxmf_host_access_e2e_services.py", "ctl", "/run/ctl.sock", line, check=True)
    return json.loads(r.stdout.strip().splitlines()[-1])


def fresh_status(h, actor, target, root):
    rid = uuid.uuid4().hex
    path = f"/state/admin/client/{rid}.json"
    absent = h.dx(actor, "test", "-e", path).returncode == 1
    sub = ctl(h, actor, f"admin-submit --state /state --target {target} --root {root} --scope NODE --op status.get --request-id {rid}")
    end = time.monotonic() + 60
    fin = {}
    while sub.get("accepted") and time.monotonic() < end:
        fin = ctl(h, actor, f"admin-status --state /state --request-id {rid}")
        if fin.get("state") in ("applied", "rejected", "stale", "expired", "unknown"):
            break
        time.sleep(.5)
    # Client file contains the authenticated received envelope, unlike admin-view
    # (which may return an older capability). No raw envelope/key/ID is exported.
    j = h.jread(actor, path) or {}
    env = j.get("authenticated_envelope") or {}
    result = fin.get("result") or {}
    return {"fresh_id_absent_before": absent,
            "accepted": sub.get("accepted"), "queued": sub.get("queued"),
            "local_rejected": sub.get("rejected"), "state": fin.get("state"),
            "durable_ack": fin.get("durable_ack"),
            "authority_rights": (result.get("authority") or {}).get("rights"),
            "code": result.get("code"), "authenticated_envelope_present": bool(env),
            "request_id_matches": j.get("request", {}).get("requestid") == rid,
            "envelope_fields": sorted(env) if isinstance(env, dict) else [],
            "result_fields": sorted(result)}


def invite_file(h, name, rights):
    # Secret file is copied, not opened, parsed, or returned to the model.
    src = f"/state/.invite-{name}"
    r = h.dx("admin", "knothopd", "invite", "--state", "/state", "--rights", rights,
             "--label", name, "--out", src)
    if r.returncode:
        raise RuntimeError("invite CLI failed (output withheld)")
    dst = h.sdir(name) / "invite.txt"
    h.sh("docker", "cp", f"{h.NAME('admin')}:{src}", str(dst))
    os.chmod(dst, 0o600)
    h.dx("admin", "rm", src, check=True)


def image_sha(h, name):
    r = h.dx(name, "sha256sum", "/usr/local/bin/knothopd", check=True)
    return r.stdout.split()[0]


def persist(h, result):
    path = h.ROOT / "revocation-diagnosis.json"
    tmp = path.with_suffix(".tmp")
    fd = os.open(tmp, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    with os.fdopen(fd, "w") as f:
        json.dump(result, f, indent=2)
        f.flush()
        os.fsync(f.fileno())
    os.replace(tmp, path)


def root_client_bug(out):
    """Require commit evidence AND fresh authenticated replies, not CLI text."""
    try:
        base = out["after_15s"]["admin"]["trust_rows"][0]
        revoke = next(r for r in out["after_15s"]["admin"]["inbox_rows"]
                      if r["rights"] == 0 and r["issuer_root"] and r["seq"] > base["seq"])
        if revoke.get("suffix") != ".rec" or out["grant_cli"]["returncode"] != 0:
            return False
        for n in ("admin", "exit1", "deleg"):
            row = out["after_15s"][n]["trust_rows"][0]
            if row["rights"] != 63 or not row["issuer_root"] or row["seq"] != base["seq"]:
                return False
        for key in ("before_reply", "after_reply"):
            reply = out[key]
            if not all(reply.get(k) for k in ("fresh_id_absent_before", "accepted", "queued", "durable_ack", "authenticated_envelope_present", "request_id_matches")):
                return False
            if reply.get("state") != "applied" or reply.get("authority_rights") != 63:
                return False
        return True
    except (KeyError, IndexError, StopIteration):
        return False


def run(h):
    if h.P == "lxe2e" or h.ROOT.exists():
        raise RuntimeError("run requires a new non-shared prefix and state directory")
    h.sh("docker", "network", "create", "--internal", "--subnet", h.SUBNET, h.NET)
    names = []
    try:
        h.run("hub", h.HUB_IP, "exec knothopd hub --state /state --port 47000 --tcp-port 4242", extra=("-e", "KNOTHOP_REGION=ZZ"))
        names.append("hub")
        for n in ("admin", "exit1", "deleg"):
            (h.sdir(n) / "pub.txt").write_text(f"{h.HUB_IP}:4242\n")
        driver = "exec driver /run/ctl.sock /state -- client --state /state --public-rns-file /state/pub.txt"
        h.run("admin", f"{h.BASE}.12", driver, extra=("-e", "KNOTHOP_REGION=ZZ"))
        names.append("admin")
        h.wait(lambda: h.dx("admin", "test", "-S", "/run/ctl.sock").returncode == 0, 30, "admin ready")
        ids = {"admin": h.whoami("admin")["hash"]}
        root = ids["admin"]
        invite_file(h, "exit1", "relay")
        acl = '{"version":1,"aliases":[],"allow":[]}'
        h.run("exit1", h.EXIT1_IP, h.exit_cmd("exit1", h.EXIT1_IP, acl, root), extra=("-e", "KNOTHOP_REGION=ZZ"))
        names.append("exit1")
        h.wait(lambda: h.dx("exit1", "test", "-f", "/state/trust.json").returncode == 0, 90, "target trust")
        invite_file(h, "deleg", "admin")
        h.run("deleg", f"{h.BASE}.14", driver + " --invite-file /state/invite.txt", extra=("-e", "KNOTHOP_REGION=ZZ"))
        names.append("deleg")
        h.wait(lambda: h.dx("deleg", "test", "-S", "/run/ctl.sock").returncode == 0, 30, "delegate ready")
        ids.update({n: h.whoami(n)["hash"] for n in ("deleg", "exit1")})
        target = h.jread("exit1", "/state/server.json")["d"]
        def enrolled():
            try:
                rows = snapshot(h, "exit1", root, ids["deleg"])["trust_rows"]
                return rows and rows[0]["rights"] == 63
            except (RuntimeError, KeyError, ValueError):
                return False
        h.wait(enrolled, 120, "delegate delivered to target")
        h.wait(lambda: (h.jread("deleg", "/state/status.json") or {}).get("current"), 120, "delegate connected")
        out = {"binary_sha256": image_sha(h, "admin"), "before_reply": fresh_status(h, "deleg", target, root)}
        out["before"] = {n: snapshot(h, n, root, ids["deleg"]) for n in ("admin", "exit1", "deleg")}
        r = h.dx("admin", "knothopd", "grant", "--state", "/state", "--holder", ids["deleg"], "--rights", "none")
        out["grant_cli"] = {"returncode": r.returncode, "success_line_present": "подписана" in r.stdout,
                            "command": "knothopd grant --state /state --holder DELEG --rights none"}
        time.sleep(15)
        out["after_15s"] = {n: snapshot(h, n, root, ids["deleg"]) for n in ("admin", "exit1", "deleg")}
        out["after_reply"] = fresh_status(h, "deleg", target, root)
        out["root_client_inbox_bug_reproduced"] = root_client_bug(out)
        persist(h, out)
        # A supported consumer control: same root STATE/identity, now NodeCtx.
        # No record is injected into the target; root node must accept its own
        # queued signed CLI record and deliver it over normal T_REC mesh sync.
        h.sh("docker", "stop", "-t", "3", h.NAME("deleg"))
        h.sh("docker", "stop", "-t", "3", h.NAME("admin"))
        seed = h.jread("exit1", "/state/server.json")["e"]
        node_cmd = h.exit_cmd("admin", f"{h.BASE}.12", acl, root)
        node_cmd = node_cmd.replace(" --public-rns-file", f" --seed {seed}@{h.EXIT1_IP}:47001 --public-rns-file")
        h.run("admin", f"{h.BASE}.12", node_cmd, extra=("-e", "KNOTHOP_REGION=ZZ"))
        def revoked():
            a = snapshot(h, "admin", root, ids["deleg"])
            t = snapshot(h, "exit1", root, ids["deleg"])
            return a["trust_rows"] and t["trust_rows"] and a["trust_rows"][0]["rights"] == 0 and t["trust_rows"][0]["rights"] == 0
        h.wait(revoked, 120, "root-node inbox commit and target T_REC commit")
        out["node_consumer_control"] = {n: snapshot(h, n, root, ids["deleg"]) for n in ("admin", "exit1")}
        # Frozen actor state has never received the revocation. Its normal submit
        # remains authorized locally; enqueue promptly after runtime comes up.
        h.sh("docker", "start", h.NAME("deleg"))
        h.wait(lambda: h.dx("deleg", "test", "-S", "/run/ctl.sock").returncode == 0, 30, "delegate runtime")
        time.sleep(2)
        out["post_target_commit_reply"] = fresh_status(h, "deleg", target, root)
        out["actor_after_control"] = snapshot(h, "deleg", root, ids["deleg"])
        persist(h, out)
        return out
    finally:
        # Only our exact container names; keep isolated state/evidence on disk.
        for n in reversed(names):
            h.sh("docker", "rm", "-f", h.NAME(n), check=False)
        h.sh("docker", "network", "rm", h.NET, check=False)


def main():
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument("--observe", action="store_true")
    p.add_argument("--run", action="store_true")
    a = p.parse_args()
    if a.observe == a.run:
        p.error("choose --observe or --run")
    h = load_harness()
    if a.observe:
        ids = public_ids(h, ("admin", "deleg"))
        result = {n: snapshot(h, n, ids["admin"], ids["deleg"]) for n in ("admin", "exit1", "deleg")}
    else:
        result = run(h)
    print(json.dumps(result, indent=2))


if __name__ == "__main__":
    main()
