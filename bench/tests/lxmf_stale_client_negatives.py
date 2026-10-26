#!/usr/bin/env python3
"""Narrow K6/K7 and M0/M1 runtime probes on a private, immutable-binary Docker lab.

No production build or full E2E. Each container is region-pinned to ZZ and attached
only to a Docker --internal network. Synthetic trust/invite material stays in a
0600/0700 private lab root and is never printed.
"""
import hashlib
import json
import os
import secrets
import sys
import time
from pathlib import Path

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE))
import lxmf_host_access_e2e as H  # noqa: E402
import lxmf_host_access_e2e_scenarios as S  # noqa: E402

SNAP = Path.home() / ".cache/knothop-lxe2e-snapshots/integrated-20261024T164615"
MANIFEST = SNAP / "manifest.json"
EXPECTED_MANIFEST_SHA = "a5082faf7190648ae36d66987b4a4bc8cfb53683f2dfbeb5bace6ddb0408303b"
EXPECTED_NODE_SHA = "a723d5836bd542fc47d56688375a26080b21c98ec803e77c63d87ab628f871b8"
EXPECTED_DRIVER_SHA = "61d75ea632123259d5cba906b8da78b488e1b2f36949ffcb0e8a546008b8e931"
REGION = "ZZ"
SUBNET = "172.29.101.0/24"
NET = f"lxsneg-{time.strftime('%Y%m%d')}-{secrets.token_hex(3)}-net"
PREFIX = NET[:-4]
RUN_ID = PREFIX
ROOT = Path.home() / ".cache/knothop-lxe2e" / RUN_ID
BASE = SUBNET.rsplit(".", 1)[0]
HUB_IP, SITE_IP, EXIT1_IP, EXIT2_IP = (f"{BASE}.10", f"{BASE}.50", f"{BASE}.11", f"{BASE}.21")
CONTAINERS = ("hub", "site", "admin", "exit1", "exit2", "usr", "deleg", "foreign")
RESULTS = []
SPAWNED = []
NETWORK_CREATED = False


def file_sha(path):
    h = hashlib.sha256()
    with open(path, "rb") as f:
        for chunk in iter(lambda: f.read(1 << 20), b""):
            h.update(chunk)
    return h.hexdigest()


def record(sid, name, verdict, **fields):
    RESULTS.append({"id": sid, "name": name, "verdict": verdict, **fields})
    print(f"[{verdict}] {sid} {name} {json.dumps(fields, sort_keys=True)}", flush=True)


def short_submit(sub):
    return {k: sub.get(k) for k in ("accepted", "queued", "state", "rejected") if k in sub}


def short_final(fin):
    result = fin.get("result") or {}
    return {
        "state": fin.get("state"),
        "durable_ack": fin.get("durable_ack"),
        "code": result.get("code") if isinstance(result, dict) else None,
        "record_committed": result.get("record_committed") if isinstance(result, dict) else None,
        "effective_host_allowed": result.get("effective_host_allowed") if isinstance(result, dict) else None,
    }


def isolated_write(name, rel, text, mode="600"):
    # Root-owned bind-mount writes for the daemon's owner/mode checks; no network.
    H.sh("docker", "run", "--rm", "-i", "--network", "none", "-e", f"KNOTHOP_REGION={REGION}",
         "-v", f"{H.sdir(name)}:/state", "--entrypoint", "sh", H.IMAGE, "-c",
         f"umask 077; cat > /state/{rel}; chmod {mode} /state/{rel}", inp=text)


def lab_run(name, ip, cmd):
    cname = H.NAME(name)
    # Names are from this unique prefix only; the script refuses existing lab roots/networks.
    H.sh("docker", "run", "-d", "--name", cname, "--hostname", name, "--network", NET, "--ip", ip,
         "--label", f"knothop.stale-negatives={RUN_ID}",
         "--cap-add", "NET_ADMIN", "--cap-add", "NET_RAW", "--device", "/dev/net/tun",
         "--sysctl", "net.ipv4.ip_forward=1",
         "-e", f"KNOTHOP_REGION={REGION}", "-e", "KNOTHOP_DEBUG=1", "-e", "KNOTHOP_ALLOW_PRIVATE_DIAL=1",
         "-e", "KNOTHOP_TCP_BACKOFF_S=30",
         "-v", f"{H.BIN}:/usr/local/bin/knothopd:ro", "-v", f"{H.DRIVER}:/usr/local/bin/driver:ro",
         "-v", f"{HERE}:/e2e:ro", "-v", f"{H.sdir(name)}:/state",
         "--entrypoint", "sh", H.IMAGE, "-c", cmd)
    SPAWNED.append(cname)


def make_local_lab():
    global NETWORK_CREATED
    if file_sha(MANIFEST) != EXPECTED_MANIFEST_SHA:
        raise RuntimeError("snapshot manifest SHA mismatch")
    if file_sha(SNAP / "knothopd") != EXPECTED_NODE_SHA or file_sha(SNAP / "driver") != EXPECTED_DRIVER_SHA:
        raise RuntimeError("immutable snapshot binary SHA mismatch")
    if ROOT.exists() or H.sh("docker", "network", "inspect", NET, check=False).returncode == 0:
        raise RuntimeError("unique lab root or network already exists; refusing reuse")
    ROOT.mkdir(parents=True, mode=0o700)
    os.chmod(ROOT, 0o700)
    H.ROOT, H.P, H.NET, H.SUBNET = ROOT, PREFIX, NET, SUBNET
    H.NAME = lambda name: f"{PREFIX}-{name}"
    H.BASE = BASE
    H.HUB_IP, H.SITE_IP, H.EXIT1_IP, H.EXIT2_IP = HUB_IP, SITE_IP, EXIT1_IP, EXIT2_IP
    H.BIN, H.DRIVER = SNAP / "knothopd", SNAP / "driver"
    H.put_file = isolated_write

    H.sh("docker", "network", "create", "--internal", "--subnet", SUBNET,
         "--label", f"knothop.stale-negatives={RUN_ID}", NET)
    NETWORK_CREATED = True
    record("LAB", "private internal network created", "PASS", region=REGION, network=NET, subnet=SUBNET, root=str(ROOT))

    lab_run("hub", HUB_IP, "exec knothopd hub --state /state --port 47000 --tcp-port 4242")
    lab_run("site", SITE_IP,
            f"ip addr add {H.INET_IP}/32 dev lo; python3 /e2e/lxmf_host_access_e2e_services.py udplog 9999 /state/udp.log & "
            "exec python3 /e2e/lxmf_host_access_e2e_services.py web 80")
    for n in CONTAINERS:
        H.sdir(n)
        (H.sdir(n) / "pub.txt").write_text(f"{HUB_IP}:4242\n")

    admin_cmd = "exec driver /run/ctl.sock /state -- client --state /state --public-rns-file /state/pub.txt"
    lab_run("admin", f"{BASE}.12", admin_cmd)
    H.wait(lambda: H.dx("admin", "test", "-f", "/state/identity.key").returncode == 0, 45, "admin identity")
    root = H.whoami("admin")["hash"]
    acl = '{"version":1,"aliases":[],"allow":[]}'
    for name, ip in (("exit1", EXIT1_IP), ("exit2", EXIT2_IP)):
        invite = H.make_invite("admin", "relay", name)
        isolated_write(name, "invite.txt", invite + "\n")
        lab_run(name, ip, H.exit_cmd(name, ip, acl, policy_root=root))
        H.wait(lambda name=name: H.dx(name, "test", "-f", "/state/server.json").returncode == 0, 60, f"{name} server identity")

    usr_invite = H.make_invite("admin", "user", "usr")
    isolated_write("usr", "invite.txt", usr_invite + "\n")
    lab_run("usr", f"{BASE}.13", H.client_cmd())
    H.wait(lambda: root in (H.dx("usr", "cat", "/state/trust.json").stdout or ""), 90, "usr enrollment")

    deleg_invite = H.make_invite("admin", "admin", "deleg")
    isolated_write("deleg", "invite.txt", deleg_invite + "\n")
    lab_run("deleg", f"{BASE}.14", admin_cmd + " --invite-file /state/invite.txt")
    lab_run("foreign", f"{BASE}.15", admin_cmd)

    S.H = H
    S.CTX.clear()
    S.discover()
    S.select_exit(S.CTX["exit1"]["d"])
    H.wait(lambda: S.usr_exit().get("d") == S.CTX["exit1"]["d"], 150, "usr link to exit1")
    record("SETUP", "eight local synthetic containers enrolled and linked", "PASS", roles="hub/site/admin/exit1/exit2/usr/deleg/foreign")


def refresh(actor, node):
    rid, sub, fin = S.get_status(actor, node)
    record(f"STATUS-{actor}", f"fresh {actor} status.get", "PASS" if fin.get("state") == "applied" and fin.get("durable_ack") is True else "BLOCKED",
           state=fin.get("state"), durable_ack=fin.get("durable_ack"), queued=sub.get("queued"))
    return fin


def submit_known_bounded(actor, node, op, holder, rights, seconds=75):
    """Retry only a local known-holder guard; same request id, bounded, no trust-file edits."""
    rid = S.new_id()
    deadline = time.monotonic() + seconds
    while True:
        _, sub = S.submit(actor, S.CTX[node]["d"], op, holder=holder, rights=rights, rid=rid)
        if sub.get("rejected") != "holder_not_known_in_selected_root":
            break
        if time.monotonic() >= deadline:
            return rid, sub, None
        time.sleep(1)
    if sub.get("accepted") is not True or sub.get("queued") is not True:
        return rid, sub, None
    return rid, sub, S.await_final(actor, rid, 120)


def run_k_pair():
    d1 = S.CTX["exit1"]["d"]
    before = refresh("admin", "exit1")
    view = S.aview("admin", d1)
    caps = view.get("capabilities") or {}
    cap_ok = (before.get("state") == "applied" and before.get("durable_ack") is True
              and caps.get("host_access") is True and caps.get("rights_grant") is True and caps.get("rights_revoke") is True)
    ready = (H.jread("exit1", "/state/status.json") or {}).get("tun", {}).get("host_acl_ready") is True
    record("K-PRE", "root cache and ACL ready before mode change", "PASS" if cap_ok and ready else "BLOCKED",
           host_access=caps.get("host_access"), rights_grant=caps.get("rights_grant"), rights_revoke=caps.get("rights_revoke"), host_acl_ready=ready)
    if not cap_ok or not ready:
        for sid in ("K6", "K7"):
            record(sid, "ACL-unavailable signed transient rejection", "BLOCKED", reason="fresh authorized cache/ready precondition not established")
        return

    H.dx("exit1", "chmod", "644", "/state/host-acl.json", check=True)
    try:
        H.wait(lambda: (H.jread("exit1", "/state/status.json") or {}).get("tun", {}).get("host_acl_ready") is False,
               45, "exit1 host ACL readiness false", step=0.5)
    except TimeoutError as exc:
        for sid in ("K6", "K7"):
            record(sid, "ACL-unavailable signed transient rejection", "BLOCKED", reason="ACL readiness did not turn false")
        raise RuntimeError(str(exc))
    record("K-READY", "node reports host_acl_ready=false", "PASS")

    # Preserve the pre-transition, signed admin capability cache across both mutations.
    for sid, op in (("K6", "rights.grant"), ("K7", "rights.revoke")):
        rid, sub = S.submit("admin", d1, op, holder=S.CTX["usr"]["hash"], rights=64)
        fin = S.await_final("admin", rid, 60) if sub.get("accepted") is True and sub.get("queued") is True else S.astatus("admin", rid)
        verdict = S.signed_rejection_verdict(sub, fin, "host_acl_unavailable", durable=False)
        record(sid, f"{op} returns signed non-durable host_acl_unavailable", verdict,
               submit_accepted=sub.get("accepted"), queued=sub.get("queued"), submit_rejected=sub.get("rejected"), **_final_fields(fin))

    H.dx("exit1", "chmod", "600", "/state/host-acl.json", check=True)
    H.wait(lambda: (H.jread("exit1", "/state/status.json") or {}).get("tun", {}).get("host_acl_ready") is True,
           45, "exit1 host ACL readiness restored", step=0.5)
    recovered = refresh("admin", "exit1")
    if recovered.get("state") != "applied":
        record("K-RECOVERY", "root status after ACL recovery", "BLOCKED", state=recovered.get("state"))
    else:
        record("K-RECOVERY", "root status after ACL recovery", "PASS", durable_ack=recovered.get("durable_ack"))


def _final_fields(fin):
    result = fin.get("result") or {}
    return {"state": fin.get("state"), "durable_ack": fin.get("durable_ack"),
            "code": result.get("code") if isinstance(result, dict) else None,
            "record_committed": result.get("record_committed") if isinstance(result, dict) else None,
            "effective_host_allowed": result.get("effective_host_allowed") if isinstance(result, dict) else None}


def run_m_pair():
    d1 = S.CTX["exit1"]["d"]
    deleg_hash = S.CTX["deleg"]
    # Root-issued NODE-scoped HOST_ACCESS delegation; retry only the root CLI's local known-holder guard.
    root_before = refresh("admin", "exit1")
    root_caps = (S.aview("admin", d1).get("capabilities") or {})
    if root_before.get("state") != "applied" or root_caps.get("rights_grant") is not True:
        record("M-PREP-ROOT", "root can issue scoped delegation", "BLOCKED", host_access=root_caps.get("host_access"), rights_grant=root_caps.get("rights_grant"))
        return
    rid, sub, fin = submit_known_bounded("admin", "exit1", "rights.grant", deleg_hash, 127)
    if fin is None:
        record("M-PREP-DELEG", "root HOST_ACCESS grant to deleg", "BLOCKED", submit_accepted=sub.get("accepted"), queued=sub.get("queued"), rejected=sub.get("rejected"))
        return
    prep_result = (fin.get("result") or {})
    prep_ok = (fin.get("state") == "applied" and fin.get("durable_ack") is True
               and prep_result.get("record_committed") is True and prep_result.get("effective_host_allowed") is True)
    record("M-PREP-DELEG", "root NODE-scoped HOST_ACCESS grant to deleg", "PASS" if prep_ok else "FAIL",
           **_final_fields(fin), queued=sub.get("queued"))
    if not prep_ok:
        return

    # Establish real ordinary-holder knowledge and an applied delegate grant before revoke.
    deleg_status = refresh("deleg", "exit1")
    deleg_view = S.aview("deleg", d1)
    deleg_caps = deleg_view.get("capabilities") or {}
    deleg_authorities = (deleg_view.get("effective_authority") or {}).get("authorities") or [{}]
    deleg_authority = deleg_authorities[0]
    pre_can_grant = (deleg_status.get("state") == "applied" and deleg_status.get("durable_ack") is True
                     and deleg_caps.get("rights_grant") is True and deleg_authority.get("can_grant") is True)
    record("M-PRE-DELEG", "delegate has normal signed capability and scoped can_grant", "PASS" if pre_can_grant else "BLOCKED",
           status=deleg_status.get("state"), rights_grant=deleg_caps.get("rights_grant"), can_grant=deleg_authority.get("can_grant"))
    if not pre_can_grant:
        return

    usr_hash = S.CTX["usr"]["hash"]
    rid, sub, fin = submit_known_bounded("deleg", "exit1", "rights.grant", usr_hash, 64)
    if fin is None:
        record("M-PREP-USR", "delegate learns ordinary usr holder and gets grant", "BLOCKED",
               submit_accepted=sub.get("accepted"), queued=sub.get("queued"), rejected=sub.get("rejected"))
        return
    delegated_grant = fin.get("result") or {}
    usr_prep_ok = (fin.get("state") == "applied" and fin.get("durable_ack") is True
                   and delegated_grant.get("record_committed") is True
                   and delegated_grant.get("effective_host_allowed") is True)
    record("M-PREP-USR", "delegate's ordinary queued usr grant applies", "PASS" if usr_prep_ok else "FAIL",
           **_final_fields(fin), queued=sub.get("queued"))
    if not usr_prep_ok:
        return

    # Refresh both sides immediately before root-scoped revocation.
    deleg_before = refresh("deleg", "exit1")
    deleg_view = S.aview("deleg", d1)
    dcap = deleg_view.get("capabilities") or {}
    dauth = (deleg_view.get("effective_authority") or {}).get("authorities") or [{}]
    dauth = dauth[0]
    root_before = refresh("admin", "exit1")
    root_view = S.aview("admin", d1)
    rcap = root_view.get("capabilities") or {}
    rauth = (root_view.get("effective_authority") or {}).get("authorities") or [{}]
    rauth = rauth[0]
    pre_ok = (deleg_before.get("state") == "applied" and deleg_before.get("durable_ack") is True
              and dcap.get("host_access") is True and dcap.get("rights_grant") is True and dauth.get("can_grant") is True
              and root_before.get("state") == "applied" and root_before.get("durable_ack") is True
              and rcap.get("host_access") is True and rcap.get("rights_revoke") is True and rauth.get("can_revoke") is True)
    record("M-PRE", "fresh actor can_grant=true and root can_revoke=true before M0", "PASS" if pre_ok else "BLOCKED",
           delegate_can_grant=dauth.get("can_grant"), delegate_rights_grant=dcap.get("rights_grant"),
           root_can_revoke=rauth.get("can_revoke"), root_rights_revoke=rcap.get("rights_revoke"))
    if not pre_ok:
        record("M0", "root revokes NODE-scoped HOST_ACCESS from deleg", "BLOCKED", reason="pre-revoke capabilities not proven")
        record("M1", "stale delegate cache gets authority_insufficient", "BLOCKED", reason="M0 not run")
        return

    deleg_cache_time = time.monotonic()
    rid, sub = S.submit("admin", d1, "rights.revoke", holder=deleg_hash, rights=64)
    fin = S.await_final("admin", rid, 75) if sub.get("accepted") is True and sub.get("queued") is True else S.astatus("admin", rid)
    root_revoke = fin.get("result") or {}
    m0_ok = (sub.get("accepted") is True and sub.get("queued") is True
             and fin.get("state") == "applied" and fin.get("durable_ack") is True
             and root_revoke.get("record_committed") is True
             and root_revoke.get("effective_host_allowed") is False)
    record("M0", "root LXMF commits effective NODE HOST_ACCESS delegation revoke", "PASS" if m0_ok else "BLOCKED",
           submit_accepted=sub.get("accepted"), queued=sub.get("queued"), submit_rejected=sub.get("rejected"), **_final_fields(fin),
           ordinary_ADD_REMOVE="untouched")
    if not m0_ok:
        record("M1", "stale delegate cache gets authority_insufficient", "BLOCKED", reason="M0 not durably/effectively applied")
        return
    cache_age = time.monotonic() - deleg_cache_time
    cache_verdict = S.cache_freshness_verdict(cache_age, 600)
    record("M-CACHE", "delegate signed capability cache remains <600s; no refresh", cache_verdict, age_s=round(cache_age, 2))
    if cache_verdict != "PASS":
        record("M1", "stale delegate cache gets authority_insufficient", "BLOCKED", reason="legitimate cached capability expired")
        return

    # Deliberately no get_status()/admin-view on deleg after M0. Normal CLI must queue
    # using its still-valid signed cached snapshot; executor rechecks current NODE scope.
    rid, sub = S.submit("deleg", d1, "rights.grant", holder=usr_hash, rights=64)
    if sub.get("accepted") is not True or sub.get("queued") is not True:
        record("M1-client", "delegate submit using stale signed cache", "INFO", accepted=sub.get("accepted"), queued=sub.get("queued"), rejected=sub.get("rejected"))
        record("M1", "stale delegate cache gets authority_insufficient", "BLOCKED", reason="normal client did not queue request")
        return
    fin = S.await_final("deleg", rid, 75)
    verdict = S.signed_rejection_verdict(sub, fin, "authority_insufficient", durable=True)
    record("M1", "executor rejects stale delegate cache after scoped authority revoke", verdict,
           queued=sub.get("queued"), **_final_fields(fin))


def save_results():
    ROOT.mkdir(parents=True, exist_ok=True, mode=0o700)
    os.chmod(ROOT, 0o700)
    counts = {}
    for item in RESULTS:
        counts[item["verdict"]] = counts.get(item["verdict"], 0) + 1
    out = {
        "run_id": RUN_ID,
        "when_utc": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
        "scope": "K6/K7 + NODE HOST_ACCESS scoped authority M0/M1 only; not full suite",
        "region": REGION,
        "network_internal": True,
        "subnet": SUBNET,
        "snapshot": {"manifest_sha256": file_sha(MANIFEST), "knothopd_sha256": file_sha(H.BIN), "driver_sha256": file_sha(H.DRIVER)},
        "scenario_sha256": file_sha(HERE / "lxmf_host_access_e2e_scenarios.py"),
        "services_sha256": file_sha(HERE / "lxmf_host_access_e2e_services.py"),
        "counts": counts,
        "results": RESULTS,
    }
    path = ROOT / "stale-negatives-results.json"
    temp = ROOT / ".stale-negatives-results.tmp"
    fd = os.open(temp, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
    with os.fdopen(fd, "w") as f:
        json.dump(out, f, ensure_ascii=False, indent=2)
        f.flush()
        os.fsync(f.fileno())
    os.replace(temp, path)
    os.chmod(path, 0o600)
    print(f"RESULTS {json.dumps(counts)} {path}", flush=True)


def cleanup_own_lab():
    for cname in SPAWNED:
        H.sh("docker", "rm", "-f", cname, check=False, timeout=45)
    if NETWORK_CREATED:
        H.sh("docker", "network", "rm", NET, check=False, timeout=45)


def main():
    node_before = file_sha(SNAP / "knothopd")
    driver_before = file_sha(SNAP / "driver")
    scenarios_before = file_sha(HERE / "lxmf_host_access_e2e_scenarios.py")
    try:
        make_local_lab()
        run_k_pair()
        run_m_pair()
    except Exception as exc:  # capture the exact bounded blocker without printing credentials
        record("RUNTIME", "narrow probe interrupted", "BLOCKED", error_type=type(exc).__name__, message=str(exc)[:300])
    finally:
        try:
            save_results()
        finally:
            cleanup_own_lab()
    assert file_sha(SNAP / "knothopd") == node_before
    assert file_sha(SNAP / "driver") == driver_before
    assert file_sha(HERE / "lxmf_host_access_e2e_scenarios.py") == scenarios_before


if __name__ == "__main__":
    main()
