#!/usr/bin/env python3
"""Targeted real-runtime regression for delegated holder discovery.

Uses the existing E2E lab helpers and the production `admin-submit` bridge;
does not construct or edit trust state. It uses a per-process Docker prefix,
subnet and state directory so it cannot interfere with the live E2E run.

Expected current-code result: nonzero at delegated grant submission with
`holder_not_known_in_selected_root`. After a root-scoped T_REC visibility fix,
the same scenario must reach an applied durable ACK. No assertion treats the
current failure as a passing regression test.
"""
import importlib
import json
import os
import sys
import time
from types import SimpleNamespace


def safe_submit_fields(reply: dict) -> dict:
    """Only report public submission state; never echo request/identity data."""
    fields = ("accepted", "queued", "rejected", "state", "durable_ack")
    return {key: reply[key] for key in fields if key in reply}


def submit_after_local_holder_sync(scenarios, actor, target, *, holder, rights, root, timeout_s=180):
    """Wait for admin-submit's real disk-loaded Trust check to know the holder."""
    rid = scenarios.new_id()
    deadline = time.monotonic() + timeout_s
    attempt = 0
    while True:
        _, reply = scenarios.submit(actor, target, "rights.grant", holder=holder,
                                    rights=rights, root=root, rid=rid)
        attempt += 1
        safe = safe_submit_fields(reply)
        print(f"root grant local submit attempt {attempt}: {json.dumps(safe, sort_keys=True)}", flush=True)
        if reply.get("rejected") != "holder_not_known_in_selected_root" or time.monotonic() >= deadline:
            return rid, reply
        time.sleep(min(5, max(0, deadline - time.monotonic())))


def main() -> int:
    tag = str(os.getpid())
    # Override any caller's regular E2E settings: isolation is mandatory.
    os.environ["E2E_PREFIX"] = f"khdsync{tag}"
    os.environ["E2E_SUBNET"] = "192.0.2.0/24"
    os.environ["E2E_ROOT"] = os.path.expanduser(f"~/.cache/knothop-trust-sync/{tag}")

    sys.path.insert(0, os.path.dirname(__file__))
    lab = importlib.import_module("lxmf_host_access_e2e")
    scenarios = importlib.import_module("lxmf_host_access_e2e_scenarios")
    scenarios.H = lab
    own_lab_started = False
    try:
        lab.cmd_up(SimpleNamespace())
        own_lab_started = True
        scenarios.discover()

        target = scenarios.CTX["exit1"]["d"]
        root_r = scenarios.CTX["root"]
        root_s = scenarios.CTX["deleg"]
        usr_hash = scenarios.CTX["usr"]["hash"]

        # Non-admin in R must not gain admin status or mutation authority.
        _, nonadmin = scenarios.submit("usr", target, "status.get", root=root_r)
        if nonadmin.get("accepted") is True or nonadmin.get("queued") is True:
            raise AssertionError("USE-only identity was allowed to queue status.get")

        _, admin_status_submit, admin_status = scenarios.get_status("admin", "exit1")
        if admin_status_submit.get("accepted") is not True or admin_status.get("state") != "applied":
            raise AssertionError("admin could not establish authenticated target status")

        parts, _ = scenarios.participants("admin", "exit1")
        deleg_rights = (parts.get(root_s) or {}).get("rights", 63)
        # Client startup is asynchronous: the deleg identity may not yet have
        # reached the admin's persisted Trust snapshot. Re-run the normal
        # production admin-submit check with the same request id, boundedly,
        # until that holder is known or a different local error is observed.
        rid, sub = submit_after_local_holder_sync(
            scenarios, "admin", target, holder=root_s,
            rights=deleg_rights | 64, root=root_r,
        )
        if sub.get("accepted") is not True or sub.get("queued") is not True:
            raise AssertionError(
                "root scoped grant was not accepted and queued before status polling; "
                f"safe local submit fields={json.dumps(safe_submit_fields(sub), sort_keys=True)}"
            )
        final = scenarios.await_final("admin", rid)
        if final.get("state") != "applied":
            raise AssertionError(f"root could not delegate scoped HOST_ACCESS: {final.get('state')}")

        _, delegate_status_submit, delegate_status = scenarios.get_status("deleg", "exit1")
        if delegate_status_submit.get("accepted") is not True or delegate_status.get("state") != "applied":
            raise AssertionError("delegate could not establish authenticated target status")

        # The delegate's independent identity root S must not borrow target
        # membership or rights from its accepted network root R.
        _, foreign_root = scenarios.submit("deleg", target, "status.get", root=root_s)
        if foreign_root.get("rejected") != "target_not_in_selected_root":
            raise AssertionError(f"target escaped selected-root boundary: {foreign_root.get('rejected')}")

        # This assertion is intentionally a positive requirement. On the frozen
        # implementation it should fail locally before queuing because the
        # client's T_REC snapshot did not expose usr's public key in R.
        rid, sub = scenarios.submit(
            "deleg", target, "rights.grant", holder=usr_hash,
            rights=1 | 64, root=root_r,
        )
        if sub.get("rejected"):
            raise AssertionError(
                "delegated holder-discovery regression: expected a queued real "
                f"LXMF command, got {sub.get('rejected')} (request {rid[:8]})"
            )
        if sub.get("accepted") is not True or sub.get("queued") is not True:
            raise AssertionError(f"delegated grant was not queued: {sub}")
        final = scenarios.await_final("deleg", rid)
        if final.get("state") != "applied":
            raise AssertionError(f"delegated grant did not reach durable applied ACK: {final.get('state')}")

        print("PASS: non-admin denial, selected-root isolation, delegated holder sync and applied grant")
        return 0
    finally:
        if own_lab_started:
            # Removes only this script's PID-scoped containers/network; state is
            # retained under the PID-scoped cache path for owner inspection.
            lab.cmd_down(SimpleNamespace())


if __name__ == "__main__":
    raise SystemExit(main())
