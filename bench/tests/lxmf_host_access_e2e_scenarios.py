"""Сценарии E2E HOST_ACCESS + прямой LXMF-админ (запускаются из lxmf_host_access_e2e.py run).

Всё, что меняет права, идёт ТОЛЬКО через реальный путь: admin-submit/status/view (мост admin_cli_json в процессе клиента) ->
direct LXMF -> исполнитель на ноде -> подписанная запись -> durable save -> подписанный ACK -> ACL существующего Link.
Наблюдение - пакетное: curl/UDP из контейнера клиента через его TUN и сырые пакеты в TUN; состояние нод читается только как
доказательство (файлы trust/журнала), а не как способ менять права. Секреты не печатаются (identity лаборатории синтетические).
"""
import hashlib
import json
import os
import re
import time
from pathlib import Path

H = None            # модуль harness (lxmf_host_access_e2e)
RESULTS = []        # [{id, name, verdict, detail}]
CTX = {}            # root, usr, deleg, exit1/exit2 {d, id}, ...

SRC_DIR = Path(__file__).resolve().parent.parent / "rns-iroh-node"
SRC_FILES = ["src/lib.rs", "src/vpn.rs", "src/trust.rs", "src/lxmf_admin.rs", "src/host_acl.rs", "Cargo.toml", "Cargo.lock"]
SERVICES = "/e2e/lxmf_host_access_e2e_services.py"
HOST_ACCESS_ONLY = 64


# ------------------------------------------------------------------ учёт результатов
def rec(sid, name, verdict, detail=""):
    """verdict: PASS | FAIL | BLOCKED | INFO."""
    RESULTS.append({"id": sid, "name": name, "verdict": verdict, "detail": str(detail)[:900]})
    print(f"[{verdict:7}] {sid} {name}" + (f" - {str(detail)[:300]}" if detail else ""), flush=True)


def check(sid, name, cond, detail=""):
    rec(sid, name, "PASS" if cond else "FAIL", detail)
    return bool(cond)


def dependent_verdict(dependencies_ok, observed_ok):
    """Do not turn missing positive controls into green negative/security assertions."""
    if not dependencies_ok:
        return "BLOCKED"
    return "PASS" if observed_ok else "FAIL"


def dependent_check(sid, name, observed_ok, dependencies_ok, detail="", blocked_reason="positive prerequisite not established"):
    verdict = dependent_verdict(dependencies_ok, observed_ok)
    rec(sid, name, verdict, detail if dependencies_ok else f"{blocked_reason}; {detail}".strip("; "))
    return verdict == "PASS"


def stale_snapshot_verdict(submit_result, final_result):
    """Only a queued request with a durable terminal ACK can test server stale handling."""
    if submit_result.get("accepted") is not True or submit_result.get("queued") is not True:
        return "BLOCKED"
    if final_result.get("state") in (None, "unknown") or final_result.get("durable_ack") is not True:
        return "BLOCKED"
    return "PASS" if final_result.get("state") == "stale" else "FAIL"


def applied_mutation_verdict(submit_result, final_result):
    """Unknown/local-refusal is not an application failure; only durable target outcome is."""
    if submit_result.get("accepted") is not True or submit_result.get("queued") is not True:
        return "BLOCKED"
    if final_result.get("state") in (None, "unknown") or final_result.get("durable_ack") is not True:
        return "BLOCKED"
    return "PASS" if final_result.get("state") == "applied" else "FAIL"


def signed_rejection_verdict(submit_result, final_result, expected_code, durable):
    """Classify a client-verified target reply; transient rejects need not be durable."""
    if submit_result.get("accepted") is not True or submit_result.get("queued") is not True:
        return "BLOCKED"
    state = final_result.get("state")
    if state not in ("applied", "rejected", "stale", "expired"):
        return "BLOCKED"
    ack = final_result.get("durable_ack")
    if not isinstance(ack, bool):
        return "BLOCKED"
    if state == "applied":
        return "FAIL" if ack else "BLOCKED"
    result = final_result.get("result") or final_result
    if state != "rejected":
        return "FAIL" if ack else "BLOCKED"
    if result.get("code") != expected_code:
        return "FAIL"
    return "PASS" if ack is durable else "FAIL"


def capability_snapshot_verdict(status_result, capabilities, required):
    if status_result.get("state") != "applied" or status_result.get("durable_ack") is not True:
        return "BLOCKED"
    return "PASS" if all(capabilities.get(name) is True for name in required) else "FAIL"


def cache_freshness_verdict(age_seconds, ttl_seconds=600):
    return "PASS" if 0 <= age_seconds < ttl_seconds else "BLOCKED"


def participants_verdict(export_capability, participant, host_access_expected=False):
    """A disabled privacy capability blocks this assertion; it is not a feature pass."""
    if export_capability is not True:
        return "BLOCKED"
    if not participant:
        return "FAIL"
    return "PASS" if participant.get("host_access") is host_access_expected else "FAIL"


def sha(path):
    h = hashlib.sha256()
    with open(path, "rb") as f:
        for chunk in iter(lambda: f.read(1 << 20), b""):
            h.update(chunk)
    return h.hexdigest()


def sources():
    out = {}
    for rel in SRC_FILES:
        p = SRC_DIR / rel
        out[rel] = sha(p) if p.exists() else None
    out["bin:knothopd"] = sha(H.BIN)
    out["bin:driver"] = sha(H.DRIVER)
    out["tests:scenarios"] = sha(Path(__file__))
    out["tests:harness"] = sha(Path(H.__file__))
    return out


# ------------------------------------------------------------------ примитивы лаборатории
def ctl(name, line, timeout=40):
    r = H.dx(name, "python3", SERVICES, "ctl", "/run/ctl.sock", line, timeout=timeout)
    out = r.stdout.strip().splitlines()
    try:
        return json.loads(out[-1])
    except Exception:  # noqa: BLE001
        return {"_raw": (r.stdout + r.stderr)[-300:]}


def new_id():
    return os.urandom(16).hex()


def submit(actor, target, op, holder=None, rights=None, rid=None, root=None):
    rid = rid or new_id()
    line = f"admin-submit --state /state --target {target} --root {root or CTX['root']} --op {op} --scope NODE --request-id {rid}"
    if holder:
        line += f" --holder {holder}"
    if rights is not None:
        line += f" --rights {rights}"
    return rid, ctl(actor, line)


def astatus(actor, rid):
    return ctl(actor, f"admin-status --state /state --request-id {rid}")


def aview(actor, target):
    return ctl(actor, f"admin-view --state /state --target {target}")


def lose_client_ack(actor, rid):
    """Keep original request bytes/expiry/signature; only simulate loss of local ACK state."""
    if not re_full_request_id(rid):
        return False
    result = H.dx(actor, "python3", "/e2e/lxmf_e2e_replay.py", f"/state/admin/client/{rid}.json")
    return result.returncode == 0


def re_full_request_id(rid):
    return len(rid) == 32 and all(c in "0123456789abcdef" for c in rid)


# applied_not_effective: запись сохранена, но действующее решение не совпало с намерением; unknown: исход неизвестен (без автоповтора).
FINAL = ("applied", "rejected", "stale", "expired", "applied_not_effective", "unknown")


def await_final(actor, rid, secs=75):
    """Ждёт терминального состояния команды (durable ACK от ноды). Таймаут -> последнее увиденное состояние."""
    seen = []

    def fn():
        s = astatus(actor, rid)
        if not seen or seen[-1] != s.get("state"):
            seen.append(s.get("state"))
        return s if s.get("state") in FINAL else None

    try:
        s = H.wait(fn, secs, f"{actor} {rid[:8]} final", step=1.0)
    except TimeoutError:
        s = astatus(actor, rid)
    s["_seen"] = seen
    return s


def http(name, ip, port=8080, path="/", t=4):
    """(код, тело). 000 - не соединились/нет ответа за t секунд."""
    r = H.dx(name, "curl", "-s", "-m", str(t), "-w", "\n%{http_code}", f"http://{ip}:{port}{path}", timeout=t + 15)
    lines = r.stdout.rsplit("\n", 1)
    return (lines[-1].strip() or "000"), (lines[0] if len(lines) > 1 else "")


def fileread(name, path):
    r = H.dx(name, "cat", path)
    return r.stdout if r.returncode == 0 else ""


def k8_exit_refused(log_tail):
    """K8: в журнале клиента после рестарта есть отказ именно exit1 по неготовому ACL (имя выхода может быть с префиксом региона)."""
    return any(re.search(r"выход (\S+-)?exit1: .*отказал в доступе: exit not ready", line) for line in log_tail.splitlines())


def file_sha(name, path):
    r = H.dx(name, "sh", "-c", f"sha256sum {path} 2>/dev/null | cut -d' ' -f1")
    return r.stdout.strip()


def udp_logged(node, tag, log="/state/udp-host.log"):
    return tag in fileread(node, log)


def inject(src, dst, kind, tag, port=9998):
    H.dx("usr", "python3", SERVICES, "inject", "tun0", src, dst, kind, tag, str(port))


def exit_status(name):
    j = H.jread(name, "/state/status.json") or {}
    return j


def client_status(name):
    return H.jread(name, "/state/status.json") or {}


def usr_exit():
    cur = client_status("usr").get("current") or {}
    return cur


def wait_usr_link(want_d, secs=120):
    def fn():
        cur = usr_exit()
        return cur if cur.get("d") == want_d else None
    return H.wait(fn, secs, "usr link to exit", step=1.0)


def select_exit(d):
    H.dx("usr", "sh", "-c", f"printf '%s' {d} > /state/select")


def restart(name, secs=10):
    H.sh("docker", "restart", "-t", str(secs), H.NAME(name))


def discover():
    """Хеш корня, identity держателей и (dest, id) нод по видимому админу снимку."""
    CTX["root"] = H.whoami("admin")["hash"]
    CTX["usr"] = H.whoami("usr")
    CTX["deleg"] = H.whoami("deleg")["hash"]
    CTX["usr_rights"] = 1   # USE: пресет `user`, выданный harness-ом в up

    def seen():
        # показываемое имя может получить префикс (например, «страна-»): сопоставляем по суффиксу
        out = {}
        for e in (client_status("admin").get("exits") or []):
            for n in ("exit1", "exit2"):
                if str(e.get("n") or "").endswith(n) and e.get("id"):
                    out[n] = e
        return out if len(out) == 2 else None

    ex = H.wait(seen, 150, "admin sees exit1/exit2 with identity", step=2.0)
    for n in ("exit1", "exit2"):
        CTX[n] = {"d": ex[n]["d"], "id": ex[n]["id"]}


def get_status(actor, node):
    """status.get по LXMF до терминального ACK (нужен перед grant/revoke: capability кэш)."""
    rid, sub = submit(actor, CTX[node]["d"], "status.get")
    return rid, sub, await_final(actor, rid)


def participants(actor, node):
    v = aview(actor, CTX[node]["d"])
    return {p["holder"]: p for p in (v.get("participants") or [])}, v


def usr_rights(actor="admin", node="exit1"):
    parts, _ = participants(actor, node)
    return (parts.get(CTX["usr"]["hash"]) or {}).get("rights")


PIN_STABLE_S = 6        # client must have been on the target exit this long before a host probe
PIN_WAIT_S = 200        # exit failover after an exit restart lasted 60-120 s in the post-D1 run


def client_on_exit(cur, want_d):
    return bool(want_d) and cur.get("d") == want_d


def host_probe_state(code, want_d, before, after):
    """open | closed | unknown. A 200 can only come from the host service on the target exit.
    Any other result is evidence about the ACL only if the client stayed on that exit (Link not reset) for the whole probe;
    after an exit restart the client fails over to the other exit for 1-2 minutes and its host-bound SYN goes there."""
    if code == "200":
        return "open"
    stayed = (client_on_exit(before, want_d) and client_on_exit(after, want_d)
              and (after.get("since_s") or 0) >= (before.get("since_s") or 0))
    return "closed" if stayed else "unknown"


def host_probe_verdict(want_open, state):
    """unknown (client not on the target exit) is BLOCKED for both positive and negative host-TCP assertions."""
    if state == "unknown":
        return "BLOCKED"
    return "PASS" if (state == "open") == want_open else "FAIL"


def pin_usr_to_exit1(secs=PIN_STABLE_S, limit=None):
    """Wait until the client's current exit is exit1 and its Link there is `secs` old (no re-select spam: it causes address clashes)."""
    limit = PIN_WAIT_S if limit is None else limit
    want = CTX["exit1"]["d"]
    t0 = time.time()
    reselected = False
    while time.time() - t0 < limit:
        cur = usr_exit()
        if client_on_exit(cur, want) and (cur.get("since_s") or 0) >= secs:
            return True
        if not reselected and time.time() - t0 > 60:
            select_exit(want)       # one nudge: user selection makes the client re-try the pinned exit
            reselected = True
        time.sleep(1)
    return False


def host_state(ip=None, t=4, attempts=2):
    """(state, code): one host-bound TCP probe made only while usr is on exit1 and still there afterwards."""
    want = CTX["exit1"]["d"]
    code, state = "000", "unknown"
    for _ in range(attempts):
        if not pin_usr_to_exit1():
            return "unknown", "000 (usr not on exit1: failover)"
        before = usr_exit()
        code, _ = http("usr", ip or H.HOST_PUB, t=t)
        after = usr_exit()
        state = host_probe_state(code, want, before, after)
        if state != "unknown":
            return state, code
    return state, f"{code} (usr left exit1 during probe)"


def host_ok(ip=None, t=4):
    state, code = host_state(ip, t)
    return state == "open", code, ""


def stream_total(path="/tmp/stream.log"):
    lines = [l for l in fileread("usr", path).splitlines() if l.strip()]
    if not lines:
        return None
    try:
        return int(lines[-1].split()[1])
    except Exception:  # noqa: BLE001
        return None


# ------------------------------------------------------------------ сценарии
def s_baseline():
    """A/B: интернет без HOST; хост по умолчанию закрыт (и сам сервис жив: контроль с самого выхода)."""
    code, body = http("usr", H.INET_IP, 80, t=8)
    check("A1", "интернет через выход работает без HOST_ACCESS", code == "200", f"http={code}")
    try:
        seen_by_site = json.loads(body).get("you_are")
    except Exception:  # noqa: BLE001
        seen_by_site = None
    check("A2", "сайт видит адрес выхода (NAT), а не клиента", seen_by_site is not None and not str(seen_by_site).startswith("198.1"), f"you_are class={'nat' if seen_by_site and not str(seen_by_site).startswith('198.1') else seen_by_site}")
    ctrl = H.dx("exit1", "curl", "-s", "-m", "4", "-o", "/dev/null", "-w", "%{http_code}", f"http://{H.HOST_PUB}:8080/").stdout.strip()
    check("B0", "контроль: сервис выхода жив локально (отказ ниже - это ACL, не мёртвый сервис)", ctrl == "200", f"http={ctrl}")
    for sid, label, ip in (("B1", "публичный адрес самого выхода закрыт по умолчанию", H.HOST_PUB),
                           ("B2", "приватный адрес выхода закрыт", H.HOST_PRIV),
                           ("B3", "docker-мост выхода закрыт", H.DOCKER_IP),
                           ("B4", "служебный адрес khd0 (кроме health echo) закрыт для TCP", H.SVC_TUN)):
        state, code = host_state(ip, 4)
        rec(sid, label, host_probe_verdict(False, state), f"http={code} state={state}")


def s_status_before():
    rid, sub, fin = get_status("admin", "exit1")
    check("C1", "status.get: submit принят живым LXMF-процессором", sub.get("accepted") is True and sub.get("queued") is True, json.dumps(sub))
    check("C2", "status.get: терминальный applied только после ACK ноды", fin.get("state") == "applied" and fin.get("durable_ack") is True, f"seen={fin.get('_seen')} state={fin.get('state')}")
    v = aview("admin", CTX["exit1"]["d"])
    caps = v.get("capabilities") or {}
    auth = (v.get("effective_authority") or {}).get("authorities") or [{}]
    keys_ok = all(k in v for k in ("version", "target", "node", "capabilities", "effective_authority", "participants", "commands")) \
        and all(k in caps for k in ("host_access", "admin_commands", "status_get", "participants_export", "rights_grant", "rights_revoke"))
    check("C3", "admin-view соответствует JSON-контракту UI (ключи)", keys_ok, f"keys={sorted(v.keys())}")
    check("C4", "capabilities: HOST_ACCESS доступен, grant/revoke разрешены корню", caps.get("host_access") is True and caps.get("rights_grant") is True and caps.get("rights_revoke") is True, json.dumps(caps))
    check("C5", "узел помечен authenticated", (v.get("node") or {}).get("status") == "authenticated", json.dumps(v.get("node")))
    parts = {p["holder"]: p for p in (v.get("participants") or [])}
    usr = parts.get(CTX["usr"]["hash"])
    c6 = participants_verdict(caps.get("participants_export"), usr)
    rec("C6", "participants: usr виден, host_access=false до выдачи" if caps.get("participants_export") else "participants недоступны при privacy capability=false", c6,
        json.dumps(usr) if caps.get("participants_export") else "BLOCKED: participants_export=false; не расширять root-scoped export этим E2E")
    # пресеты выданы самим harness (invite --rights user/admin); если нода не экспортирует участников - берём известные значения
    CTX["usr_rights"] = (usr or {}).get("rights", 1)
    CTX["participants_exported"] = bool(parts)
    check("C7", "authority.scope=NODE и держатель корня", auth[0].get("scope") == "NODE" and auth[0].get("trusted") is True, json.dumps(auth[0]))


def s_delegation_restart():
    """J: delegate-record claims require actual pre-restart delegated grant and revoke."""
    d1 = CTX["exit1"]["d"]
    deleg = CTX["deleg"]
    parts, _ = participants("admin", "exit1")
    deleg_rights = (parts.get(deleg) or {}).get("rights", 63)
    _, _, root_status = get_status("admin", "exit1")
    if root_status.get("state") != "applied" or root_status.get("durable_ack") is not True:
        for sid, label in (("J1", "root delegates HOST_ACCESS"), ("J2", "delegate status.get"), ("J3", "delegate capabilities"),
                           ("J4", "delegate grant"), ("J5", "grant positive"), ("J6", "delegate revoke"), ("J7", "revoke negative")):
            rec(sid, label, "BLOCKED", "fresh admin status.get did not get durable applied ACK")
        delegated_grant = delegate_revoke = False
    else:
        rid, sub = submit("admin", d1, "rights.grant", holder=deleg, rights=deleg_rights | 64)
        fin = await_final("admin", rid)
        j1_verdict = applied_mutation_verdict(sub, fin)
        delegated_grant = j1_verdict == "PASS"
        rec("J1", "корень делегирует scoped HOST_ACCESS делегату (durable applied)", j1_verdict, f"sub={sub} fin={fin.get('state')}/{fin.get('result')}")
        _, _, st = get_status("deleg", "exit1")
        check("J2", "делегат получает status.get applied", st.get("state") == "applied" and st.get("durable_ack") is True, f"state={st.get('state')} seen={st.get('_seen')}")
        caps = (aview("deleg", d1).get("capabilities") or {})
        check("J3", "делегату видны grant/revoke (scoped authority)", caps.get("rights_grant") is True and caps.get("rights_revoke") is True, json.dumps(caps))
        usr_hash = CTX["usr"]["hash"]
        if not delegated_grant:
            for sid, label in (("J4", "delegate grants HOST_ACCESS"), ("J5", "delegated grant positive TCP"),
                               ("J6", "delegate revokes HOST_ACCESS"), ("J7", "delegated revoke negative TCP")):
                rec(sid, label, "BLOCKED", f"J1 not durably applied; submit={sub.get('rejected') or fin.get('state')}")
            delegate_revoke = False
        else:
            rid, sub = submit("deleg", d1, "rights.grant", holder=usr_hash, rights=HOST_ACCESS_ONLY)
            fin = await_final("deleg", rid)
            j4_verdict = applied_mutation_verdict(sub, fin)
            j4 = j4_verdict == "PASS"
            rec("J4", "делегат выдаёт HOST_ACCESS пользователю (durable applied)", j4_verdict, f"sub={sub} fin={fin.get('state')}/{fin.get('result')}")
            if not j4:
                for sid, label in (("J5", "delegated grant positive TCP"), ("J6", "delegate revokes HOST_ACCESS"), ("J7", "delegated revoke negative TCP")):
                    rec(sid, label, "BLOCKED", f"J4 not applied; submit={sub.get('rejected') or fin.get('state')}")
                delegate_revoke = False
            else:
                time.sleep(2)
                j5_state, code = host_state()
                j5 = j5_state == "open"
                rec("J5", "выданное делегатом действует на существующем Link без переподключения", host_probe_verdict(True, j5_state), f"http={code} state={j5_state}")
                _, _, fresh = get_status("deleg", "exit1")
                if fresh.get("state") != "applied" or fresh.get("durable_ack") is not True:
                    rec("J6", "делегат отзывает HOST_ACCESS", "BLOCKED", "нет fresh durable status.get перед revoke")
                    rec("J7", "после отзыва делегатом host снова закрыт", "BLOCKED", "J6 revoke не отправлен")
                    delegate_revoke = False
                else:
                    rid, sub = submit("deleg", d1, "rights.revoke", holder=usr_hash, rights=64)
                    fin = await_final("deleg", rid)
                    j6_verdict = applied_mutation_verdict(sub, fin)
                    delegate_revoke = j6_verdict == "PASS"
                    rec("J6", "делегат отзывает HOST_ACCESS (durable applied)", j6_verdict, f"sub={sub} fin={fin.get('state')}/{fin.get('result')}")
                    if not j5 or not delegate_revoke:
                        rec("J7", "после отзыва делегатом host снова закрыт", "BLOCKED", "нужны J5 positive grant и J6 durable revoke")
                    else:
                        time.sleep(2)
                        state, code = host_state()
                        rec("J7", "после отзыва делегатом хост снова закрыт", host_probe_verdict(False, state), f"http={code} state={state}")

    # Process restart/readiness is independent, but does not prove signed delegate-record reload.
    pre_sha = file_sha("exit1", "/state/host-access.json")
    restart("exit1")
    try:
        H.wait(lambda: (exit_status("exit1").get("tun") or {}).get("host_acl_ready") is True, 90, "exit1 host_acl_ready after restart", step=1.0)
        ready = True
    except TimeoutError:
        ready = False
    check("J8", "нода поднялась после рестарта (ACL ready; это не delegate-record proof)", ready, f"host-access.json sha before={pre_sha[:12]} after={file_sha('exit1', '/state/host-access.json')[:12]}; pre_restart_delegate_grant_revoke={delegated_grant and delegate_revoke}")
    if not ready:
        rec("J9", "после рестарта executor обрабатывает status.get", "BLOCKED", "node/ACL readiness prerequisite J8 failed")
        for sid in ("J10", "J11", "J12", "J13"):
            rec(sid, "delegated restart/scope check", "BLOCKED", "J8 readiness failed; no delegate-record proof")
        return
    try:
        wait_usr_link(CTX["exit1"]["d"], 150)
    except TimeoutError:
        rec("J9", "usr восстановил Link к exit1 после рестарта", "BLOCKED", "нет Link за 150 с; executor request path unavailable")
        for sid in ("J10", "J11", "J12", "J13"):
            rec(sid, "delegated restart/scope check", "BLOCKED", "client Link did not recover after restart")
        return
    time.sleep(8)
    _, _, st = get_status("admin", "exit1")
    check("J9", "после рестарта executor обрабатывает status.get", st.get("state") == "applied" and st.get("durable_ack") is True, f"state={st.get('state')} seen={st.get('_seen')}")
    if not (delegated_grant and delegate_revoke):
        for sid, label in (("J10", "delegate grant after restart (signed-record reload)"), ("J11", "delegated grant positive after restart"),
                           ("J12", "delegated revoke after restart"), ("J13", "delegate NODE scope")):
            rec(sid, label, "BLOCKED", "pre-restart delegate grant/revoke was not durably applied")
        return
    _, _, fresh = get_status("deleg", "exit1")
    if fresh.get("state") != "applied" or fresh.get("durable_ack") is not True:
        for sid, label in (("J10", "delegate grant after restart (signed-record reload)"), ("J11", "delegated grant positive after restart"), ("J12", "delegated revoke after restart")):
            rec(sid, label, "BLOCKED", "no fresh durable status.get after restart")
        return
    usr_hash = CTX["usr"]["hash"]
    rid, sub = submit("deleg", d1, "rights.grant", holder=usr_hash, rights=HOST_ACCESS_ONLY)
    fin = await_final("deleg", rid)
    j10_verdict = applied_mutation_verdict(sub, fin)
    j10 = j10_verdict == "PASS"
    rec("J10", "после рестарта делегат снова выдаёт (signed delegate-record reload)", j10_verdict, f"sub={sub} fin={fin.get('state')}/{fin.get('result')}")
    if not j10:
        for sid, label in (("J11", "delegated grant positive after restart"), ("J12", "delegated revoke after restart"), ("J13", "delegate NODE scope")):
            rec(sid, label, "BLOCKED", "J10 did not produce durable applied ACK")
        return
    time.sleep(2)
    j11_state, code = host_state()
    j11 = j11_state == "open"
    rec("J11", "новый grant делегата действует на Link, поднятом после рестарта", host_probe_verdict(True, j11_state), f"http={code} state={j11_state}")
    _, _, fresh = get_status("deleg", "exit1")
    if fresh.get("state") != "applied" or fresh.get("durable_ack") is not True:
        rec("J12", "отзыв делегата после рестарта действует", "BLOCKED", "no fresh durable status.get before revoke")
    else:
        rid, sub = submit("deleg", d1, "rights.revoke", holder=usr_hash, rights=64)
        fin = await_final("deleg", rid)
        j12 = fin.get("state") == "applied" and fin.get("durable_ack") is True
        if not j11 or not j12:
            rec("J12", "отзыв делегата после рестарта действует", "BLOCKED", f"needs J11 positive and J12 durable revoke; sub={sub}; state={fin.get('state')}")
        else:
            time.sleep(2)
            state, code = host_state()
            rec("J12", "отзыв делегата после рестарта действует", host_probe_verdict(False, state), f"http={code} state={state}")
    _, _, st2 = get_status("deleg", "exit2")
    v2 = aview("deleg", CTX["exit2"]["d"])
    caps2 = v2.get("capabilities") or {}
    if st2.get("state") != "applied":
        rec("J13", "delegate NODE scope", "BLOCKED", f"exit2 status.get={st2.get('state')}")
    elif caps2.get("rights_grant") is False:
        rec("J13", "scoped-право exit1 не открывает grant на exit2", "PASS", json.dumps(caps2))
    else:
        rid, sub = submit("deleg", CTX["exit2"]["d"], "rights.grant", holder=usr_hash, rights=HOST_ACCESS_ONLY)
        if sub.get("accepted") is not True or sub.get("queued") is not True:
            rec("J13", "scoped-право exit1 не открывает grant на exit2", "BLOCKED", f"request not delivered to target: {sub.get('rejected')}")
        else:
            fin = await_final("deleg", rid)
            check("J13", "scoped-право exit1 не даёт grant на exit2", fin.get("state") != "applied" and fin.get("durable_ack") is True, f"sub={sub} fin={fin.get('state')}/{fin.get('result')}")


def s_grant_flow():
    """D/E/F/G: корневой grant по LXMF -> хост открыт без переподключения; чужое остаётся закрытым; спуф/мусор; повтор id."""
    d1 = CTX["exit1"]["d"]
    usr_hash = CTX["usr"]["hash"]
    hsha0 = file_sha("exit1", "/state/host-access.json")
    state0, code0 = host_state()
    rec("D0", "перед grant хост закрыт", host_probe_verdict(False, state0), f"http={code0} state={state0}")
    cur0 = usr_exit()      # after the pin: D4 must compare Links on exit1, not on whichever exit the client failed over to
    _, _, fresh = get_status("admin", "exit1")
    if fresh.get("state") != "applied" or fresh.get("durable_ack") is not True:
        for sid in ("D1", "D2", "D3", "D4", "D5", "D6", "E1", "E2", "E3", "E4", "E5", "E6", "E7", "F1", "F2", "F3", "F4", "F9", "F10", "G1", "G2", "G3", "G4", "G5"):
            rec(sid, "root grant / dependent packet and replay checks", "BLOCKED", "no fresh durable status.get before mutation")
        return
    # Current representation under test is a standalone HOST_ACCESS record.
    rights = HOST_ACCESS_ONLY
    rid, sub = submit("admin", d1, "rights.grant", holder=usr_hash, rights=rights)
    CTX["grant_rid"] = rid
    if sub.get("accepted") is not True or sub.get("queued") is not True:
        rec("D1", "submit rights.grant принят очередью LXMF", "BLOCKED", f"local submit did not queue: {sub.get('rejected')}")
        rec("D2", "ACK ноды: applied + durable_ack", "BLOCKED", "request did not reach LXMF queue")
        for sid in ("D3", "D4", "D5", "E1", "E2", "E3", "E4", "E5", "E6", "E7", "F1", "F2", "F4", "F9", "G1", "G2", "G3", "G4", "G5"):
            rec(sid, "grant-dependent assertion", "BLOCKED", "root grant was not queued")
        code_net, _ = http("usr", H.INET_IP, 80, t=6)
        check("D6", "интернет-путь остаётся доступен", code_net == "200", f"http={code_net}")
        rec("F3", "internet source-spoof negative", "BLOCKED", "F10 valid internet UDP control not run")
        rec("F10", "valid internet UDP control", "BLOCKED", "grant flow exited before packet controls")
        return
    check("D1", "submit rights.grant принят очередью LXMF (queued, ещё не applied)", sub.get("state") == "pending", json.dumps(sub))
    fin = await_final("admin", rid)
    CTX["grant_fin"] = fin
    d2_verdict = applied_mutation_verdict(sub, fin)
    rec("D2", "ACK ноды: applied + durable_ack", d2_verdict, f"seen={fin.get('_seen')} result={fin.get('result')}")
    if d2_verdict != "PASS":
        for sid in ("D3", "D4", "D5", "E1", "E2", "E3", "E4", "E5", "E6", "E7", "F1", "F2", "F4", "F9", "G1", "G2", "G3", "G4", "G5"):
            rec(sid, "grant-dependent assertion", "BLOCKED", f"D2 not durable applied: {fin.get('state')}")
        code_net, _ = http("usr", H.INET_IP, 80, t=6)
        check("D6", "интернет-путь остаётся доступен", code_net == "200", f"http={code_net}")
        rec("F3", "internet source-spoof negative", "BLOCKED", "F10 valid internet UDP control not run")
        rec("F10", "valid internet UDP control", "BLOCKED", "grant flow exited before packet controls")
        return
    hsha1 = file_sha("exit1", "/state/host-access.json")
    check("D3", "к моменту applied запись уже durable на ноде (host-access.json изменился)", bool(hsha1) and hsha1 != hsha0, f"before={hsha0[:12]} after={hsha1[:12]}")
    time.sleep(2)
    cur1 = usr_exit()
    same_link = (cur0.get("d") == CTX["exit1"]["d"] and cur1.get("d") == cur0.get("d")
                 and (cur1.get("since_s") or 0) >= (cur0.get("since_s") or 0))
    check("D4", "тот же Link: usr не переподключался (since_s не сброшен)", same_link, f"since {cur0.get('since_s')} -> {cur1.get('since_s')}")
    d5_state, code = host_state()
    CTX["host_tcp_positive"] = d5_state == "open"
    rec("D5", "TCP к публичному адресу выхода открылся без переподключения", host_probe_verdict(True, d5_state), f"http={code} state={d5_state}")
    code_net, _ = http("usr", H.INET_IP, 80, t=6)
    check("D6", "интернет по-прежнему работает", code_net == "200", f"http={code_net}")
    # E1-E3 are meaningful ACL negatives only after the same client has a positive host-TCP control.
    for sid, label, ip in (("E1", "приватный адрес выхода без точного allow закрыт при grant", H.HOST_PRIV),
                           ("E2", "docker-мост выхода закрыт при grant", H.DOCKER_IP),
                           ("E3", "служебный khd0 закрыт для TCP при grant", H.SVC_TUN)):
        if not CTX["host_tcp_positive"]:
            rec(sid, label, "BLOCKED", "D5 positive host-TCP control failed")
        else:
            state, code = host_state(ip, 4)
            rec(sid, label, host_probe_verdict(False, state), f"http={code} state={state}")
    me = CTX["usr"]["ip"]
    # First establish an allowed packet through this exact raw-TUN injection path.
    inject(me, H.HOST_PUB, "ok", "E7ctrl")
    time.sleep(2)
    e7_ok = udp_logged("exit1", "E7ctrl")
    CTX["host_udp_positive"] = e7_ok
    check("E7", "контроль: UDP на публичный адрес выхода проходит через TUN injection", e7_ok)
    # Only now compare private/loopback/docker raw packets against the positive injection control.
    inject(me, H.EXIT1_IP, "ok", "E4eth0")
    inject(me, "127.0.0.1", "ok", "E5loop")
    inject(me, "172.17.0.1", "ok", "E6dock")
    time.sleep(2)
    for sid, label, tag in (("E4", "приватный адрес eth0 выхода закрыт при grant (UDP)", "E4eth0"),
                            ("E5", "loopback выхода закрыт при grant (UDP)", "E5loop"),
                            ("E6", "docker0 выхода закрыт при grant (UDP)", "E6dock")):
        dependent_check(sid, label, not udp_logged("exit1", tag), e7_ok, f"tag={tag}", "E7 valid raw-UDP injection control failed")
    # Independent positive controls for host-bound UDP and the internet UDP path.
    inject(me, H.HOST_PUB, "ok", "F9ctrl")
    inject(me, H.INET_IP, "ok", "F10ctrl", port=9999)
    time.sleep(2)
    f9_ok = udp_logged("exit1", "F9ctrl")
    f10_ok = udp_logged("site", "F10ctrl", "/state/udp.log")
    check("F9", "контроль: корректный host UDP того же клиента проходит", f9_ok)
    check("F10", "контроль: корректный internet UDP того же клиента доходит до сервиса", f10_ok)
    # F: inject malformed/spoofed packets only after the matching valid control has been observed.
    inject("198.19.99.9", H.HOST_PUB, "ok", "F1spoofclient")
    inject("8.8.8.8", H.HOST_PUB, "ok", "F2spoofpub")
    inject("8.8.8.8", H.INET_IP, "ok", "F3spoofnet", port=9999)
    kinds = ["badver", "ihl4", "longlen", "shortlen", "trunc", "opts", "frag", "gre"]
    for k in kinds:
        inject(me, H.HOST_PUB, k, f"F4{k}")
    time.sleep(2)
    dependent_check("F1", "подмена src другого клиента пула отброшена", not udp_logged("exit1", "F1spoofclient"), f9_ok,
                    "", "F9 valid host UDP control failed")
    dependent_check("F2", "подмена src публичным адресом отброшена на host-адрес", not udp_logged("exit1", "F2spoofpub"), f9_ok,
                    "", "F9 valid host UDP control failed")
    dependent_check("F3", "подмена src публичным адресом не доходит до internet UDP service", not udp_logged("site", "F3spoofnet", "/state/udp.log"), f10_ok,
                    "", "F10 valid internet UDP control failed")
    leaked = [k for k in kinds if udp_logged("exit1", f"F4{k}")]
    dependent_check("F4", "невалидный IPv4 на host отброшен", not leaked, f9_ok, f"прошли: {leaked}", "F9 valid host UDP control failed")
    # G: повтор id
    again = ctl("admin", f"admin-submit --state /state --target {d1} --root {CTX['root']} --op rights.grant --holder {usr_hash} --rights {rights} --scope NODE --request-id {rid}")
    check("G1", "повтор того же requestid: тот же applied-результат, без повторной очереди", again.get("accepted") is True and again.get("queued") is False and again.get("state") == "applied", json.dumps(again))
    conflict = ctl("admin", f"admin-submit --state /state --target {d1} --root {CTX['root']} --op rights.revoke --holder {usr_hash} --rights 64 --scope NODE --request-id {rid}")
    check("G2", "тот же requestid с другим действием: request_id_conflict", conflict.get("rejected") == "request_id_conflict", json.dumps(conflict))
    hsha2 = file_sha("exit1", "/state/host-access.json")
    check("G3", "повторы не меняют durable-запись на ноде", hsha2 == hsha1, f"{hsha1[:12]} vs {hsha2[:12]}")
    # Утрачен только ACK: удаление всей записи создало бы новую подпись/exp и законный конфликт digest.
    if not lose_client_ack("admin", rid):
        rec("G4", "идентичный запрос повторяется из серверного журнала", "BLOCKED", "исходный запрос отсутствует, не подтверждён или истёк")
        rec("G5", "журнальный повтор не меняет durable-запись", "BLOCKED", "нет валидного идентичного повтора G4")
        return
    again = ctl("admin", f"admin-submit --state /state --target {d1} --root {CTX['root']} --op rights.grant --holder {usr_hash} --rights {rights} --scope NODE --request-id {rid}")
    fin2 = await_final("admin", rid)
    same = fin2.get("state") == "applied" and (fin2.get("result") or {}) == (fin.get("result") or {})
    check("G4", "нода повторно отвечает из журнала тем же applied (revision/результат те же)", same and again.get("accepted") is True, f"first={fin.get('result')} second={fin2.get('result')}")
    check("G5", "журнальный повтор не меняет durable-запись", file_sha("exit1", "/state/host-access.json") == hsha1)


def s_revoke_flow():
    """H: ACK and internet/Link checks are independent; flow-revocation claims require H0."""
    d1 = CTX["exit1"]["d"]
    usr_hash = CTX["usr"]["hash"]
    if not CTX.get("host_tcp_positive"):
        rec("H0", "перед отзывом долгий host TCP поток идёт", "BLOCKED", "D5 positive host-TCP control was not established")
        h0 = False
    else:
        H.sh("docker", "exec", "-d", H.NAME("usr"), "python3", SERVICES, "stream", H.HOST_PUB, "8080", "60", "/tmp/stream.log")
        time.sleep(5)
        t0 = stream_total()
        time.sleep(3)
        t1 = stream_total()
        h0 = t0 is not None and t1 is not None and t1 > t0 > 0
        check("H0", "перед отзывом долгий host TCP поток идёт (байты растут)", h0, f"{t0} -> {t1}")
    _, _, fresh = get_status("admin", "exit1")
    if fresh.get("state") != "applied" or fresh.get("durable_ack") is not True:
        rec("H1", "revoke: ACK ноды applied + durable_ack", "BLOCKED", "нет fresh durable status.get перед revoke")
        for sid, label in (("H2", "existing stream blocked after revoke"), ("H3", "new host TCP denied after revoke")):
            rec(sid, label, "BLOCKED", "revoke not sent")
        # Independent observations remain useful and are still recorded below.
        code_net, _ = http("usr", H.INET_IP, 80, t=6)
        check("H4", "интернет-путь доступен на этой фазе", code_net == "200", f"http={code_net}")
        check("H5", "тот же Link у usr (revoke не рвал соединение)", usr_exit().get("d") == CTX["exit1"]["d"], json.dumps({"since_s": usr_exit().get("since_s")}))
        return
    rid, sub = submit("admin", d1, "rights.revoke", holder=usr_hash, rights=64)
    fin = await_final("admin", rid)
    h1_verdict = applied_mutation_verdict(sub, fin)
    h1 = h1_verdict == "PASS"
    rec("H1", "revoke: ACK ноды applied + durable_ack", h1_verdict, f"sub={sub} result={fin.get('result')}")
    if h1 and h0:
        time.sleep(3)
        a = stream_total()
        time.sleep(8)
        b = stream_total()
        check("H2", "после ACK revoke существующий поток перестаёт получать данные", a is not None and b is not None and b - a <= 2048, f"{a} -> {b} за 8 с")
        state, code = host_state()
        rec("H3", "после revoke новые host TCP соединения закрыты", host_probe_verdict(False, state), f"http={code} state={state}")
    else:
        reason = "H1 revoke not durably applied" if not h1 else "H0 stream byte growth not established"
        rec("H2", "после revoke existing flow перестаёт получать данные", "BLOCKED", reason)
        rec("H3", "после revoke новые host TCP соединения закрыты", "BLOCKED", reason)
    code_net, _ = http("usr", H.INET_IP, 80, t=6)
    check("H4", "интернет не пострадал от revoke", code_net == "200", f"http={code_net}")
    check("H5", "тот же Link у usr (revoke не рвал соединение)", usr_exit().get("d") == CTX["exit1"]["d"], json.dumps({"since_s": usr_exit().get("since_s")}))


def s_persist_restart():
    """I: durable grant переживает рестарт ноды; ACK идемпотентен после рестарта."""
    d1 = CTX["exit1"]["d"]
    usr_hash = CTX["usr"]["hash"]
    _, _, status = get_status("admin", "exit1")
    if status.get("state") != "applied" or status.get("durable_ack") is not True:
        for sid in ("I0", "I1", "I2", "I3", "I4", "I5"):
            rec(sid, "grant/restart/idempotency", "BLOCKED", "нет свежего подтверждённого status.get")
        return
    rights = HOST_ACCESS_ONLY
    rid, sub = submit("admin", d1, "rights.grant", holder=usr_hash, rights=rights)
    fin = await_final("admin", rid)
    i0_verdict = applied_mutation_verdict(sub, fin)
    rec("I0", "повторная выдача корнем после отзыва: durable applied", i0_verdict, f"sub={sub} result={fin.get('result')}")
    if i0_verdict != "PASS":
        for sid in ("I1", "I2", "I3", "I4", "I5"):
            rec(sid, "persist/restart grant", "BLOCKED", "выдача I0 не подтверждена")
        return
    time.sleep(2)
    state, code = host_state()
    rec("I1", "до рестарта хост открыт", host_probe_verdict(True, state), f"http={code} state={state}")
    sha_before = file_sha("exit1", "/state/host-access.json")
    restart("exit1")
    H.wait(lambda: (exit_status("exit1").get("tun") or {}).get("host_acl_ready") is True, 90, "exit1 ready", step=1.0)
    try:
        wait_usr_link(d1, 150)
    except TimeoutError:
        pass            # host_state() waits for the client to return to exit1 and reports BLOCKED if it never does
    time.sleep(8)
    check("I2", "host-access.json тот же после рестарта (durable)", file_sha("exit1", "/state/host-access.json") == sha_before)
    state, code = host_state(t=6)
    rec("I3", "после рестарта ноды и нового Link grant действует", host_probe_verdict(True, state), f"http={code} state={state}")
    if not lose_client_ack("admin", rid):
        rec("I4", "идентичный запрос после рестарта", "BLOCKED", "исходный запрос отсутствует, не подтверждён или истёк")
        rec("I5", "журнальный повтор не меняет запись", "BLOCKED", "нет валидного идентичного повтора I4")
        return
    again = ctl("admin", f"admin-submit --state /state --target {d1} --root {CTX['root']} --op rights.grant --holder {usr_hash} --rights {rights} --scope NODE --request-id {rid}")
    fin2 = await_final("admin", rid)
    check("I4", "тот же requestid после рестарта: нода возвращает тот же applied из журнала", fin2.get("state") == "applied" and (fin2.get("result") or {}) == (fin.get("result") or {}), f"again={again.get('accepted')} first={fin.get('result')} second={fin2.get('result')}")
    check("I5", "журнальный ответ не дублирует запись", file_sha("exit1", "/state/host-access.json") == sha_before)


def s_acl_config():
    """K: недействительный host ACL -> отказ, без AUTH_OK; восстановление."""
    # K1: нет конфигурации -> узел не стартует (fail-closed до допуска клиентов)
    bad = "bad1"
    H.sh("docker", "rm", "-f", H.NAME(bad), check=False)
    H.put_file(bad, "invite.txt", H.make_invite("admin", "relay", bad))
    (H.sdir(bad) / "pub.txt").write_text(f"{H.HUB_IP}:4242\n")
    H.run(bad, f"{H.BASE}.31", H.exit_cmd(bad, f"{H.BASE}.31", None, policy_root=CTX["root"]))
    time.sleep(12)
    st = H.sh("docker", "inspect", "-f", "{{.State.Running}} {{.State.ExitCode}}", H.NAME(bad), check=False).stdout.strip()
    log = fileread(bad, "/state/node.log") if st.startswith("true") else H.sh("docker", "logs", "--tail", "30", H.NAME(bad), check=False).stdout
    check("K1", "ACL-файла нет -> нода не поднимает приём (процесс завершён)", st.startswith("false"), f"state={st}")
    ex = {e.get("n"): e for e in (client_status("admin").get("exits") or [])}
    check("K2", "и не появляется у админа как доступный выход", "bad1" not in ex or not ex["bad1"].get("v"), json.dumps(ex.get("bad1")))
    H.sh("docker", "rm", "-f", H.NAME(bad), check=False)
    # Keep a legitimate, fresh admin capability snapshot across the ACL-readiness transition.
    d1 = CTX["exit1"]["d"]
    _, _, pre_acl_status = get_status("admin", "exit1")
    pre_acl_view = aview("admin", d1)
    pre_acl_caps = pre_acl_view.get("capabilities") or {}
    pre_acl_verdict = capability_snapshot_verdict(pre_acl_status, pre_acl_caps, ("host_access", "rights_grant", "rights_revoke"))
    pre_acl_cache_ok = pre_acl_verdict == "PASS"
    rec("K0", "fresh signed root capability cache before ACL readiness transition", pre_acl_verdict,
        json.dumps({"status": pre_acl_status.get("state"), "capabilities": pre_acl_caps}))
    k_state, k_host_code = host_state()
    k_host_positive = k_state == "open"
    rec("K0-host", "host TCP positive immediately before ACL mode change", "PASS" if k_host_positive else "BLOCKED", f"http={k_host_code} state={k_state}")

    # K3: chmod invalidates ACL readiness while preserving the just-verified client cache.
    H.dx("exit1", "chmod", "644", "/state/host-acl.json")
    try:
        H.wait(lambda: (exit_status("exit1").get("tun") or {}).get("host_acl_ready") is False, 40, "ready false", step=1.0)
        flipped = True
    except TimeoutError:
        flipped = False
    check("K3", "небезопасный режим host-acl.json -> host_acl_ready=false (fail-closed)", flipped)
    # ACL not ready: the client Link is not re-admitted by a restart here, but it must still be on exit1 for a closed result to mean anything.
    k4_state, code = host_state()
    dependent_check("K4", "при неготовом ACL host TCP блокируется", k4_state == "closed", k_host_positive and k4_state != "unknown", f"http={code} state={k4_state}", "K0-host positive host-TCP control failed or usr not on exit1")
    code_net, _ = http("usr", H.INET_IP, 80, t=6)
    rec("K5", "наблюдение: интернет при неготовом ACL", "INFO", f"http={code_net}")
    if not pre_acl_cache_ok:
        rec("K6", "grant на target при ACL-unavailable получает signed transient refusal", "BLOCKED", "fresh authorized cache not established before ACL transition")
        rec("K7", "revoke на target при ACL-unavailable получает signed transient refusal", "BLOCKED", "fresh authorized cache not established before ACL transition")
    elif not flipped:
        rec("K6", "grant на target при ACL-unavailable получает signed transient refusal", "BLOCKED", "K3 did not establish host_acl_ready=false")
        rec("K7", "revoke на target при ACL-unavailable получает signed transient refusal", "BLOCKED", "K3 did not establish host_acl_ready=false")
    else:
        # Do not refresh status here: the signed, still-fresh pre-transition cache is
        # required so both mutations reach the executor and test its current tun_ready gate.
        rid, sub = submit("admin", d1, "rights.grant", holder=CTX["usr"]["hash"], rights=HOST_ACCESS_ONLY)
        fin = await_final("admin", rid)
        k6_verdict = signed_rejection_verdict(sub, fin, "host_acl_unavailable", durable=False)
        rec("K6", "grant reaches executor and gets signed non-durable host_acl_unavailable", k6_verdict,
            f"submit={sub} state={fin.get('state')} durable_ack={fin.get('durable_ack')} result={fin.get('result')}")
        rid2, sub2 = submit("admin", d1, "rights.revoke", holder=CTX["usr"]["hash"], rights=HOST_ACCESS_ONLY)
        fin2 = await_final("admin", rid2)
        k7_verdict = signed_rejection_verdict(sub2, fin2, "host_acl_unavailable", durable=False)
        rec("K7", "revoke reaches executor and gets signed non-durable host_acl_unavailable", k7_verdict,
            f"submit={sub2} state={fin2.get('state')} durable_ack={fin2.get('durable_ack')} result={fin2.get('result')}")
    # новый Link при неготовом ACL: exit1 не выдаёт AUTH_OK. Другой готовый выход (exit2) клиент выбрать вправе,
    # поэтому проверяем именно отказ exit1 и то, что текущим выходом не стал exit1.
    log_mark = len(fileread("usr", "/state/client.log"))
    restart("usr")
    time.sleep(25)
    cur = usr_exit()
    tail = fileread("usr", "/state/client.log")[log_mark:]
    refused = k8_exit_refused(tail)
    check("K8", "новый Link к exit1 при неготовом ACL не допущен (exit not ready, текущий выход не exit1)",
          refused and cur.get("d") != d1,
          json.dumps({"current_is_exit1": cur.get("d") == d1, "exit1_refused_not_ready": refused, "state": client_status("usr").get("state")}))
    H.dx("exit1", "chmod", "600", "/state/host-acl.json")
    try:
        H.wait(lambda: (exit_status("exit1").get("tun") or {}).get("host_acl_ready") is True, 40, "ready true", step=1.0)
        back = True
    except TimeoutError:
        back = False
    check("K9", "после восстановления файла ACL снова ready", back)
    # Refresh only after both transient rejection probes and readiness recovery.
    _, _, recovered = get_status("admin", "exit1")
    rec("K9-status", "root capability cache refreshed after ACL recovery", "PASS" if recovered.get("state") == "applied" and recovered.get("durable_ack") is True else "BLOCKED",
        f"state={recovered.get('state')} durable_ack={recovered.get('durable_ack')}")
    try:
        wait_usr_link(d1, 150)
        link = True
    except TimeoutError:
        link = False
    check("K10", "usr снова допущен после восстановления", link)


def s_negatives():
    """L/M/N: чужой корень, отозванный актор, устаревший срез, no policy."""
    d1 = CTX["exit1"]["d"]
    usr_hash = CTX["usr"]["hash"]
    # L: чужой корень (клиент без приглашения, свой корень)
    rid, sub = submit("foreign", d1, "status.get", root=CTX["root"])
    check("L1", "чужой корень: submit отклонён локально, не очередь LXMF", sub.get("accepted") is False and sub.get("queued") is False, json.dumps(sub))
    fa = ctl("foreign", f"admin-view --state /state --target {d1}")
    check("L2", "чужой корень: admin-view не раскрывает возможностей", (fa.get("capabilities") or {}).get("rights_grant") is not True, json.dumps(fa.get("capabilities")))
    # N: устаревший срез прав -> stale_rights_snapshot (нода сверяет не-64 часть)
    base = CTX.get("usr_rights") or 0
    _, _, fresh = get_status("admin", "exit1")
    if fresh.get("state") != "applied" or fresh.get("durable_ack") is not True:
        rec("N1", "устаревший срез прав: нода отвечает stale, не applied", "BLOCKED", "no fresh durable status.get before stale-snapshot mutation")
        rec("N2", "HOST-политика ноды: configured roots", "INFO", "policy fixture is configured; no policy mutation tested")
        return
    rid, sub = submit("admin", d1, "rights.grant", holder=usr_hash, rights=(base ^ 4) | 64)
    if sub.get("accepted") is not True or sub.get("queued") is not True:
        rec("N1", "устаревший срез прав: нода отвечает stale, не applied", "BLOCKED", f"submit did not reach LXMF queue: {sub.get('rejected')}")
    else:
        fin = await_final("admin", rid)
        verdict = stale_snapshot_verdict(sub, fin)
        rec("N1", "устаревший срез прав: нода отвечает stale, не applied", verdict,
            f"state={fin.get('state')} durable_ack={fin.get('durable_ack')} result={fin.get('result')}")
    # no policy на exit2 для чужого корня недоступно без второго корня; проверяем фактическую политику
    rec("N2", "HOST-политика ноды (M5): корень admin разрешён host-policy.json на exit1/exit2", "INFO", "host-policy.json создан оператором в лаборатории")


def s_revoked_actor():
    """M: root-scoped NODE HOST_ACCESS authority revocation; not generic ADD/REMOVE revocation."""
    d1 = CTX["exit1"]["d"]
    deleg = CTX["deleg"]
    rec("M2", "generic ordinary ADD/REMOVE revocation", "INFO", "NOT RUN: this case only revokes NODE-scoped HOST_ACCESS; generic root-client inbox revocation is separate")

    # Legitimate cached delegate capability is established before M0, and must remain
    # unrefreshed after M0 so the normal client queues the stale-capability mutation.
    _, _, deleg_before = get_status("deleg", "exit1")
    deleg_cache_received = time.monotonic()
    deleg_view_before = aview("deleg", d1)
    deleg_caps_before = deleg_view_before.get("capabilities") or {}
    deleg_authorities = (deleg_view_before.get("effective_authority") or {}).get("authorities") or [{}]
    deleg_authority_before = deleg_authorities[0]
    deleg_pre = capability_snapshot_verdict(deleg_before, deleg_caps_before, ("host_access", "rights_grant", "rights_revoke"))
    if deleg_pre == "PASS" and deleg_authority_before.get("can_grant") is not True:
        deleg_pre = "FAIL"
    rec("M-pre-deleg", "delegate has fresh signed scoped grant capability before root revoke", deleg_pre,
        json.dumps({"status": deleg_before.get("state"), "capabilities": deleg_caps_before, "authority": deleg_authority_before}))

    _, _, root_before = get_status("admin", "exit1")
    root_view_before = aview("admin", d1)
    root_caps_before = root_view_before.get("capabilities") or {}
    root_authorities = (root_view_before.get("effective_authority") or {}).get("authorities") or [{}]
    root_authority_before = root_authorities[0]
    root_pre = capability_snapshot_verdict(root_before, root_caps_before, ("host_access", "rights_revoke"))
    if root_pre == "PASS" and root_authority_before.get("can_revoke") is not True:
        root_pre = "FAIL"
    rec("M-pre-root", "root has fresh signed capability to revoke scoped delegation", root_pre,
        json.dumps({"status": root_before.get("state"), "capabilities": root_caps_before, "authority": root_authority_before}))
    if deleg_pre != "PASS" or root_pre != "PASS":
        rec("M0", "effective target revoke of NODE-scoped HOST_ACCESS delegation", "BLOCKED", "pre-revoke actor/root capability assertion did not pass")
        rec("M1", "stale delegate cache reaches executor and gets authority_insufficient", "BLOCKED", "M0 did not run")
        return

    # Revoke delegate HOST_ACCESS at the actual target through the root's direct LXMF path.
    rid, sub = submit("admin", d1, "rights.revoke", holder=deleg, rights=64)
    fin_root = await_final("admin", rid)
    revoke_result = fin_root.get("result") or {}
    target_revoke = (sub.get("accepted") is True and sub.get("queued") is True
                     and fin_root.get("state") == "applied" and fin_root.get("durable_ack") is True
                     and revoke_result.get("record_committed") is True
                     and revoke_result.get("effective_host_allowed") is False)
    if not target_revoke:
        rec("M0", "effective target revoke of NODE-scoped HOST_ACCESS delegation", "BLOCKED", f"submit={sub}; state={fin_root.get('state')} result={fin_root.get('result')}")
        rec("M1", "stale delegate cache reaches executor and gets authority_insufficient", "BLOCKED", "M0 was not durably and effectively applied")
        return
    rec("M0", "effective target revoke of NODE-scoped HOST_ACCESS delegation", "PASS", f"durable_ack=true result={fin_root.get('result')}; ordinary ADD/REMOVE 63 is unchanged")
    cache_age = time.monotonic() - deleg_cache_received
    cache_verdict = cache_freshness_verdict(cache_age)
    rec("M-cache", "delegate capability cache is still within 600 s without refresh", cache_verdict, f"age_s={cache_age:.1f}")
    if cache_verdict != "PASS":
        rec("M1", "stale delegate cache reaches executor and gets durable authority_insufficient", "BLOCKED", "pre-revoke delegate capability cache expired before mutation")
        return
    # Deliberately do NOT refresh delegate status: use its genuine, signed, <600s
    # pre-revoke cache. Local ordinary ADD/REMOVE authority remains 63, so this
    # mutation should queue and be rejected only by the executor's fresh scoped gate.
    rid, sub = submit("deleg", d1, "rights.grant", holder=CTX["usr"]["hash"], rights=HOST_ACCESS_ONLY)
    if sub.get("accepted") is not True or sub.get("queued") is not True:
        rec("M1-client", "delegate client guard after scoped revoke", "INFO", f"local refusal before target: {sub.get('rejected')}; not executor proof")
        rec("M1", "stale delegate cache reaches executor and gets authority_insufficient", "BLOCKED", "client did not queue the mutation")
        return
    fin = await_final("deleg", rid, 45)
    m1_verdict = signed_rejection_verdict(sub, fin, "authority_insufficient", durable=True)
    rec("M1", "stale delegate cache reaches executor and gets durable authority_insufficient", m1_verdict,
        f"state={fin.get('state')} durable_ack={fin.get('durable_ack')} result={fin.get('result')}")


def s_bench():
    """P: малый замер издержек пути (не пропускная способность; условия - один хост, loopback-Docker)."""
    out = {}
    for label, ip, port, node, log in (("internet", H.INET_IP, 9999, "site", "/state/udp.log"),):
        r = H.dx("usr", "ping", "-c", "30", "-i", "0.2", "-q", ip, timeout=60)
        out[f"{label}_ping"] = [l for l in r.stdout.splitlines() if "min/avg" in l or "packet loss" in l]
        H.dx(node, "sh", "-c", f": > {log}")
        r = H.dx("usr", "python3", SERVICES, "blast", ip, str(port), "3000", "500", "B", timeout=60)
        time.sleep(2)
        got = len([l for l in fileread(node, log).splitlines() if l.split(" ", 1)[-1].startswith("B-")])
        out[f"{label}_udp"] = {"sender": r.stdout.strip(), "received": got, "of": 3000}
    rec("P1", "малый замер: интернет-путь через TUN, 3000 UDP по 500 pps и ping", "INFO", json.dumps(out))
    return out


# ------------------------------------------------------------------ запуск
ORDER = [("base", s_baseline), ("status", s_status_before), ("deleg", s_delegation_restart), ("grant", s_grant_flow),
         ("revoke", s_revoke_flow), ("persist", s_persist_restart), ("acl", s_acl_config), ("neg", s_negatives), ("revoked", s_revoked_actor)]


def run(harness, args):
    global H
    H = harness
    only = {x for x in args.only.split(",") if x}
    t0 = time.time()
    src = sources()
    print("источники:", json.dumps({k: (v or "-")[:16] for k, v in src.items()}), flush=True)
    discover()
    select_exit(CTX["exit1"]["d"])
    try:
        wait_usr_link(CTX["exit1"]["d"], 120)
    except TimeoutError:
        rec("0", "usr подключён к exit1 (select)", "BLOCKED", "нет Link за 120 с; дальнейшие проверки не имеют смысла")
        return finish(src, t0)
    for name, fn in ORDER:
        if only and name not in only:
            continue
        try:
            fn()
        except Exception as e:  # noqa: BLE001
            rec(name, "сценарий прервался исключением", "FAIL", repr(e)[:400])
    if args.bench and not any(r["verdict"] == "FAIL" for r in RESULTS):
        s_bench()
    return finish(src, t0)


def finish(src, t0):
    cnt = {}
    for r in RESULTS:
        cnt[r["verdict"]] = cnt.get(r["verdict"], 0) + 1
    out = {"when": time.strftime("%Y-%m-%d %H:%M:%S"), "secs": round(time.time() - t0), "counts": cnt, "sources": src, "results": RESULTS}
    path = H.ROOT / f"results-{time.strftime('%Y%m%d-%H%M%S')}.json"
    H.ROOT.mkdir(parents=True, exist_ok=True)
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
    with os.fdopen(fd, "w") as f:
        json.dump(out, f, ensure_ascii=False, indent=1)
    print("итог:", json.dumps(cnt), "->", path, flush=True)
    return 1 if cnt.get("FAIL") or cnt.get("BLOCKED") else 0
