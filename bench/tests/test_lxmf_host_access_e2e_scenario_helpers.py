"""Fast, source-only checks for E2E verdict/dependency helpers; no Docker or project binaries."""
import sys
import ast
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
import lxmf_host_access_e2e_scenarios as scenarios


class ScenarioHelperTests(unittest.TestCase):
    def setUp(self):
        self.old_results = scenarios.RESULTS
        scenarios.RESULTS = []

    def tearDown(self):
        scenarios.RESULTS = self.old_results

    def test_k8_requires_exit1_not_ready_refusal(self):
        self.assertTrue(scenarios.k8_exit_refused("[1] выход knothop-ZZ-exit1: knothop-ZZ-exit1 отказал в доступе: exit not ready\n"))
        self.assertTrue(scenarios.k8_exit_refused("[1] выход exit1: exit1 отказал в доступе: exit not ready"))
        self.assertFalse(scenarios.k8_exit_refused("[1] выход exit2: exit2 отказал в доступе: exit not ready"))
        self.assertFalse(scenarios.k8_exit_refused("[1] выход exit1: exit1 отказал в доступе: address clash"))
        self.assertFalse(scenarios.k8_exit_refused(""))

    def test_dependent_negative_is_blocked_without_positive_control(self):
        self.assertEqual(scenarios.dependent_verdict(False, True), "BLOCKED")
        scenarios.dependent_check("NEG", "negative", True, False, blocked_reason="no positive")
        self.assertEqual(scenarios.RESULTS[-1]["verdict"], "BLOCKED")

    def test_dependent_negative_passes_only_after_positive_and_observed_deny(self):
        self.assertEqual(scenarios.dependent_verdict(True, True), "PASS")
        self.assertEqual(scenarios.dependent_verdict(True, False), "FAIL")

    def test_stale_requires_queued_request_and_durable_terminal_ack(self):
        sub = {"accepted": True, "queued": True}
        self.assertEqual(scenarios.stale_snapshot_verdict(sub, {"state": "stale", "durable_ack": True}), "PASS")
        self.assertEqual(scenarios.stale_snapshot_verdict(sub, {"state": "applied", "durable_ack": True}), "FAIL")

    def test_stale_local_refusal_or_unknown_is_blocked_not_server_failure(self):
        self.assertEqual(scenarios.stale_snapshot_verdict({"accepted": False}, {"state": "unknown"}), "BLOCKED")
        self.assertEqual(scenarios.stale_snapshot_verdict({"accepted": True, "queued": True}, {"state": "unknown", "durable_ack": False}), "BLOCKED")

    def test_applied_mutation_requires_queued_request_and_durable_ack(self):
        self.assertEqual(scenarios.applied_mutation_verdict({"accepted": True, "queued": True}, {"state": "applied", "durable_ack": True}), "PASS")
        self.assertEqual(scenarios.applied_mutation_verdict({"accepted": False}, {"state": "unknown"}), "BLOCKED")
        self.assertEqual(scenarios.applied_mutation_verdict({"accepted": True, "queued": True}, {"state": "unknown", "durable_ack": False}), "BLOCKED")
        self.assertEqual(scenarios.applied_mutation_verdict({"accepted": True, "queued": True}, {"state": "rejected", "durable_ack": True}), "FAIL")

    def test_signed_transient_host_acl_rejection_is_non_durable(self):
        queued = {"accepted": True, "queued": True}
        signed_transient = {"state": "rejected", "durable_ack": False, "result": {"code": "host_acl_unavailable"}}
        self.assertEqual(scenarios.signed_rejection_verdict(queued, signed_transient, "host_acl_unavailable", durable=False), "PASS")
        self.assertEqual(scenarios.signed_rejection_verdict(queued, {"state": "unknown", "durable_ack": False}, "host_acl_unavailable", durable=False), "BLOCKED")
        self.assertEqual(scenarios.signed_rejection_verdict(queued, {"state": "delivered", "durable_ack": False}, "host_acl_unavailable", durable=False), "BLOCKED")
        self.assertEqual(scenarios.signed_rejection_verdict(queued, {"state": "applied", "durable_ack": True}, "host_acl_unavailable", durable=False), "FAIL")
        self.assertEqual(scenarios.signed_rejection_verdict(queued, {"state": "rejected", "durable_ack": False, "result": {"code": "other"}}, "host_acl_unavailable", durable=False), "FAIL")

    def test_signed_durable_authority_refusal_requires_exact_code(self):
        queued = {"accepted": True, "queued": True}
        refusal = {"state": "rejected", "durable_ack": True, "result": {"code": "authority_insufficient"}}
        self.assertEqual(scenarios.signed_rejection_verdict(queued, refusal, "authority_insufficient", durable=True), "PASS")
        self.assertEqual(scenarios.signed_rejection_verdict({"accepted": False}, refusal, "authority_insufficient", durable=True), "BLOCKED")
        self.assertEqual(scenarios.signed_rejection_verdict(queued, {"state": "rejected", "durable_ack": False, "result": {"code": "authority_insufficient"}}, "authority_insufficient", durable=True), "FAIL")

    def test_stale_actor_cache_must_remain_inside_ttl_without_refresh(self):
        self.assertEqual(scenarios.cache_freshness_verdict(42), "PASS")
        self.assertEqual(scenarios.cache_freshness_verdict(599.9), "PASS")
        self.assertEqual(scenarios.cache_freshness_verdict(600), "BLOCKED")
        self.assertEqual(scenarios.cache_freshness_verdict(-1), "BLOCKED")

    @staticmethod
    def _calls(function_name):
        tree = ast.parse(Path(scenarios.__file__).read_text())
        fn = next(n for n in tree.body if isinstance(n, (ast.FunctionDef, ast.AsyncFunctionDef)) and n.name == function_name)
        calls = []
        for node in ast.walk(fn):
            if not isinstance(node, ast.Call):
                continue
            name = node.func.attr if isinstance(node.func, ast.Attribute) else node.func.id if isinstance(node.func, ast.Name) else ""
            args = [a.value if isinstance(a, ast.Constant) else None for a in node.args]
            calls.append((node.lineno, name, args))
        return sorted(calls)

    def test_actor_revocation_keeps_delegate_capability_snapshot_stale_after_m0(self):
        calls = self._calls("s_revoked_actor")
        deleg_status = next(line for line, name, args in calls if name == "get_status" and args[:2] == ["deleg", "exit1"])
        root_status = next(line for line, name, args in calls if name == "get_status" and args[:2] == ["admin", "exit1"])
        root_revoke = next(line for line, name, args in calls if name == "submit" and args[:3] == ["admin", None, "rights.revoke"])
        delegate_grant = next(line for line, name, args in calls if name == "submit" and args[:3] == ["deleg", None, "rights.grant"])
        self.assertLess(deleg_status, root_status)
        self.assertLess(root_status, root_revoke)
        self.assertLess(root_revoke, delegate_grant)
        self.assertFalse(any(name == "get_status" and args[:2] == ["deleg", "exit1"] and root_revoke < line < delegate_grant for line, name, args in calls))

    def test_acl_readiness_probes_use_pretransition_cache_without_refresh_between_k6_k7(self):
        calls = self._calls("s_acl_config")
        pre_status = next(line for line, name, args in calls if name == "get_status" and args[:2] == ["admin", "exit1"])
        chmod_bad = next(line for line, name, args in calls if name == "dx" and args[:3] == ["exit1", "chmod", "644"])
        grant = next(line for line, name, args in calls if name == "submit" and args[:3] == ["admin", None, "rights.grant"])
        revoke = next(line for line, name, args in calls if name == "submit" and args[:3] == ["admin", None, "rights.revoke"])
        recovery_statuses = [line for line, name, args in calls if name == "get_status" and args[:2] == ["admin", "exit1"] and line > revoke]
        self.assertLess(pre_status, chmod_bad)
        self.assertLess(chmod_bad, grant)
        self.assertLess(grant, revoke)
        self.assertTrue(recovery_statuses, "refresh only after the transient rejection probes")
        self.assertFalse(any(name == "get_status" and args[:2] == ["admin", "exit1"] and chmod_bad < line < revoke for line, name, args in calls))

    def test_host_probe_state_requires_client_on_target_exit_for_a_closed_result(self):
        e1, e2 = "e1", "e2"
        on1 = {"d": e1, "since_s": 20}
        self.assertEqual(scenarios.host_probe_state("200", e1, on1, on1), "open")
        self.assertEqual(scenarios.host_probe_state("200", e1, {"d": e2, "since_s": 5}, on1), "open")
        self.assertEqual(scenarios.host_probe_state("000", e1, on1, {"d": e1, "since_s": 24}), "closed")
        # D5/I3/J11 of the post-D1 run: client had failed over to exit2 (host address lives on exit1 only)
        self.assertEqual(scenarios.host_probe_state("000", e1, {"d": e2, "since_s": 48}, {"d": e2, "since_s": 64}), "unknown")
        self.assertEqual(scenarios.host_probe_state("000", e1, on1, {"d": e2, "since_s": 1}), "unknown")
        self.assertEqual(scenarios.host_probe_state("000", e1, on1, {"d": e1, "since_s": 2}), "unknown")   # Link reset during probe
        self.assertEqual(scenarios.host_probe_state("000", e1, {}, {}), "unknown")

    def test_host_probe_verdict_blocks_unknown_for_positive_and_negative(self):
        self.assertEqual(scenarios.host_probe_verdict(True, "open"), "PASS")
        self.assertEqual(scenarios.host_probe_verdict(True, "closed"), "FAIL")
        self.assertEqual(scenarios.host_probe_verdict(False, "closed"), "PASS")
        self.assertEqual(scenarios.host_probe_verdict(False, "open"), "FAIL")
        self.assertEqual(scenarios.host_probe_verdict(True, "unknown"), "BLOCKED")
        self.assertEqual(scenarios.host_probe_verdict(False, "unknown"), "BLOCKED")

    def test_host_state_waits_for_exit1_and_retries_once_after_failover(self):
        saved = (scenarios.usr_exit, scenarios.http, scenarios.time.sleep, scenarios.time.time, scenarios.CTX.copy())
        scenarios.CTX["exit1"] = {"d": "e1"}
        timeline = iter([  # pin: exit2, exit2, exit1/old, exit1/ok (pin) | before | after (probe 1: client flipped away)
            {"d": "e2", "since_s": 3}, {"d": "e2", "since_s": 4}, {"d": "e1", "since_s": 2}, {"d": "e1", "since_s": 8},
            {"d": "e1", "since_s": 8}, {"d": "e2", "since_s": 1},
            {"d": "e1", "since_s": 9}, {"d": "e1", "since_s": 9}, {"d": "e1", "since_s": 12}])   # pin, before, after (probe 2)
        probes = iter(["000", "200"])
        clock = [0.0]
        try:
            scenarios.usr_exit = lambda: next(timeline)
            scenarios.http = lambda *a, **k: (next(probes), "")
            scenarios.time.sleep = lambda s: clock.__setitem__(0, clock[0] + s)
            scenarios.time.time = lambda: clock[0]
            self.assertEqual(scenarios.host_state("1.1.1.1"), ("open", "200"))
        finally:
            scenarios.usr_exit, scenarios.http, scenarios.time.sleep, scenarios.time.time = saved[:4]
            scenarios.CTX.clear()
            scenarios.CTX.update(saved[4])

    def test_host_state_is_unknown_when_client_never_returns_to_exit1(self):
        saved = (scenarios.usr_exit, scenarios.select_exit, scenarios.time.sleep, scenarios.time.time, scenarios.CTX.copy())
        scenarios.CTX["exit1"] = {"d": "e1"}
        clock, nudges = [0.0], []
        try:
            scenarios.usr_exit = lambda: {"d": "e2", "since_s": 99}
            scenarios.select_exit = lambda d: nudges.append(d)
            scenarios.time.sleep = lambda s: clock.__setitem__(0, clock[0] + s)
            scenarios.time.time = lambda: clock[0]
            state, code = scenarios.host_state()
            self.assertEqual(state, "unknown")
            self.assertEqual(nudges, ["e1"])      # one user-selection nudge, not a spam of re-selects
        finally:
            scenarios.usr_exit, scenarios.select_exit, scenarios.time.sleep, scenarios.time.time = saved[:4]
            scenarios.CTX.clear()
            scenarios.CTX.update(saved[4])

    def test_every_host_tcp_assertion_goes_through_the_exit1_pin(self):
        tree = ast.parse(Path(scenarios.__file__).read_text())
        direct = []
        for fn in tree.body:
            if not isinstance(fn, ast.FunctionDef) or not fn.name.startswith("s_"):
                continue
            for node in ast.walk(fn):
                if isinstance(node, ast.Call) and isinstance(node.func, ast.Name) and node.func.id == "http":
                    args = [a.value if isinstance(a, ast.Constant) else None for a in node.args]
                    if len(args) > 1 and args[1] != "H.INET_IP" and not (isinstance(node.args[1], ast.Attribute) and node.args[1].attr == "INET_IP"):
                        direct.append((fn.name, node.lineno))
                if isinstance(node, ast.Call) and isinstance(node.func, ast.Name) and node.func.id == "host_ok":
                    direct.append((fn.name, node.lineno))
        self.assertEqual(direct, [], "host-bound TCP must use host_state()/pin_usr_to_exit1(), not a raw probe from a client that may have failed over")

    def test_participant_privacy_capability_false_is_blocked(self):
        self.assertEqual(scenarios.participants_verdict(False, None), "BLOCKED")

    def test_participant_assertion_only_runs_when_export_is_advertised(self):
        self.assertEqual(scenarios.participants_verdict(True, {"host_access": False}), "PASS")
        self.assertEqual(scenarios.participants_verdict(True, None), "FAIL")
        self.assertEqual(scenarios.participants_verdict(True, {"host_access": True}), "FAIL")


if __name__ == "__main__":
    unittest.main()
