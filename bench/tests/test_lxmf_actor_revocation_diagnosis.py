#!/usr/bin/env python3
"""Pure fixture-evidence regression; no Docker, keys, network, or builds."""
import copy
import importlib.util
from pathlib import Path
import unittest

spec = importlib.util.spec_from_file_location("m1", Path(__file__).with_name("lxmf_actor_revocation_diagnosis.py"))
m1 = importlib.util.module_from_spec(spec)
spec.loader.exec_module(m1)


class EvidenceTest(unittest.TestCase):
    def sample(self):
        row = {"rights": 63, "seq": 10, "issuer_root": True}
        reply = {"fresh_id_absent_before": True, "accepted": True, "queued": True,
                 "durable_ack": True, "authenticated_envelope_present": True,
                 "request_id_matches": True, "state": "applied", "authority_rights": 63}
        return {"grant_cli": {"returncode": 0},
                "before_reply": copy.deepcopy(reply), "after_reply": copy.deepcopy(reply),
                "after_15s": {n: {"trust_rows": [copy.deepcopy(row)],
                    "inbox_rows": [{"rights": 0, "seq": 11, "issuer_root": True, "suffix": ".rec"}] if n == "admin" else []}
                    for n in ("admin", "exit1", "deleg")}}

    def test_exact_unconsumed_revoke(self):
        self.assertTrue(m1.root_client_bug(self.sample()))

    def test_no_success_from_cli_text_or_cached_view(self):
        for k in ("fresh_id_absent_before", "queued", "authenticated_envelope_present", "request_id_matches", "durable_ack"):
            with self.subTest(k=k):
                out = self.sample()
                out["after_reply"][k] = False
                self.assertFalse(m1.root_client_bug(out))

    def test_target_committed_revoke_is_not_this_bug(self):
        out = self.sample()
        out["after_15s"]["exit1"]["trust_rows"][0]["rights"] = 0
        self.assertFalse(m1.root_client_bug(out))

    def test_cli_failure_or_old_wrong_issuer_not_this_bug(self):
        out = self.sample()
        out["grant_cli"]["returncode"] = 1
        self.assertFalse(m1.root_client_bug(out))
        for change in ({"seq": 9}, {"issuer_root": False}, {"suffix": ".rejected"}):
            out = self.sample()
            out["after_15s"]["admin"]["inbox_rows"][0].update(change)
            self.assertFalse(m1.root_client_bug(out))

    def test_observe_reads_public_snapshot_without_whoami_cli(self):
        class ReadOnly:
            def jread(self, name, path):
                self_seen.append((name, path))
                return {"hash": "public-pseudonym"}
        self_seen = []
        ids = m1.public_ids(ReadOnly(), ("admin", "deleg"))
        self.assertEqual(set(ids), {"admin", "deleg"})
        self.assertEqual(self_seen, [("admin", "/state/whoami.json"), ("deleg", "/state/whoami.json")])


if __name__ == "__main__":
    unittest.main()
