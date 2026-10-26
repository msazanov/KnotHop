import copy
import json
from pathlib import Path
import tempfile
import unittest

from lxmf_e2e_replay import lose_ack, without_ack


class ReplayFixtureTest(unittest.TestCase):
    def record(self):
        return {"request": {"requestid": "a" * 32, "exp": 2000, "host_record": "signed-original",
                            "root": "b" * 32, "rights": 64},
                "target_public_key": "public-original", "status": "applied", "durable_ack": True,
                "result": {"state": "applied"}, "authenticated_envelope": "signed-reply",
                "created": 900, "updated": 1000}

    def test_only_ack_metadata_changes_not_request_or_signature(self):
        record = self.record()
        before = copy.deepcopy(record)
        pending = without_ack(record, 1100)
        self.assertEqual(record, before)
        self.assertEqual(pending["request"], before["request"])
        self.assertEqual(pending["target_public_key"], before["target_public_key"])
        self.assertEqual(pending["created"], before["created"])
        self.assertIs(pending["durable_ack"], False)
        self.assertEqual(pending["status"], "pending")
        self.assertIsNone(pending["result"])
        self.assertIsNone(pending["authenticated_envelope"])

    def test_expired_request_is_not_resigned_or_given_a_new_expiry(self):
        record = self.record()
        with self.assertRaises(ValueError):
            without_ack(record, 2000)
        self.assertEqual(record["request"]["exp"], 2000)
        self.assertIs(record["durable_ack"], True)

    def test_requires_a_successful_ack_before_simulating_its_loss(self):
        record = self.record()
        record["durable_ack"] = False
        with self.assertRaises(ValueError):
            without_ack(record, 1100)

    def test_atomic_file_preserves_request_and_private_mode(self):
        with tempfile.TemporaryDirectory(prefix="knothop-replay-") as tmp:
            path = Path(tmp) / "command.json"
            record = self.record()
            path.write_text(json.dumps(record))
            lose_ack(path, 1100)
            self.assertEqual(json.loads(path.read_text())["request"], record["request"])
            self.assertEqual(path.stat().st_mode & 0o777, 0o600)
            self.assertEqual([p.name for p in path.parent.iterdir()], ["command.json"])


if __name__ == "__main__":
    unittest.main()
